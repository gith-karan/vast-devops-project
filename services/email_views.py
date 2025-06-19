import math
import uuid
from django.shortcuts import render
from django.http import JsonResponse
import re
import dns.resolver
from .models import EmailCheck, EmailCheckResult, Feedback
import socket
from urllib.parse import quote_plus
import whois
from .models import DisposableDomain
import json
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import threading
import time
import smtplib
import random
import dns.reversename
import concurrent.futures
from .models import SpamDatabaseEntry
from django.utils import timezone 
from datetime import datetime, timedelta
from django.http import HttpResponse
from django.template.loader import get_template
from xhtml2pdf import pisa
from io import BytesIO
import base64
from datetime import datetime

from .scan_limiter import ScanLimiter

disposable_domains_cache = {
    'domains': set(),
    'last_updated': None,
    'lock': threading.Lock()
}

def fetch_disposable_domains():
    global disposable_domains_cache
    
    # Only update the cache if it's older than 24 hours or doesn't exist
    with disposable_domains_cache['lock']:
        current_time = time.time()
        if (disposable_domains_cache['last_updated'] is None or 
            current_time - disposable_domains_cache['last_updated'] > 86400):  # 24 hours
            
            all_domains = set()
            
            # List of sources
            sources = [
                'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf',
                'https://raw.githubusercontent.com/martenson/disposable-email-domains/master/disposable_email_blocklist.conf',
                'https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json',
                # Additional sources
                'https://raw.githubusercontent.com/7c/fakefilter/main/txt/data.txt',
            ]
            
            for source in sources:
                try:
                    response = requests.get(source, timeout=5)
                    if response.status_code == 200:
                        # Parse the source content
                        if source.endswith('.json'):
                            # Parse JSON format
                            domains = json.loads(response.text)
                            all_domains.update([d.lower() for d in domains])
                        else:
                            # Parse text format (one domain per line)
                            lines = response.text.splitlines()
                            domains = [line.strip().lower() for line in lines if line.strip() and not line.startswith('#')]
                            all_domains.update(domains)
                except Exception as e:
                    print(f"Error fetching domains from {source}: {str(e)}")
            
            # Add existing domains from the database
            from .models import DisposableDomain
            db_domains = DisposableDomain.objects.values_list('domain', flat=True)
            all_domains.update([d.lower() for d in db_domains])
            
            # Update the cache
            disposable_domains_cache['domains'] = all_domains
            disposable_domains_cache['last_updated'] = current_time
            
            print(f"Updated disposable domains cache with {len(all_domains)} domains")
            
    return disposable_domains_cache['domains']

def check_domain_reachability(domain):
    """Check if domain is reachable via DNS and HTTP"""
    results = {
        'dns_resolves': False,
        'web_reachable': False,
        'dns_error': None,
        'web_error': None
    }
    
    # Check DNS resolution
    try:
        socket.gethostbyname(domain)
        results['dns_resolves'] = True
    except Exception as e:
        results['dns_error'] = str(e)
    
    # Check website reachability
    if results['dns_resolves']:
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{domain}"
                response = requests.get(url, timeout=5)
                if response.status_code < 500:  
                    results['web_reachable'] = True
                    break
            except Exception as e:
                results['web_error'] = str(e)
    
    return results

def check_mx_records(domain):
    mx_records = []
    try:
        # Set a custom timeout and try multiple resolvers if needed
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0  # Shorter timeout (2 seconds instead of default)
        resolver.lifetime = 4.0  # Total lookup time limit
        
        # Try to get MX records with the custom resolver
        try:
            answers = resolver.resolve(domain, 'MX')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # No error, just no MX records found
            return []
        except Exception:
            # Try with some public DNS servers if the default fails
            backup_resolvers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
            for dns_server in backup_resolvers:
                try:
                    resolver.nameservers = [dns_server]
                    answers = resolver.resolve(domain, 'MX')
                    break  # Found records, exit loop
                except Exception:
                    continue
            else:
                # No successful lookup with any resolver
                print(f"Unable to resolve MX records for {domain} after trying multiple DNS servers")
                return []
        
        # Process the answers
        for rdata in answers:
            hostname = str(rdata.exchange).rstrip('.')
            ip_address = None
            try:
                # Short timeout for hostname resolution
                ip_address = socket.gethostbyname(hostname)
            except socket.gaierror:
                try:
                    # Try with A record if direct resolution fails
                    a_records = resolver.resolve(hostname, 'A')
                    if a_records and len(a_records) > 0:
                        ip_address = str(a_records[0])
                except Exception:
                    ip_address = "Resolution failed"
            except socket.timeout:
                ip_address = "Resolution timed out"
                
            if not ip_address:
                ip_address = "Resolution failed"
                
            mx_records.append({
                'hostname': hostname,
                'preference': int(rdata.preference),
                'ip_address': ip_address
            })
        mx_records.sort(key=lambda x: x['preference'])
    except Exception as e:
        print(f"Error checking MX records for {domain}: {str(e)}")
    
    return mx_records

def check_spf_record(domain):
    """Check if domain has an SPF record"""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = str(rdata).lower()
            if 'v=spf1' in txt_record:
                return True
    except Exception:
        pass
    return False

def check_disposable_content(domain):
    """Check if a website's content suggests it's a disposable email service"""
    # Expanded keyword list with variations and common terms
    disposable_keywords = [
        'temp mail', 'temporary mail', 'disposable mail', 'throwaway mail', 'fake mail',
        'temporary email', 'disposable email', 'throwaway email', 'fake email', 'temp email',
        'temp address', 'temporary address', 'disposable address', 'throwaway address', 
        'one-time email', 'anonymous email', 'trash mail', 'burner email', 'tempmail',
        'temporary mailbox', 'disposable mailbox', 'one time', 'one-time', 'no registration', 
        '10 minute mail', '5 minute mail', 'minute mail', 'inboxes', 'inbox service',
        'free inbox', 'email generator', 'throwaway account', 'temp account', 'selfdestructing',
        'self-destructing', 'expiring email', 'instant email', 'receive email', 'generate email', 
        'create new email', 'random email', 'anonymous inbox', 'no signup', 'without registration',
        'receive-smth.com', 'email provider', 'dummy mail', 'mailbox service', 'spam blocker',
        'forwarding service', 'disposable', 'delete after', 'auto delete', 'fake identity',
        'privacy email', 'hide identity', 'anonymous', 'hide your', 'secure mail generator'
    ]
    
    # Features of disposable email sites
    disposable_features = [
        'copy to clipboard', 'refresh inbox', 'check inbox', 'random address', 'delete email',
        'generate random', 'new email address', 'your inbox', 'inbox view', 'create mailbox',
        'create inbox', 'destroy', 'self-destruct'
    ]
    
    url = f"http://{domain}"
    secure_url = f"https://{domain}"
    
    # Set headers to mimic a real browser
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
    }
    
    try:
        # Try HTTPS first, then HTTP
        for attempt_url in [secure_url, url]:
            try:
                response = requests.get(attempt_url, headers=headers, timeout=10, allow_redirects=True)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # 1. Check page title
                    title = soup.title.text.lower() if soup.title else ""
                    for keyword in disposable_keywords:
                        if keyword in title:
                            print(f"Found disposable keyword '{keyword}' in title of {domain}")
                            return True
                    
                    # 2. Check meta description and keywords
                    meta_desc = soup.find('meta', attrs={'name': 'description'})
                    meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
                    
                    if meta_desc and meta_desc.get('content'):
                        meta_desc_text = meta_desc.get('content').lower()
                        for keyword in disposable_keywords:
                            if keyword in meta_desc_text:
                                print(f"Found disposable keyword '{keyword}' in meta description of {domain}")
                                return True
                                
                    if meta_keywords and meta_keywords.get('content'):
                        meta_keywords_text = meta_keywords.get('content').lower()
                        for keyword in disposable_keywords:
                            if keyword in meta_keywords_text:
                                print(f"Found disposable keyword '{keyword}' in meta keywords of {domain}")
                                return True
                    
                    # 3. Check for email generation forms or input fields
                    email_inputs = soup.find_all('input', attrs={'type': 'email'})
                    buttons = soup.find_all(['button', 'a', 'input'], attrs={'type': ['button', 'submit']})
                    
                    # Check button/link text for common disposable email actions
                    for button in buttons:
                        button_text = button.text.lower() if button.text else ""
                        button_value = button.get('value', '').lower()
                        combined_text = f"{button_text} {button_value}"
                        
                        for feature in disposable_features:
                            if feature in combined_text:
                                print(f"Found disposable feature '{feature}' in button/link of {domain}")
                                return True
                    
                    # 4. Check main content (first 10000 chars)
                    content = soup.get_text(" ", strip=True).lower()
                    content_sample = content[:10000]
                    
                    # Search for keyword phrases
                    for keyword in disposable_keywords:
                        if keyword in content_sample:
                            # Double-check to avoid false positives by looking at surrounding text
                            keyword_index = content_sample.find(keyword)
                            # Get some context around the match (50 chars before and after)
                            start = max(0, keyword_index - 50)
                            end = min(len(content_sample), keyword_index + len(keyword) + 50)
                            context = content_sample[start:end]
                            
                            # Check if the context suggests a disposable email service
                            negative_contexts = [
                                "avoid disposable email", 
                                "don't use disposable", 
                                "block disposable", 
                                "prevent disposable"
                            ]
                            
                            if not any(neg in context for neg in negative_contexts):
                                print(f"Found disposable keyword '{keyword}' in content of {domain}")
                                return True
                    
                    # 5. Look for common email generation interface elements
                    random_btns = soup.find_all(text=re.compile(r'(random|generate|create|new|refresh).*email', re.I))
                    if random_btns:
                        print(f"Found email generation UI elements on {domain}")
                        return True
                    
                    # 6. Look for inbox display sections
                    inbox_sections = soup.find_all(['div', 'section', 'article'], 
                                                  attrs={'id': re.compile(r'inbox|messages|mail', re.I)})
                    if inbox_sections:
                        print(f"Found inbox display section on {domain}")
                        return True
                            
                    # If we reached here, no definitive indicators were found
                    return False
                    
            except Exception as e:
                print(f"Error checking URL {attempt_url}: {str(e)}")
                continue  # Try next URL format
                
        # If both attempts failed, we cannot determine from content
        return False
        
    except Exception as e:
        print(f"Error checking content for {domain}: {str(e)}")
        return False
    
def check_for_random_domain_pattern(domain):
    domain_name = domain.split('.')[0].lower()
    
    # Look for extremely random patterns (all digits + letters with no recognizable words)
    random_pattern = re.compile(r'^[a-z0-9]{10,}$')  # Increased from 8 to 10
    
    # Legitimate business tech words - don't count these against domains
    common_tech_terms = [
        'dev', 'mail', 'box', 'web', 'net', 'cloud', 'host', 'data',
        'info', 'sys', 'tech', 'site', 'app', 'pro', 'soft', 'ware', 'code',
        'lab', 'secure', 'smart', 'cyber', 'meta', 'digi', 'byte', 'flex', 
        'swift', 'global', 'systems', 'digital', 'solutions', 'software'
    ]
    
    # Domain must contain multiple tech terms to be suspicious
    word_part_count = 0
    for word in common_tech_terms:
        if word in domain_name:
            word_part_count += 1
    
    # Pattern matches ONLY if it's both random-looking AND not containing
    # recognizable business terms
    if random_pattern.match(domain_name) and word_part_count == 0:
        return True
    
    # Check for repetitive patterns
    if len(domain_name) >= 8:  # Increased from 6
        half_point = len(domain_name) // 2
        if domain_name[:half_point] == domain_name[half_point:half_point*2]:
            return True
    
    # Check for keyboard patterns
    keyboard_patterns = ['qwerty', 'asdfgh', '123456', 'zxcvbn']
    for pattern in keyboard_patterns:
        if pattern in domain_name:
            return True
    
    return False

domain_info_cache = {
    'domains': {},
    'last_updated': {},
    'lock': threading.Lock()
}

def get_domain_info(domain):
    global domain_info_cache
    
    with domain_info_cache['lock']:
        current_time = time.time()
        if domain in domain_info_cache['domains'] and domain in domain_info_cache['last_updated']:
            last_update = domain_info_cache['last_updated'][domain]
            # Cache domain info for 72 hours (259200 seconds)
            if current_time - last_update < 259200:
                print(f"Using cached domain info for {domain}")
                return domain_info_cache['domains'][domain]
            
    """Get detailed information about a domain"""
    domain_info = {
        'domain': domain,
        'organization': None,
        'registrar': None,
        'creation_date': None,
        'expiration_date': None,
        'last_updated': None,
        'status': None,
        'name_servers': [],
        'is_popular': False,
        'provider_info': None
    }
    
    # Check if it's a well-known email provider
    provider_info = get_email_provider_info(domain)
    if provider_info:
        domain_info['is_popular'] = True
        domain_info['provider_info'] = provider_info
    
    # Try to get WHOIS information
    try:
        whois_info = whois.whois(domain)
        
        # Extract organization name
        if whois_info.org:
            domain_info['organization'] = whois_info.org
        elif whois_info.registrant_org:
            domain_info['organization'] = whois_info.registrant_org
            
        # Extract other domain details
        domain_info['registrar'] = whois_info.registrar
        
        # Handle dates - they can be lists or single values
        if whois_info.creation_date:
            if isinstance(whois_info.creation_date, list):
                domain_info['creation_date'] = whois_info.creation_date[0].strftime('%Y-%m-%d') if whois_info.creation_date[0] else None
            else:
                domain_info['creation_date'] = whois_info.creation_date.strftime('%Y-%m-%d') if whois_info.creation_date else None
                
        if whois_info.expiration_date:
            if isinstance(whois_info.expiration_date, list):
                domain_info['expiration_date'] = whois_info.expiration_date[0].strftime('%Y-%m-%d') if whois_info.expiration_date[0] else None
            else:
                domain_info['expiration_date'] = whois_info.expiration_date.strftime('%Y-%m-%d') if whois_info.expiration_date else None
        
        if whois_info.updated_date:
            if isinstance(whois_info.updated_date, list):
                domain_info['last_updated'] = whois_info.updated_date[0].strftime('%Y-%m-%d') if whois_info.updated_date[0] else None
            else:
                domain_info['last_updated'] = whois_info.updated_date.strftime('%Y-%m-%d') if whois_info.updated_date else None
        
        # Get domain status
        if whois_info.status:
            if isinstance(whois_info.status, list):
                domain_info['status'] = whois_info.status[0]
            else:
                domain_info['status'] = whois_info.status
                
        # Get name servers
        if whois_info.name_servers:
            if isinstance(whois_info.name_servers, list):
                domain_info['name_servers'] = [ns.lower() for ns in whois_info.name_servers if ns]
            else:
                domain_info['name_servers'] = [whois_info.name_servers.lower()] if whois_info.name_servers else []
    
    except Exception as e:
        # WHOIS lookup failed
        print(f"WHOIS lookup failed for {domain}: {str(e)}")
    
    with domain_info_cache['lock']:
        domain_info_cache['domains'][domain] = domain_info
        domain_info_cache['last_updated'][domain] = time.time()
        
    return domain_info

def get_email_provider_info(domain):
    """Get information about known email providers"""
    # Dictionary of well-known email providers with their info
    email_providers = {
        'gmail.com': {
            'name': 'Gmail',
            'company': 'Google LLC',
            'website': 'https://mail.google.com',
            'description': 'Gmail is a free email service provided by Google. It offers over 15 GB of storage, integrated Google Drive, advanced security features, and mobile apps.',
            'reputation': 'Excellent',
            'founded': 2004
        },
        'yahoo.com': {
            'name': 'Yahoo Mail',
            'company': 'Yahoo Inc.',
            'website': 'https://mail.yahoo.com',
            'description': 'Yahoo Mail is a free email service provided by Yahoo. It offers 1 TB of storage, spam protection, and integrated Yahoo products.',
            'reputation': 'Good',
            'founded': 1997
        },
        'outlook.com': {
            'name': 'Outlook',
            'company': 'Microsoft Corporation',
            'website': 'https://outlook.live.com',
            'description': 'Outlook is a free email service provided by Microsoft. It offers integration with Office products, 15 GB of storage, and advanced security features.',
            'reputation': 'Excellent',
            'founded': 2012
        },
        'hotmail.com': {
            'name': 'Hotmail (Outlook)',
            'company': 'Microsoft Corporation',
            'website': 'https://outlook.live.com',
            'description': 'Hotmail was rebranded as Outlook in 2013. It offers integration with Office products, 15 GB of storage, and advanced security features.',
            'reputation': 'Good',
            'founded': 1996
        },
        'aol.com': {
            'name': 'AOL Mail',
            'company': 'Verizon Media',
            'website': 'https://mail.aol.com',
            'description': 'AOL Mail is a free web-based email service provided by AOL, now owned by Verizon Media. It offers unlimited storage and integration with AOL services.',
            'reputation': 'Moderate',
            'founded': 1993
        },
        'protonmail.com': {
            'name': 'ProtonMail',
            'company': 'Proton AG',
            'website': 'https://protonmail.com',
            'description': 'ProtonMail is a secure email service founded by CERN scientists. It offers end-to-end encryption, anonymous signup, and Swiss privacy laws protection.',
            'reputation': 'Excellent',
            'founded': 2014
        },
        'icloud.com': {
            'name': 'iCloud Mail',
            'company': 'Apple Inc.',
            'website': 'https://www.icloud.com',
            'description': 'iCloud Mail is an email service provided by Apple. It offers integration with Apple products, 5 GB of free storage, and strong privacy features.',
            'reputation': 'Excellent',
            'founded': 2011
        },
        'zoho.com': {
            'name': 'Zoho Mail',
            'company': 'Zoho Corporation',
            'website': 'https://www.zoho.com/mail',
            'description': 'Zoho Mail is a secure email service with ad-free interface, focused on privacy and security. It offers both free and paid business plans.',
            'reputation': 'Good',
            'founded': 2005
        },
        'gmx.com': {
            'name': 'GMX Mail',
            'company': 'United Internet AG',
            'website': 'https://www.gmx.com',
            'description': 'GMX Mail offers unlimited storage, multiple email addresses, mobile apps, and file storage. It is owned by United Internet AG.',
            'reputation': 'Good',
            'founded': 1997
        },
        'mail.com': {
            'name': 'Mail.com',
            'company': 'United Internet AG',
            'website': 'https://www.mail.com',
            'description': 'Mail.com offers free email with 65 GB storage, virus protection, and a variety of domain options. It is owned by United Internet AG.',
            'reputation': 'Good',
            'founded': 1995
        },
        'yandex.com': {
            'name': 'Yandex Mail',
            'company': 'Yandex',
            'website': 'https://mail.yandex.com',
            'description': 'Yandex Mail is a secure email service with built-in translator, auto-reply, and smart spam filtering. It offers 10 GB of free storage.',
            'reputation': 'Good',
            'founded': 2000
        },
        'tutanota.com': {
            'name': 'Tutanota',
            'company': 'Tutanota GmbH',
            'website': 'https://tutanota.com',
            'description': 'Tutanota is a secure, open-source email service based in Germany. It offers end-to-end encryption, ad-free experience, and strong privacy features.',
            'reputation': 'Excellent',
            'founded': 2011
        }
    }
    
    # Check if domain is in our list of known providers
    if domain.lower() in email_providers:
        return email_providers[domain.lower()]
    
    return None

def email_scanner_view(request):
    context = {
        'is_guest': True
    }
    
    # Check if user is logged in (using session, like in accounts app)
    if request.session.get('user_email'):
        # Get user data if logged in
        user_email = request.session.get('user_email')
        try:
            from accounts.models import User  # Import the User model from accounts app
            user = User.objects.get(email=user_email)
            context = {
                'username': user.username,
                'email': user.email,
                'is_guest': False,
                'joined_date': user.date_joined
            }
        except User.DoesNotExist:
            pass
        
    return render(request, 'services/email.html', context)

def validate_email(request):
    if request.method == 'POST':
        allowed, message, remaining = ScanLimiter.check_limit(request, 'email')
        if not allowed:
            return JsonResponse({
                'error': message,
                'limit_reached': True
            }, status=403)
        
        email = request.POST.get('email', '').strip()
        if not email:
            return JsonResponse({'error': 'Please enter an email address'}, status=400)
            
        email_check = EmailCheck(email=email)
        valid_format = check_email_format(email)
        email_check.is_valid = valid_format
        is_low_quality = False
        if valid_format:
            is_low_quality = check_low_quality_email(email)
        domain_data = {}
        mx_records = []
        domain_info = {}
        spam_data = None
        
        if valid_format and '@' in email:
            domain = email.split('@')[-1]
            
            # Parallel processing for better performance
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                # Start tasks that don't depend on each other
                mx_records_future = executor.submit(check_mx_records, domain)
                domain_info_future = executor.submit(get_domain_info, domain)
                spam_data_future = executor.submit(check_spam_databases, email)
                
                # Get MX records result first as other checks depend on it
                mx_records = mx_records_future.result()
                has_mx = len(mx_records) > 0
                
                # Start tasks that depend on MX records
                mailbox_exists_future = None
                disposable_future = None
                
                if has_mx:
                    mailbox_exists_future = executor.submit(check_mailbox_exists, email)
                    disposable_future = executor.submit(check_disposable_email, domain)
                
                # Get results from other parallel tasks
                domain_info = domain_info_future.result()
                spam_data = spam_data_future.result()
                
                # Get results from MX-dependent tasks
                if has_mx:
                    mailbox_exists = mailbox_exists_future.result() if mailbox_exists_future else None
                    if disposable_future:
                        email_check.is_disposable = disposable_future.result()
                        if email_check.is_disposable:
                            update_disposable_domains_list(domain)
                else:
                    mailbox_exists = None
                    email_check.is_disposable = False
                
                # Build domain data
                domain_data = { 
                    'domain': domain,
                    'has_mx': has_mx,
                    'mx_records': mx_records,
                    'can_receive_email': has_mx and mailbox_exists != False,
                    'mailbox_exists': mailbox_exists,
                    'mailbox_verification_limited': mailbox_exists is None
                }
                
                email_check.domain_type = determine_domain_type(domain)
        else:
            email_check.is_disposable = False
            email_check.domain_type = 'unknown'
        
        email_check.save()
        
        # Calculate safety rating and generate comments
        safety_rating = calculate_safety_rating(email_check, domain_data, domain_info, spam_data)
        comments = generate_comments(email_check, domain_data, domain_info, spam_data, is_low_quality)
        
        result = EmailCheckResult.objects.create(
            email_check=email_check,
            safety_rating=safety_rating,
            comments=comments
        )
        
        # Status determination logic (including spam considerations)
        if not valid_format:
            status = "Invalid Format"
            display_rating = "-/100"
        elif not domain_data.get('has_mx', False):
            status = "Invalid Domain"
            display_rating = "-/100"
            safety_rating = 0
        elif is_low_quality:
            status = "Low Quality Email Address"
            # Reduce safety rating for low quality emails
            safety_rating = max(0, safety_rating - 15)
            display_rating = f"{safety_rating}/100"
        elif spam_data and spam_data.get('spam_score', 0) > 70:
            status = "Listed in Spam Database"
            display_rating = f"{safety_rating}/100"
        elif domain_data.get('mailbox_exists') is False:
            status = "Mailbox Not Found"
            display_rating = f"{safety_rating}/100"
        elif email_check.is_disposable:
            status = "Disposable Email"
            display_rating = f"{safety_rating}/100"
        elif domain_data.get('mailbox_exists') is None:
            status = "Valid Domain - Mailbox Verification Limited"
            display_rating = f"{safety_rating}/100"
        else:
            status = 'Safe' if safety_rating >= 70 else 'Potentially Unsafe'
            display_rating = f"{safety_rating}/100"

        response_data = {
            'email': email,
            'is_valid': email_check.is_valid,
            'is_disposable': email_check.is_disposable,
            'is_low_quality': is_low_quality,
            'is_low_quality': is_low_quality,  
            'domain_type': email_check.domain_type,
            'safety_rating': safety_rating,
            'display_rating': display_rating,
            'comments': comments,
            'status': status,
            'domain_data': domain_data,
            'domain_info': domain_info,
            'spam_data': spam_data,
        }
        
        return JsonResponse(response_data)
    
    #update scan count for guest users
    if not request.session.get('user_id') and remaining is not None:
            response_data['remaining_scans'] = remaining

    return JsonResponse({'error': 'Invalid request method'}, status=405)

def check_low_quality_email(email):
    """Check if an email is low quality based on patterns"""
    if '@' not in email:
        return False
    
    username = email.split('@')[0]
    
    # Check for multiple dots
    dot_count = username.count('.')
    if dot_count > 1:
        return True
    
    # Check for plus sign
    if '+' in username:
        return True
    
    return False

def feedback_submit(request):
    """API endpoint to submit feedback"""
    if request.method == 'POST':
        feedback_text = request.POST.get('feedback', '')
        email = request.POST.get('email', '')
        
        # Add debug logging
        print(f"Received feedback: {feedback_text}")
        print(f"From email: {email}")
        
        if not feedback_text:
            return JsonResponse({'error': 'Please enter feedback'}, status=400)
            
        try:
            # Save the feedback to the database
            feedback = Feedback.objects.create(
                email=email if email else None,
                feedback_text=feedback_text
            )
            
            return JsonResponse({'success': True, 'message': 'Thank you for your feedback!'})
        except Exception as e:
            print(f"Error saving feedback: {str(e)}")
            return JsonResponse({'error': f'Error saving feedback: {str(e)}'}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

# Helper functions
def check_email_format(email):
    """Check if the email format is valid using RFC 5322 standards"""
    # More comprehensive email regex that follows RFC 5322 standards
    pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    return bool(re.match(pattern, email))

def check_disposable_email(domain):
    domain = domain.lower().strip()
    mx_records = check_mx_records(domain)
    if not mx_records:
        return False
    
    # Check if domain is already known as disposable
    disposable_domains = fetch_disposable_domains()
    if domain in disposable_domains:
        return True
    
    # Check for trusted domains first (let's add this early exit)
    trusted_domains = [
        'google.com', 'gmail.com', 'outlook.com', 'hotmail.com', 'microsoft.com', 
        'yahoo.com', 'apple.com', 'icloud.com', 'protonmail.com', 'pm.me',
        'zoho.com', 'aol.com', 'mail.com', 'gmx.com', 'tutanota.com',
        'edu', 'ac.uk', 'ac.jp', 'edu.au', 'edu.cn', 'ac.in', 
        'gov', 'mil', 'gov.uk', 'gov.au', 'gov.ca', 
        'coursera.org', 'edx.org', 'udacity.com', 'udemy.com', 
        'github.com', 'gitlab.com', 'stackoverflow.com'
    ]
    
    domain_parts = domain.split('.')
    for trusted in trusted_domains:
        trusted_parts = trusted.split('.')
        if len(domain_parts) >= len(trusted_parts):
            if domain.endswith(trusted):
                return False
    
    # Early exit for educational and government domains
    if any(domain.endswith(edu_domain) for edu_domain in ['.edu', '.ac.', '.edu.']):
        return False
    if any(domain.endswith(gov_domain) for gov_domain in ['.gov', '.mil', '.gov.']):
        return False
    
    # Check for root domains in our disposable list
    if len(domain_parts) > 2:
        root_domain = '.'.join(domain_parts[-2:])
        if root_domain in disposable_domains:
            return True
        provider_info = get_email_provider_info(root_domain)
        if provider_info:
            return False
        if len(domain_parts) > 3 and domain_parts[-2] in ['co', 'com', 'org', 'net', 'ac', 'gov']:
            broader_root = '.'.join(domain_parts[-3:])
            if broader_root in disposable_domains:
                return True
            if get_email_provider_info(broader_root):
                return False
    
    # Business validation checks - NEW
    reachability = check_domain_reachability(domain)
    if reachability['web_reachable']:
        # If the domain has a working website, give it more benefit of doubt
        heuristic_result = check_domain_heuristics(domain)
        if heuristic_result < 4:  # Higher threshold for domains with websites
            return False
    
    # Only perform content check for highly suspicious domains
    heuristic_result = check_domain_heuristics(domain)
    if heuristic_result >= 4:  # Increased from 3 to 4
        update_disposable_domains_list(domain)
        return True
    
    if heuristic_result >= 3 and reachability['web_reachable']:
        try:
            content_check = check_disposable_content(domain)
            if content_check:
                update_disposable_domains_list(domain)
                return True
        except Exception as e:
            print(f"Error in content check for {domain}: {str(e)}")
    
    # More careful with the additional pattern check
    if check_new_disposable_patterns(domain) and heuristic_result >= 3:
        update_disposable_domains_list(domain)
        return True
    
    return False

# New function to catch edge cases based on patterns observed in problematic domains
def check_new_disposable_patterns(domain):
    domain_parts = domain.lower().split('.')
    domain_name = domain_parts[0] if domain_parts else ""
    
    # These are very specific to known disposable domains
    specific_patterns = ['iteradev', 'sidbasis', 'makroyal', 'tempm', 'tmpmail']
    for pattern in specific_patterns:
        if pattern in domain.lower():
            return True
    
    # Modified approach for tech keywords - requiring MORE evidence
    tech_keywords = ['temp', 'trash', 'throw', 'away', 'dump', 'junk', 'spam', 
                    'disposable', 'minute', 'burner', 'guerrilla', 'discard', 'momentary', 
                    'tmpmail', 'tempmail', 'fakeinbox', 'getnada', 'mailinator']
    
    tech_keyword_count = sum(1 for keyword in tech_keywords if keyword in domain_name)
    
    # Tech companies often have technical words in their domain
    # so we need multiple indicators, not just one tech word
    if tech_keyword_count >= 2:
        return True
    
    # Single clear disposable indicator + inaccessible website
    if tech_keyword_count == 1:
        reachability = check_domain_reachability(domain)
        mx_records = check_mx_records(domain)
        if not reachability['web_reachable'] and (not mx_records or len(mx_records) <= 1):
            return True
    
    # Requires both numeric pattern AND a suspicious keyword
    if any(part.isdigit() for part in re.findall(r'\d+', domain_name)):
        for keyword in tech_keywords:
            if keyword in domain_name:
                return True
    
    return False

def check_mailbox_exists(email):
    if '@' not in email:
        return False
    
    domain = email.split('@')[-1].lower()
    username = email.split('@')[0]

     # First check if it's an Outlook domain
    outlook_domains = ['outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'outlook.jp', 
                       'outlook.fr', 'outlook.de', 'outlook.co.uk', 'outlook.ie', 'outlook.dk',
                       'outlook.com.ar', 'outlook.com.au', 'outlook.at', 'outlook.be', 'outlook.com.br',
                       'outlook.cl', 'outlook.cz', 'hotmail.co.uk', 'hotmail.fr', 'hotmail.de']
    
    if domain in outlook_domains:
        return specialized_microsoft_probe(email)
    
    # Get MX records for the domain
    mx_records = check_mx_records(domain)
    if not mx_records:
        return False
    
    # Special handling for major email providers with known verification patterns
    special_domains = {
        'gmail.com': {'verify_method': 'smtp_probe', 'can_verify': True},
        'yahoo.com': {'verify_method': 'pattern', 'can_verify': False},
        'outlook.com': {'verify_method': 'specialized_probe', 'can_verify': True},
        'hotmail.com': {'verify_method': 'specialized_probe', 'can_verify': True},
        'live.com': {'verify_method': 'specialized_probe', 'can_verify': True},
        'aol.com': {'verify_method': 'smtp_probe', 'can_verify': True},
        'protonmail.com': {'verify_method': 'pattern', 'can_verify': False},
        'icloud.com': {'verify_method': 'pattern', 'can_verify': False},
    }
    
    # Generate a random but realistic non-existent address for catch-all detection
    import uuid
    random_username = f"nonexistent-{uuid.uuid4().hex[:12]}"
    nonexistent_email = f"{random_username}@{domain}"
    
    # First, test if the domain has a catch-all policy by sending to a random address
    catch_all_result = None
    if domain not in special_domains:
        catch_all_result = smtp_verify_address(nonexistent_email)
        # If a random nonexistent address is accepted, it's a catch-all domain
        if catch_all_result is True:
            # Since this is a catch-all domain, we can't reliably verify specific addresses
            return None
    
    # Handle special domains with known verification patterns
    if domain in special_domains:
        domain_info = special_domains[domain]
        if domain_info['verify_method'] == 'pattern':
            # For providers where we can't do SMTP verification, use pattern matching
            if domain == 'gmail.com':
                # Gmail-specific validation
                if not (6 <= len(username) <= 30) or not re.match(r'^[a-zA-Z0-9._%+-]+$', username):
                    return False
                # Gmail doesn't allow consecutive dots or dots at start/end
                if '..' in username or username.startswith('.') or username.endswith('.'):
                    return False
                return None  # We can't definitively verify Gmail accounts
            elif domain == 'yahoo.com' or domain == 'protonmail.com':
                # Yahoo/Proton validation
                if not (4 <= len(username) <= 32) or not re.match(r'^[a-zA-Z0-9._-]+$', username):
                    return False
                return None
            elif domain == 'icloud.com':
                # iCloud validation
                if not (3 <= len(username) <= 20) or not re.match(r'^[a-zA-Z0-9._-]+$', username):
                    return False
                return None
        elif domain_info['verify_method'] == 'smtp_probe' and domain_info['can_verify']:
            # Use standard SMTP probing for providers that allow it
            return smtp_verify_address(email)
        elif domain_info['verify_method'] == 'specialized_probe' and domain_info['can_verify']:
            # For Microsoft domains (outlook.com, hotmail.com, live.com)
            return specialized_microsoft_probe(email)
    
    # For other domains that aren't catch-all, do standard SMTP verification
    return smtp_verify_address(email)

def specialized_microsoft_probe(email):
    if '@' not in email:
        return False
    domain = email.split('@')[-1].lower()
    username = email.split('@')[0]
    
    # Check if domain is an Outlook domain
    outlook_domains = ['outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'outlook.jp', 
                       'outlook.fr', 'outlook.de', 'outlook.co.uk', 'outlook.ie', 'outlook.dk',
                       'outlook.com.ar', 'outlook.com.au', 'outlook.at', 'outlook.be', 'outlook.com.br',
                       'outlook.cl', 'outlook.cz', 'hotmail.co.uk', 'hotmail.fr', 'hotmail.de']
    
    if domain not in outlook_domains:
        return None
    
    # Basic pattern validation for Outlook/Hotmail accounts
    if not (1 <= len(username) <= 64):
        return False
    
    # Outlook-specific validation
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        return False
    
    # Check for disallowed patterns in username
    if '..' in username or username.startswith('.') or username.endswith('.'):
        return False
    if username.startswith('-') or username.endswith('-'):
        return False
        
    # Enhanced SMTP verification for Outlook domains
    mx_records = check_mx_records(domain)
    if not mx_records:
        return False
        
    # Try actual SMTP verification with randomized approach
    verification_attempts = 2
    sender_domains = ["verifymail.org", "mailcheck.info", "emailverification.net", "checkmail.net"]
    import random
    import uuid
    
    # Multiple verification attempts with different sender addresses
    for attempt in range(verification_attempts):
        sender = f"verify-{uuid.uuid4().hex[:8]}@{random.choice(sender_domains)}"
        
        # Use known Microsoft SMTP servers for Outlook domains
        microsoft_servers = [record['hostname'] for record in mx_records 
                             if any(ms in record['hostname'].lower() for ms in ['outlook', 'hotmail', 'microsoft'])]
        
        if not microsoft_servers:
            microsoft_servers = ['smtp-mail.outlook.com']
        
        for mx_host in microsoft_servers[:2]:
            try:
                with smtplib.SMTP(mx_host, timeout=10) as smtp:
                    # Random delay to avoid rate limiting
                    time.sleep(random.uniform(0.5, 1.5))
                    
                    # Use varied EHLO domains
                    ehlo_domain = random.choice(sender_domains)
                    smtp.ehlo(ehlo_domain)
                    
                    # Try STARTTLS if available
                    if smtp.has_extn('STARTTLS'):
                        try:
                            smtp.starttls()
                            smtp.ehlo(ehlo_domain)
                        except Exception:
                            pass
                    
                    # Additional delay
                    time.sleep(random.uniform(0.3, 0.7))
                    
                    try:
                        smtp.mail(sender)
                        time.sleep(random.uniform(0.3, 0.7))
                        
                        try:
                            code, message = smtp.rcpt(f"<{email}>")
                            message_str = str(message).lower()
                            
                            # Handle various response codes
                            if 200 <= code < 300:
                                return True
                            elif code == 550 or code == 551:
                                # Explicit rejection codes
                                rejection_phrases = [
                                    "does not exist", "user unknown", "no such user", "unknown user",
                                    "invalid recipient", "recipient rejected", "mailbox unavailable",
                                    "not found", "undeliverable", "recipient invalid", "address rejected",
                                    "address unknown", "mailbox not found"
                                ]
                                if any(phrase in message_str for phrase in rejection_phrases):
                                    return False
                            
                            # For other codes, we can't determine definitively
                            break
                            
                        except smtplib.SMTPRecipientsRefused as e:
                            return False
                        except Exception as e:
                            continue
                    except Exception as e:
                        continue
            except Exception as e:
                continue
    
    # If we can't verify, and it's an Outlook domain, we do a fallback check
    # Microsoft often blocks verification attempts, so we need to rely on pattern matching
    
    # Common patterns for Outlook domains
    outlook_forbidden_patterns = [
        r'^admin', r'^administrator', r'^hostmaster', r'^postmaster', 
        r'^webmaster', r'^support', r'^info', r'^contact', r'^noreply',
        r'^no-reply', r'^mail', r'^email', r'^feedback', r'^help',
        r'^[^@]{1,2}$'  # Extremely short usernames
    ]
    
    if any(re.match(pattern, username.lower()) for pattern in outlook_forbidden_patterns):
        return False
    
    # For Outlook domains, return None (uncertain) rather than False
    # This will trigger the "Mailbox Verification Limited" message
    return None

def smtp_verify_address(email):
    """Enhanced SMTP verification with better error handling and catch-all detection"""
    if '@' not in email:
        return False
    
    domain = email.split('@')[-1].lower()
    mx_records = check_mx_records(domain)
    if not mx_records:
        return False
    
    # Use multiple sender domains to avoid blacklisting
    sender_domains = ["verifymail.org", "mailcheck.info", "emailverification.net"]
    import random
    import uuid
    sender = f"verify-{uuid.uuid4().hex[:8]}@{random.choice(sender_domains)}"
    
    # Reasonable timeout
    smtp_timeout = 10  # Increased timeout for better reliability
    
    # Track verification results and connection metrics
    verification_result = None
    connections_attempted = 0
    connections_succeeded = 0
    
    # Try connecting to MX servers in priority order
    for mx_record in sorted(mx_records, key=lambda x: x['preference'])[:2]:
        mx_host = mx_record['hostname']
        connections_attempted += 1
        
        try:
            # Test connection before SMTP handshake
            with socket.create_connection((mx_host, 25), timeout=smtp_timeout) as sock:
                connections_succeeded += 1
            
            # Connect to SMTP server with timeout
            with smtplib.SMTP(mx_host, timeout=smtp_timeout) as smtp:
                # Add small delays between commands to avoid rate limits
                time.sleep(random.uniform(0.3, 0.6))
                
                # Use realistic HELO domains
                ehlo_domains = ["verifymail.org", "mailcheck.info", "emailverification.net"]
                ehlo_domain = random.choice(ehlo_domains)
                smtp.ehlo(ehlo_domain)
                
                # Use STARTTLS if available
                if smtp.has_extn('STARTTLS'):
                    try:
                        smtp.starttls()
                        smtp.ehlo(ehlo_domain)
                    except Exception:
                        pass
                
                # Begin the mail transaction
                time.sleep(random.uniform(0.3, 0.5))
                try:
                    smtp.mail(sender)
                    
                    # Try recipient verification with improved error analysis
                    time.sleep(random.uniform(0.3, 0.5))
                    try:
                        code, message = smtp.rcpt(f"<{email}>")
                        message_str = str(message).lower()
                        
                        # Success codes (2xx) - mailbox exists
                        if 200 <= code < 300:
                            verification_result = True
                            break
                        
                        # Handle permanent failures (5xx) - usually means mailbox doesn't exist
                        elif 500 <= code < 600:
                            # Expanded list of rejection phrases
                            rejection_phrases = [
                                "does not exist", "user unknown", "no such user", "unknown user",
                                "invalid recipient", "recipient rejected", "mailbox unavailable", 
                                "not found", "undeliverable", "recipient invalid", 
                                "no mailbox", "invalid mailbox", "user not found", 
                                "address rejected", "bad address", "address error",
                                "not our customer", "invalid address", "no such account", 
                                "recipient address rejected", "mailbox not found",
                                "user doesn't exist", "unknown recipient", "invalid user",
                                "no such mailbox", "account not found", "recipient not found",
                                "no account", "mailbox disabled", "undefined mailbox",
                                "address unknown", "bad recipient", "no receipt", "no such address",
                                "bad destination", "bad recipient address", "bad destination address"
                            ]
                            
                            # If error message indicates mailbox doesn't exist
                            if code == 550 or any(phrase in message_str for phrase in rejection_phrases):
                                verification_result = False
                                break
                            else:
                                # Other 5xx errors might be policy-related, not mailbox-related
                                pass
                        
                        # Temporary failures (4xx) - server couldn't verify now
                        elif 400 <= code < 500:
                            # Some servers use 4xx for valid addresses due to anti-spam measures
                            # We'll treat this as inconclusive
                            verification_result = None
                            
                    except smtplib.SMTPRecipientsRefused as e:
                        verification_result = False
                        break
                        
                    except Exception as e:
                        continue
                    
                except Exception as e:
                    # Failure in MAIL FROM command - try next server
                    continue
                    
                finally:
                    # Always quit properly
                    try:
                        smtp.quit()
                    except:
                        pass
                    
        except (socket.timeout, ConnectionRefusedError, ConnectionResetError,
                smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError) as e:
            # Connection issues - try next server
            continue
            
        except Exception as e:
            # Log unexpected errors but continue
            print(f"Unexpected error checking {email}: {str(e)}")
            continue
    
    # If we couldn't connect to any servers, return None (couldn't verify)
    if connections_attempted > 0 and connections_succeeded == 0:
        return None
        
    # If we never got a definitive result, return None (couldn't verify)
    if verification_result is None and connections_succeeded > 0:
        # We connected but couldn't determine mailbox status
        return None
        
    return verification_result
    
def check_domain_heuristics(domain):
    domain_parts = domain.lower().split('.')
    domain_name = domain_parts[0] if domain_parts else ""
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    
    suspicious_score = 0
    
    # Focus on clearly disposable keywords, removed ambiguous tech terms
    disposable_keywords = [
        'temp', 'fake', 'dummy', 'trash', 'throw', 'away', 
        'dispos', 'dump', 'junk', 'spam', 'minute',
        'hour', 'day', 'min', 'burner', 'guerrilla',
        'discard', 'incogni', 'secret', 'hide', 'anony', 'tempor',
        'nolog', 'no-log', 'notrack', 'no-track', 'dropmail', 'shortmail', 
        'yopmail', 'getnada', 'spambox', 'trashmail', 'mailinator',
        'sharklasers', 'maildrop', 'tempinbox', 'mailcatch', 'tempmail', 
        'tmpmail', 'fakemail', 'burnermail', 'throwawaymail', 'spambog',
        'jetable', 'mohmal', 'fakeinbox', 'tempinbox', 'emailondeck', 'zapto', 'moakt'
    ]
    
    # Remove tech terms like 'dev', 'iter', 'basis', 'royal' which can appear in legitimate business domains
    
    for keyword in disposable_keywords:
        if keyword in domain_name:
            suspicious_score += 2
            break
    
    # Domain length checks
    if len(domain_name) < 4:
        suspicious_score += 1
    elif len(domain_name) > 15:
        suspicious_score += 0.5
    
    # Check for numeric patterns
    digits = re.findall(r'\d+', domain_name)
    if digits:
        if any(len(d) >= 4 for d in digits):  # More digits more suspicious
            suspicious_score += 2
        elif any(len(d) >= 3 for d in digits):
            suspicious_score += 1
    
    # Calculate digit ratio
    digit_count = sum(c.isdigit() for c in domain_name)
    if digit_count > 3 and digit_count / len(domain_name) > 0.4:  # Stricter threshold
        suspicious_score += 1
    
    # Random pattern check - Only apply if high digit count
    if check_for_random_domain_pattern(domain) and digit_count > 2:
        suspicious_score += 2
    
    # Domain availability checks
    reachability = check_domain_reachability(domain)
    if not reachability['dns_resolves']:
        suspicious_score += 2
    if reachability['dns_resolves'] and not reachability['web_reachable']:
        suspicious_score += 1  # Reduced from 1.5
    
    # MX record checks
    mx_records = check_mx_records(domain)
    if not mx_records:
        suspicious_score += 2
    
    # Don't penalize for using legitimate email providers
    suspicious_mx_providers = [
        'mailgun', 'mailjet', 'amazonses', 'inbound-smtp.us-east-1.amazonaws.com',
        'mailstore1', 'mailfront'
    ]
    # Removed trusted providers: 'cloudflare', 'sendgrid', 'improvmx', 'forwardemail', 
    # 'mx.yandex', 'protonmail', 'zoho', 'mx.google.com', 'aspmx.l.google.com'
    
    mx_suspicious_count = 0
    for record in mx_records:
        hostname = record.get('hostname', '').lower()
        for provider in suspicious_mx_providers:
            if provider in hostname:
                mx_suspicious_count += 1
    
    if mx_records and mx_suspicious_count == len(mx_records):
        suspicious_score += 1
    
    # Don't penalize for lack of SPF since many legitimate domains don't have it
    # if not check_spf_record(domain):
    #     suspicious_score += 0.5
    
    # Subdomain check - don't penalize
    # if len(domain_parts) > 2 and domain_parts[0] not in ('www', 'mail', 'smtp', 'pop', 'imap'):
    #     suspicious_score += 0.5
    
    # TLD checks - keep these as they're good indicators
    disposable_tlds = ['.xyz', '.top', '.icu', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz',
                       '.monster', '.fun', '.click']
    # Removed legitimate TLDs: '.site', '.online', '.work', '.casa', '.email', '.tech', 
    # '.live', '.me', '.info', '.biz'
    
    for tld in disposable_tlds:
        if domain.lower().endswith(tld):
            suspicious_score += 1
            break
    
    # Final assessment for domains with no web presence
    if not reachability['dns_resolves'] or not reachability['web_reachable']:
        has_suspicious_name = any(keyword in domain_name for keyword in disposable_keywords)
        if has_suspicious_name and check_for_random_domain_pattern(domain):
            suspicious_score += 2  # Reduced from 3
    
    return suspicious_score

def update_disposable_domains_list(domain):
    """Add confirmed disposable domains to the database for future checks"""
    from .models import DisposableDomain
    
    domain = domain.lower().strip()
    
    # Check if already in database
    if not DisposableDomain.objects.filter(domain=domain).exists():
        try:
            DisposableDomain.objects.create(domain=domain)
            
            # Also add to the cache
            with disposable_domains_cache['lock']:
                if disposable_domains_cache['domains']:
                    disposable_domains_cache['domains'].add(domain)
                    
            print(f"Added {domain} to disposable domains database")
        except Exception as e:
            print(f"Error adding domain to database: {str(e)}")

def determine_domain_type(domain):
    """Determine if the email domain is personal, business, or other"""
    # Common personal email domains
    personal_domains = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
        'icloud.com', 'protonmail.com', 'mail.com', 'zoho.com', 'yandex.com',
        'gmx.com', 'tutanota.com', 'live.com', 'msn.com'
    ]
    
    # Common education domains
    education_domains = ['.edu', '.edu.', '.ac.']
    
    # Common government domains
    government_domains = ['.gov', '.gov.', '.mil']
    
    domain_lower = domain.lower()
    
    if domain_lower in personal_domains:
        return 'personal'
    elif any(edu_domain in domain_lower for edu_domain in education_domains):
        return 'education'
    elif any(gov_domain in domain_lower for gov_domain in government_domains):
        return 'government'
    else:
        # Try to check if it's a valid domain with MX records
        try:
            if get_mx_records(domain):
                return 'business'
        except:
            pass
        
        return 'unknown'

def get_mx_records(domain):
    """Get MX records for a domain"""
    mx_records = []
    try:
        # Query DNS for MX records
        answers = dns.resolver.resolve(domain, 'MX')
        
        # Sort by preference (lower is higher priority)
        for rdata in sorted(answers, key=lambda x: x.preference):
            # Convert to string and remove trailing dot
            mx_hostname = str(rdata.exchange).rstrip('.')
            
            # Try to get IP address
            try:
                ip_address = socket.gethostbyname(mx_hostname)
            except:
                ip_address = "Could not resolve"
                
            mx_records.append({
                'hostname': mx_hostname,
                'preference': rdata.preference,
                'ip_address': ip_address
            })
    except Exception as e:
        # No MX records or error in lookup
        pass
        
    return mx_records

def check_spam_databases(email):
    """Check domain and mail server against spam databases"""
    if '@' not in email:
        return None
    
    domain = email.split('@')[-1].lower()
    
    # Check if we have a cached result that's less than 24 hours old
    cached_entry = None
    try:
        cutoff_time = timezone.now() - timedelta(hours=24)
        cached_entry = SpamDatabaseEntry.objects.filter(
            identifier=domain, 
            is_domain=True,
            last_checked__gte=cutoff_time
        ).first()
        
        if cached_entry:
            print(f"Using cached spam data for {domain} (cached at {cached_entry.last_checked})")
            
            # Get blacklists from cached entry
            try:
                if isinstance(cached_entry.blacklists, str):
                    blacklists = json.loads(cached_entry.blacklists)
                else:
                    blacklists = cached_entry.blacklists
            except:
                blacklists = []
                
            # Get score from cached entry
            try:
                spam_score = float(cached_entry.score)
                if math.isnan(spam_score):
                    spam_score = 0
            except:
                spam_score = 0
                
            # Return cached data in the proper format
            return {
                'domain': domain,
                'domain_listed': len(blacklists) > 0,
                'domain_blacklists': blacklists,
                'ip_addresses': [], # Not storing these in cache
                'ip_results': [],   # Not storing these in cache
                'spam_score': spam_score,
                'source': 'cache'
            }
    except Exception as e:
        print(f"Error checking spam database cache: {str(e)}")
    
    # If we get here, we need to do a fresh check (no valid cache or error)
    print(f"Performing fresh spam database check for {domain}")
    
    # Initialize default values
    domain_results = {'is_listed': False, 'blacklists': []}
    ip_results = []
    ip_addresses = []
    
    # Get IP addresses associated with the domain
    ip_addresses = get_domain_ip_addresses(domain)
    
    # Check domain against domain-based blacklists
    domain_results = check_domain_blacklists(domain)
    
    # Check IPs against IP-based blacklists
    for ip in ip_addresses:
        ip_result = check_ip_blacklists(ip)
        if ip_result and ip_result.get('is_listed'):
            ip_results.append(ip_result)
    
    # BALANCED SCORE CALCULATION
    spam_score = 0
    
    # Domain blacklist scoring
    domain_bl_count = len(domain_results.get('blacklists', []))
    if domain_bl_count > 0:
        # Lower base scores
        if domain_bl_count == 1:
            spam_score = 15  # Single listing
        else:
            spam_score = 25 + ((domain_bl_count - 1) * 10)  # Multiple listings
        
        # Small bonus for reputable blacklists
        high_reputation_blacklists = ['dbl.spamhaus.org', 'multi.surbl.org', 'uribl.com']
        for bl in high_reputation_blacklists:
            if bl in domain_results.get('blacklists', []):
                spam_score += 5
    
    # IP blacklist scoring
    ip_blacklist_count = sum(len(ip_result.get('blacklists', [])) for ip_result in ip_results)
    if ip_blacklist_count > 0:
        if spam_score == 0:  # No domain blacklists found
            spam_score = 10  # Base score for single IP blacklist
            if ip_blacklist_count > 1:
                spam_score += min(15, (ip_blacklist_count - 1) * 3)
        else:
            # Add smaller amount for IP blacklists when domain is already listed
            spam_score += min(10, ip_blacklist_count * 2)
    
    # Cap at 100
    spam_score = min(100, spam_score)
    
    # Store results in database
    try:
        entry, created = SpamDatabaseEntry.objects.update_or_create(
            identifier=domain,
            is_domain=True,
            defaults={
                'blacklists': domain_results.get('blacklists', []),
                'last_checked': timezone.now(),
                'score': float(spam_score)
            }
        )
        
        # Store IP entries
        for ip_result in ip_results:
            if ip_result.get('ip'):
                ip_score = (len(ip_result.get('blacklists', [])) / max(1, len(IP_BLACKLISTS))) * 30  # Lower max score for IPs
                SpamDatabaseEntry.objects.update_or_create(
                    identifier=ip_result.get('ip'),
                    is_domain=False,
                    defaults={
                        'blacklists': ip_result.get('blacklists', []),
                        'last_checked': timezone.now(),
                        'score': float(ip_score)
                    }
                )
    except Exception as e:
        print(f"Error storing spam database results: {str(e)}")
    
    return {
        'domain': domain,
        'domain_listed': domain_results.get('is_listed', False),
        'domain_blacklists': domain_results.get('blacklists', []),
        'ip_addresses': ip_addresses,
        'ip_results': ip_results,
        'spam_score': spam_score,
        'source': 'live_check'
    }

# Domain-based spam blacklists
DOMAIN_BLACKLISTS = [
    'uribl.com',
    'dbl.spamhaus.org',
    'multi.surbl.org',  # This one is working for you
    'dbltest.com',
    'blacklist.netcore.co.in',
    # 'hostkarma.junkemailfilter.com',
    'nomail.rhsbl.sorbs.net',
    'rhsbl.sorbs.net',
    'spam.spamrats.com',
    'spamrbl.imp.ch',
    'dbl.rbl.webiron.net'
]

# IP-based spam blacklists
IP_BLACKLISTS = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'dnsbl.sorbs.net',
    'spam.dnsbl.anonmails.de',
    'bl.mailspike.net',
    'cbl.abuseat.org',
    'b.barracudacentral.org',
    'spam.dnsbl.sorbs.net',
    'dnsbl.dronebl.org',
    'blacklist.woody.ch',
    'db.wpbl.info',
    'sbl.spamhaus.org',
    'xbl.spamhaus.org',
    'pbl.spamhaus.org'
]

def get_domain_ip_addresses(domain):
    """Get all IP addresses associated with a domain including MX records"""
    ip_addresses = set()
    
    # Check domain's A record
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            ip_addresses.add(str(rdata))
    except Exception as e:
        pass
    
    # Check MX records
    try:
        mx_records = check_mx_records(domain)
        for mx_record in mx_records:
            if 'hostname' in mx_record and mx_record['hostname']:
                try:
                    mx_answers = dns.resolver.resolve(mx_record['hostname'], 'A')
                    for rdata in mx_answers:
                        ip_addresses.add(str(rdata))
                except Exception:
                    # If IP is directly in hostname record
                    if 'ip_address' in mx_record and mx_record['ip_address'] and mx_record['ip_address'] != "Resolution failed":
                        ip_addresses.add(mx_record['ip_address'])
    except Exception as e:
        pass
    
    return list(ip_addresses)

def check_domain_blacklists(domain):
    """Check a domain against domain-based blacklists"""
    results = {'domain': domain, 'is_listed': False, 'blacklists': [], 'debug_info': []}
    
    print(f"Checking domain {domain} against {len(DOMAIN_BLACKLISTS)} blacklists...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_bl = {
            executor.submit(check_single_bl, domain, bl): bl 
            for bl in DOMAIN_BLACKLISTS
        }
        
        for future in concurrent.futures.as_completed(future_to_bl):
            bl = future_to_bl[future]
            try:
                is_listed = future.result()
                results['debug_info'].append(f"{bl}: {'Listed' if is_listed else 'Not listed'}")
                print(f"Domain {domain} check against {bl}: {'Listed' if is_listed else 'Not listed'}")
                
                if is_listed:
                    results['is_listed'] = True
                    results['blacklists'].append(bl)
            except Exception as e:
                results['debug_info'].append(f"{bl}: Error - {str(e)}")
                print(f"Error checking {domain} against {bl}: {str(e)}")
    
    print(f"Domain {domain} blacklist results: {results['blacklists']}")
    return results

def check_ip_blacklists(ip):
    """Check an IP against IP-based blacklists"""
    results = {'ip': ip, 'is_listed': False, 'blacklists': []}
    
    # Check if valid IP
    try:
        socket.inet_aton(ip)
    except:
        return results
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_bl = {
            executor.submit(check_single_bl, reverse_ip(ip), bl): bl 
            for bl in IP_BLACKLISTS
        }
        
        for future in concurrent.futures.as_completed(future_to_bl):
            bl = future_to_bl[future]
            try:
                is_listed = future.result()
                if is_listed:
                    results['is_listed'] = True
                    results['blacklists'].append(bl)
            except Exception as e:
                print(f"Error checking {ip} against {bl}: {str(e)}")
    
    return results

def reverse_ip(ip):
    """Reverse an IP address for DNSBL lookup (e.g., 1.2.3.4 becomes 4.3.2.1)"""
    if not ip:
        return None
    try:
        return '.'.join(reversed(ip.split('.')))
    except:
        return None

def check_single_bl(query, blacklist):
    """Check if a query (domain or reversed IP) is listed in a single blacklist"""
    try:
        query_domain = f"{query}.{blacklist}"
        
        # Configure a specific resolver with better timeout settings
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.0
        resolver.lifetime = 2.0
        
        # Try with multiple DNS servers if needed
        try:
            resolver.resolve(query_domain, 'A')
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except Exception:
            # Try alternate DNS servers
            for dns_server in ['8.8.8.8', '1.1.1.1', '9.9.9.9']:
                try:
                    resolver.nameservers = [dns_server]
                    resolver.resolve(query_domain, 'A')
                    return True
                except dns.resolver.NXDOMAIN:
                    return False
                except:
                    continue
            return False
    except Exception as e:
        print(f"Error checking {query} against {blacklist}: {str(e)}")
        return False

def calculate_safety_rating(email_check, domain_data, domain_info=None, spam_data=None):
    if not email_check.is_valid or not domain_data.get('has_mx', False):
        return 0
        
    rating = 0
    
    # Base points for valid email format and domain
    rating += 30
    
    # Not a disposable email
    if not email_check.is_disposable:
        rating += 15
        
    # Has MX records
    if domain_data.get('has_mx', False):
        rating += 15
        
    # Mailbox exists
    if domain_data.get('mailbox_exists', None) is True:
        rating += 10
        
    # Domain type bonuses
    if email_check.domain_type == 'business':
        rating += 10
    elif email_check.domain_type == 'personal':
        rating += 15
    elif email_check.domain_type == 'education':
        rating += 15
    elif email_check.domain_type == 'government':
        rating += 15
        
    # Domain age points
    if domain_info and domain_info.get('creation_date'):
        try:
            creation_date = datetime.strptime(domain_info['creation_date'], '%Y-%m-%d')
            age_in_years = (datetime.now() - creation_date).days / 365
            if age_in_years > 10:
                rating += 10
            elif age_in_years > 5:
                rating += 8
            elif age_in_years > 3:
                rating += 6
            elif age_in_years > 1:
                rating += 4
            else:
                rating += 2
        except:
            pass
            
    # Popular email provider bonus
    if domain_info and domain_info.get('is_popular', False):
        rating += 5
        
    # Organization information bonus
    if domain_info and domain_info.get('organization'):
        rating += 5
        
    # NEW: Spam database penalty
    if spam_data:
        spam_score = spam_data.get('spam_score', 0)
        # Penalize based on spam score (higher spam score = higher penalty)
        if spam_score > 80:
            rating -= 50  # Severe penalty for highly listed domains
        elif spam_score > 50:
            rating -= 30  # Strong penalty
        elif spam_score > 30:
            rating -= 20  # Moderate penalty
        elif spam_score > 10:
            rating -= 10  # Minor penalty
            
        # Additional penalty for domain specifically being listed (vs just IPs)
        if spam_data.get('domain_listed', False):
            rating -= 15
            
    return max(0, min(rating, 100))  # Ensure rating is between 0-100

def generate_comments(email_check, domain_data, domain_info=None, spam_data=None, is_low_quality=False):
    comments = []
    
    # Basic validation comments
    if not email_check.is_valid:
        comments.append("❌ Invalid email format.")
    else:
        comments.append("✅ Valid email format.")
        
        # Domain validation comments
        if not domain_data.get('has_mx', False):
            comments.append(f"❌ This domain does not have MX records and cannot receive email. This appears to be an invalid email domain.")
        else:
            comments.append(f"✅ This domain has MX records and can receive email.")
            
            # Mailbox validation comments
            if domain_data.get('mailbox_exists') is False:
                comments.append("❌ However, the specific mailbox for this email address does not exist or is not accepting mail.")
            elif domain_data.get('mailbox_exists') is True:
                comments.append("✅ The mailbox for this address exists and can receive email.")
            elif domain_data.get('mailbox_exists') is None:
                comments.append("⚠️ Many email servers don't allow verification of individual mailboxes to prevent spam. We couldn't definitively verify if this mailbox exists, but the domain itself is valid and can receive email.")
                
            # Disposable email comments
            if email_check.is_disposable:
                comments.append("⚠️ WARNING: This is a disposable email address, typically used for temporary accounts or to avoid identification. Exercise caution when dealing with this address.")
            else:
                comments.append("✅ This is not a disposable email address.")

            if is_low_quality:
                comments.append("⚠️ This is a low quality email address with multiple dots or plus signs in the username, which may be used for filter bypassing or disposable purposes.")
                
            # Spam database comments
            if spam_data:
                spam_score = spam_data.get('spam_score', 0)
                if spam_score > 0:
                    # Domain blacklist comment
                    if spam_data.get('domain_listed', False) and spam_data.get('domain_blacklists'):
                        bl_count = len(spam_data.get('domain_blacklists', []))
                        comments.append(f"⚠️ WARNING: This email domain is listed in {bl_count} spam blacklist{'s' if bl_count > 1 else ''}. This strongly indicates the domain is used for sending spam.")
                    
                    # IP blacklist comments
                    ip_listings = []
                    for ip_result in spam_data.get('ip_results', []):
                        if ip_result.get('is_listed') and ip_result.get('blacklists'):
                            ip_listings.append(f"{ip_result.get('ip')} (in {len(ip_result.get('blacklists'))} blacklists)")
                    
                    if ip_listings:
                        comments.append(f"⚠️ CAUTION: The mail servers for this domain have IP addresses that appear in spam blacklists: {', '.join(ip_listings)}.")
                    
                    # Overall spam risk assessment
                    if spam_score > 80:
                        comments.append("🚨 This email address has a VERY HIGH spam risk score. It appears on multiple blacklists and should be treated with extreme caution.")
                    elif spam_score > 50:
                        comments.append("⚠️ This email address has a HIGH spam risk score based on blacklist appearances.")
                    elif spam_score > 30:
                        comments.append("⚠️ This email address has a MODERATE spam risk score.")
                    elif spam_score > 10:
                        comments.append("ℹ️ This email address has a LOW spam risk score, but does appear on some blacklists.")
                else:
                    comments.append("✅ This email domain and its servers do not appear on any spam blacklists, which is a positive indicator.")
            
            # Email provider comments
            if domain_info and domain_info.get('is_popular', False):
                provider = domain_info['provider_info']
                comments.append(f"✅ This email uses {provider['name']} provided by {provider['company']}, a well-established email service founded in {provider['founded']}.")
            elif domain_info and domain_info.get('organization'):
                comments.append(f"ℹ️ This email domain is registered to {domain_info['organization']}.")
                
            # Domain age comments
            if domain_info and domain_info.get('creation_date'):
                comments.append(f"ℹ️ This domain was created on {domain_info['creation_date']}.")
                try:
                    creation_date = datetime.strptime(domain_info['creation_date'], '%Y-%m-%d')
                    age_in_years = (datetime.now() - creation_date).days / 365
                    if age_in_years < 1:
                        comments.append("⚠️ This domain is less than 1 year old, which could indicate a new legitimate business or a recently created domain for suspicious purposes.")
                    elif age_in_years > 10:
                        comments.append("✅ This domain has been registered for over 10 years, which is a positive indication of legitimacy.")
                except:
                    pass
                    
            # Domain type comments
            if email_check.domain_type == 'personal':
                comments.append("✅ This email belongs to a common personal email provider.")
            elif email_check.domain_type == 'business':
                comments.append("ℹ️ This email appears to belong to a business domain.")
            elif email_check.domain_type == 'education':
                comments.append("✅ This email appears to belong to an educational institution.")
            elif email_check.domain_type == 'government':
                comments.append("✅ This email appears to belong to a government domain.")
            else:
                comments.append("ℹ️ Unable to determine the domain type.")
                
    return "\n".join(comments)

def generate_pdf_report(request):
    if request.method == 'POST':
        try:
            # Get the JSON data from the request
            data = json.loads(request.body)
            email_results = data.get('report_data')
            
            if not email_results:
                return JsonResponse({'error': 'No report data provided'}, status=400)
                
            # Create a template context with the results
            context = {
                'report': email_results,
                'generated_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
            
            # Render the template
            template = get_template('services/email_report_pdf.html')
            html = template.render(context)
            
            # Create a PDF
            result = BytesIO()
            pdf = pisa.pisaDocument(BytesIO(html.encode("UTF-8")), result)
            
            if not pdf.err:
                # Encode the PDF as base64 to return to frontend
                pdf_data = base64.b64encode(result.getvalue()).decode('utf-8')
                return JsonResponse({
                    'success': True,
                    'pdf_data': pdf_data,
                    'filename': f"VAST_EMAIL_Report_{email_results['email'].replace('@', '_at_')}.pdf"
                })
            else:
                return JsonResponse({'error': 'Error generating PDF'}, status=500)
                
        except Exception as e:
            print(f"Error generating PDF: {str(e)}")
            return JsonResponse({'error': f'Error generating PDF: {str(e)}'}, status=500)
            
    return JsonResponse({'error': 'Invalid request method'}, status=405)