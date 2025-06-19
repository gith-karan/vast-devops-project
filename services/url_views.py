import re
import json
import socket
import ssl
import threading
import time
import requests
import tldextract
import dns.resolver
from urllib.parse import urlparse, urlunparse, parse_qs
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.template.loader import get_template
from django.utils import timezone
from xhtml2pdf import pisa
from io import BytesIO
import whois
import os
import time

from .models import URLCheck, URLCheckResult, URLRedirect, TrackerDetection
from .scan_limiter import ScanLimiter

# Global cache for URL shorteners
url_shorteners_cache = {
    'shorteners': set(),
    'last_updated': None,
    'lock': threading.Lock()
}

def fetch_url_shorteners():
    """Fetch a list of URL shorteners with memory caching"""
    global url_shorteners_cache
    
    with url_shorteners_cache['lock']:
        current_time = time.time()
        
        # Return cached data if available and less than a week old
        if url_shorteners_cache['last_updated'] is not None and \
           current_time - url_shorteners_cache['last_updated'] < 60 * 60 * 24 * 7:  # 7 days
            return url_shorteners_cache['shorteners']
        
        # Default list as fallback
        shortener_list = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly',
            'rebrand.ly', 'ow.ly', 'tr.im', 'cli.gs', 'tiny.cc', 'shorte.st',
            'go.me', 'wp.me', 'u.nu', 'x.co', 'surl.li', 'rb.gy', 'cutt.ly',
            'snip.ly', 'vs.gd', 'lc.chat', 'db.tt', 'qr.ae', 'moourl.com',
            'clck.ru', 'tggl.io', 'bit.do', 'bl.ink', 'adcrun.ch', 'dft.ba',
            'filoops.info', 'simurl.com', 'adf.ly', 'j.mp', 'smallurl.co'
        ]
        
        try:
            # Fetch from GitHub
            response = requests.get('https://raw.githubusercontent.com/PeterDaveHello/url-shorteners/refs/heads/master/list', timeout=10)
            if response.status_code == 200:
                # Parse the list
                shorteners = [line.strip().lower() for line in response.text.split('\n') 
                             if line.strip() and not line.strip().startswith('#')]
                
                # Make sure bit.ly is in the list
                if 'bit.ly' not in shorteners:
                    shorteners.append('bit.ly')
                
                # Update cache with the fetched list
                url_shorteners_cache['shorteners'] = set(shorteners)
                url_shorteners_cache['last_updated'] = current_time
                
                print(f"Updated URL shorteners cache with {len(shorteners)} entries")
                return url_shorteners_cache['shorteners']
                
        except Exception as e:
            print(f"Error fetching URL shortener list: {str(e)}")
        
        # Update cache with default list if fetching failed
        url_shorteners_cache['shorteners'] = set(shortener_list)
        url_shorteners_cache['last_updated'] = current_time
        
    return url_shorteners_cache['shorteners']

# Replace the URL_SHORTENERS list declaration with this:
URL_SHORTENERS = fetch_url_shorteners()

def url_scanner_view(request):
    """Render the URL scanner page"""
    context = {}
    
    # Check if user is logged in
    user_email = request.session.get('user_email')
    
    if user_email:
        # Get user info for display
        from accounts.models import User
        try:
            user = User.objects.get(email=user_email)
            context['username'] = user.username
            context['joined_date'] = user.date_joined  # Changed from created_at to date_joined
            context['is_guest'] = False
        except User.DoesNotExist:
            context['is_guest'] = True
    else:
        context['is_guest'] = True
    
    return render(request, 'services/url.html', context)

def json_serialize_helper(obj):
    """Helper function to make objects JSON serializable"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)

def is_valid_domain(domain):
    """Check if a domain is valid and resolvable"""
    try:
        # Check if the domain is syntactically valid
        if not re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', domain):
            return False, "Invalid domain format"
        
        # Check if the domain has a valid TLD
        extracted = tldextract.extract(domain)
        if not extracted.suffix:
            return False, "Invalid domain (missing or invalid TLD)"
        
        # Try to resolve the domain using DNS
        socket.gethostbyname(domain)
        return True, "Domain is valid"
    except socket.gaierror:
        return False, "Domain not resolvable"
    except Exception as e:
        return False, f"Error validating domain: {str(e)}"

def get_ip_range(ip_address):
    """
    Determine the IP range for a given IP address
    Returns a dict with CIDR notation and range information
    """
    if not ip_address or ip_address == 'Unknown':
        return {
            'cidr': None,
            'range_start': None,
            'range_end': None,
            'error': 'No IP address provided'
        }
    
    try:
        # Convert IP to integer for easier range calculation
        ip_parts = ip_address.split('.')
        if len(ip_parts) != 4:  # Ensure it's IPv4
            return {
                'cidr': None,
                'range_start': None,
                'range_end': None,
                'error': 'Not a valid IPv4 address'
            }
        
        # Determine the likely CIDR block (assuming a /24 network)
        # This is a simplification - in production you might want to use 
        # a service like ipwhois or a local database like MaxMind
        network_prefix = '.'.join(ip_parts[:3])
        cidr = f"{network_prefix}.0/24"
        
        # Calculate range start and end
        range_start = f"{network_prefix}.1"
        range_end = f"{network_prefix}.254"
        
        return {
            'cidr': cidr,
            'range_start': range_start,
            'range_end': range_end,
            'error': None
        }
    except Exception as e:
        return {
            'cidr': None,
            'range_start': None,
            'range_end': None,
            'error': f"Error determining IP range: {str(e)}"
        }


def resolve_domain_to_ip(domain):
    """
    Resolve a domain name to its IP address(es) and determine IP range
    Returns a dict with 'primary_ip', 'all_ips' list, and 'ip_range'
    """
    result = {
        'primary_ip': None,
        'all_ips': [],
        'ip_range': None,
        'error': None
    }
    
    try:
        # Get all IP addresses associated with the domain
        ip_list = socket.gethostbyname_ex(domain)[2]
        
        if ip_list:
            result['primary_ip'] = ip_list[0]
            result['all_ips'] = ip_list
            
            # Get IP range for the primary IP
            result['ip_range'] = get_ip_range(ip_list[0])
        else:
            result['error'] = "No IP addresses found"
            
    except socket.gaierror as e:
        result['error'] = f"DNS resolution failed: {str(e)}"
    except Exception as e:
        result['error'] = f"Error resolving IP: {str(e)}"
        
    return result

def discover_page_content(url):
    """
    Discover links, javascripts, and iframes on a webpage
    Returns a dict with lists of discovered content
    """
    discovered = {
        'links': [],
        'scripts': [],
        'iframes': [],
        'embedded_objects': [],
        'error': None
    }
    
    try:
        # Set proper headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        
        # Make a GET request to fetch the page content
        response = requests.get(url, headers=headers, timeout=15, verify=False)
        
        if response.status_code != 200:
            discovered['error'] = f"HTTP error: Status code {response.status_code}"
            return discovered
            
        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract base URL for resolving relative URLs
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Process all links (a tags)
        for link in soup.find_all('a', href=True):
            href = link['href'].strip()
            
            # Skip empty links and javascript: links
            if not href or href.startswith('javascript:') or href == '#':
                continue
                
            # Resolve relative URLs
            if href.startswith('/'):
                full_url = f"{base_url}{href}"
            elif not href.startswith(('http://', 'https://')):
                full_url = f"{base_url}/{href}"
            else:
                full_url = href
                
            # Add to discovered links
            link_text = link.get_text().strip()
            if not link_text:
                link_text = "(No text)"
            
            discovered['links'].append({
                'url': full_url,
                'text': link_text[:50] + ('...' if len(link_text) > 50 else '')
            })
        
        # Process all scripts
        for script in soup.find_all('script', src=True):
            src = script['src'].strip()
            
            # Resolve relative URLs
            if src.startswith('/'):
                full_url = f"{base_url}{src}"
            elif not src.startswith(('http://', 'https://')):
                full_url = f"{base_url}/{src}"
            else:
                full_url = src
                
            discovered['scripts'].append({
                'url': full_url,
                'type': script.get('type', 'text/javascript')
            })
        
        # Process all iframes
        for iframe in soup.find_all('iframe'):
            src = iframe.get('src', '').strip()
            
            # Skip empty sources
            if not src:
                continue
                
            # Resolve relative URLs
            if src.startswith('/'):
                full_url = f"{base_url}{src}"
            elif not src.startswith(('http://', 'https://')):
                full_url = f"{base_url}/{src}"
            else:
                full_url = src
                
            discovered['iframes'].append({
                'url': full_url,
                'title': iframe.get('title', '(No title)')
            })
        
        # Process other embedded objects (embed, object tags)
        for obj in soup.find_all(['embed', 'object']):
            src = obj.get('src', obj.get('data', '')).strip()
            
            # Skip empty sources
            if not src:
                continue
                
            # Resolve relative URLs
            if src.startswith('/'):
                full_url = f"{base_url}{src}"
            elif not src.startswith(('http://', 'https://')):
                full_url = f"{base_url}/{src}"
            else:
                full_url = src
                
            discovered['embedded_objects'].append({
                'url': full_url,
                'type': obj.get('type', '(Unknown type)')
            })
        
        # Limit the number of results to avoid overwhelming the UI
        discovered['links'] = discovered['links'][:100]
        discovered['scripts'] = discovered['scripts'][:50]
        discovered['iframes'] = discovered['iframes'][:20]
        discovered['embedded_objects'] = discovered['embedded_objects'][:20]
        
    except Exception as e:
        discovered['error'] = f"Error discovering page content: {str(e)}"
        
    return discovered



def get_hosting_info(url):
    """
    Get hosting provider and server information for a URL
    Returns a dict with hosting provider and server details
    """
    hosting_info = {
        'provider': None,
        'server': None,
        'error': None
    }
    
    try:
        # Set proper headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        
        # Make a HEAD request to get headers without downloading the full page
        response = requests.head(url, headers=headers, timeout=10, allow_redirects=True)
        
        # Get server information from headers
        if 'Server' in response.headers:
            hosting_info['server'] = response.headers['Server']
        
        # Try to determine hosting provider from headers and other signals
        # This is approximate and may not always be accurate
        headers_str = str(response.headers).lower()
        
        # Check for common hosting providers in headers
        if 'cloudflare' in headers_str:
            hosting_info['provider'] = 'Cloudflare'
        elif 'aws' in headers_str or 'amazon' in headers_str:
            hosting_info['provider'] = 'Amazon Web Services (AWS)'
        elif 'azure' in headers_str or 'microsoft' in headers_str:
            hosting_info['provider'] = 'Microsoft Azure'
        elif 'google' in headers_str or 'gws' in headers_str:
            hosting_info['provider'] = 'Google Cloud'
        elif 'fastly' in headers_str:
            hosting_info['provider'] = 'Fastly'
        elif 'akamai' in headers_str:
            hosting_info['provider'] = 'Akamai'
        elif 'litespeed' in headers_str:
            hosting_info['provider'] = 'LiteSpeed'
        elif 'nginx' in headers_str and hosting_info['server'] and 'nginx' in hosting_info['server'].lower():
            hosting_info['provider'] = 'NGINX-based host'
        elif 'apache' in headers_str and hosting_info['server'] and 'apache' in hosting_info['server'].lower():
            hosting_info['provider'] = 'Apache-based host'
        else:
            hosting_info['provider'] = 'Unknown'
            
    except requests.exceptions.RequestException as e:
        hosting_info['error'] = f"Error fetching hosting info: {str(e)}"
    except Exception as e:
        hosting_info['error'] = f"Error: {str(e)}"
        
    return hosting_info

def follow_redirects(url, max_redirects=10):
    """
    Follow URL redirects and return the redirect chain
    Returns a list of dicts with url and status_code
    """
    redirect_chain = []
    current_url = url
    
    try:
        with requests.Session() as session:
            session.max_redirects = max_redirects
            
            # Set a proper user agent to avoid being blocked
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'max-age=0',
            }
            
            # Disable redirects to handle them manually
            response = session.get(url, headers=headers, allow_redirects=False, timeout=10, verify=False)
            redirect_chain.append({'url': url, 'status_code': response.status_code})
            
            # Follow redirects manually to capture each step
            redirect_count = 0
            while redirect_count < max_redirects and response.is_redirect:
                redirect_count += 1
                
                # Get the redirect URL
                if 'location' in response.headers:
                    # Handle relative URLs
                    redirect_url = response.headers['location']
                    if redirect_url.startswith('/'):
                        parsed_url = urlparse(current_url)
                        redirect_url = f"{parsed_url.scheme}://{parsed_url.netloc}{redirect_url}"
                    
                    current_url = redirect_url
                    response = session.get(current_url, headers=headers, allow_redirects=False, timeout=10, verify=False)
                    redirect_chain.append({'url': current_url, 'status_code': response.status_code})
                else:
                    break
                
        return current_url, redirect_chain
        
    except requests.exceptions.TooManyRedirects:
        # Append a note about max redirects exceeded
        redirect_chain.append({'url': 'Max redirects exceeded', 'status_code': None})
        return current_url, redirect_chain
    except Exception as e:
        # Handle other exceptions
        redirect_chain.append({'url': f'Error: {str(e)}', 'status_code': None})
        return current_url, redirect_chain

def check_ssl_certificate(domain):
    """Check if the domain has a valid SSL certificate"""
    try:
        ssl_context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ssl_context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssl_info = ssock.getpeercert()
                # Extract certificate info
                not_after = datetime.strptime(ssl_info.get('notAfter'), '%b %d %H:%M:%S %Y %Z')
                not_before = datetime.strptime(ssl_info.get('notBefore'), '%b %d %H:%M:%S %Y %Z')
                issuer = ', '.join([f"{k}={v}" for k, v in ssl_info['issuer'][0]])
                subject = ', '.join([f"{k}={v}" for k, v in ssl_info['subject'][0]])
                
                return {
                    'valid': True,
                    'issuer': issuer,
                    'subject': subject,
                    'not_before': not_before,
                    'not_after': not_after,
                    'expiry_days': (not_after - datetime.now()).days
                }
    except Exception as e:
        return {
            'valid': False,
            'error': str(e)
        }

def get_domain_info(domain):
    """
    Get information about a domain including registration date, age, and registrar
    Returns a tuple of (domain_age_days, domain_info_dict)
    """
    domain_info = {
        'creation_date': None,
        'expiration_date': None,
        'last_updated': None,
        'registrar': 'Unknown',
        'age': 'Unknown',
        'name_servers': [],
        'status': 'Unknown',
        'error': None
    }
    
    domain_age_days = 0  # Default value if we can't determine age
    
    try:
        # Query WHOIS information for the domain
        w = whois.whois(domain)
        
        # Handle creation date
        if w.creation_date:
            # Some domains return a list of dates, take the first one
            if isinstance(w.creation_date, list):
                domain_info['creation_date'] = w.creation_date[0]
            else:
                domain_info['creation_date'] = w.creation_date
                
            # Calculate age
            if domain_info['creation_date']:
                now = datetime.now()
                domain_age_days = (now - domain_info['creation_date']).days
                years = domain_age_days // 365
                months = (domain_age_days % 365) // 30
                days = (domain_age_days % 365) % 30
                
                if years > 0:
                    domain_info['age'] = f"{years} year{'s' if years != 1 else ''}"
                    if months > 0:
                        domain_info['age'] += f", {months} month{'s' if months != 1 else ''}"
                elif months > 0:
                    domain_info['age'] = f"{months} month{'s' if months != 1 else ''}"
                    if days > 0:
                        domain_info['age'] += f", {days} day{'s' if days != 1 else ''}"
                elif days > 0:
                    domain_info['age'] = f"{days} day{'s' if days != 1 else ''}"
                else:
                    domain_info['age'] = "Less than a day"
        
        # Handle expiration date
        if w.expiration_date:
            if isinstance(w.expiration_date, list):
                domain_info['expiration_date'] = w.expiration_date[0]
            else:
                domain_info['expiration_date'] = w.expiration_date
        
        # Handle last updated date
        if hasattr(w, 'updated_date') and w.updated_date:
            if isinstance(w.updated_date, list):
                domain_info['last_updated'] = w.updated_date[0]
            else:
                domain_info['last_updated'] = w.updated_date
        
        # Handle registrar
        if hasattr(w, 'registrar') and w.registrar:
            domain_info['registrar'] = w.registrar
        
        # Handle name servers
        if hasattr(w, 'name_servers') and w.name_servers:
            if isinstance(w.name_servers, list):
                domain_info['name_servers'] = [ns.lower() for ns in w.name_servers if ns]
            else:
                domain_info['name_servers'] = [w.name_servers.lower()]
        
        # Handle status
        if hasattr(w, 'status') and w.status:
            if isinstance(w.status, list):
                domain_info['status'] = w.status[0]
            else:
                domain_info['status'] = w.status
                
    except Exception as e:
        domain_info['error'] = str(e)
        
    return domain_age_days, domain_info


def detect_defacement(url, response_content):
    """
    Detect if a website has been defaced by looking for common defacement markers
    Returns a dict with detection results
    """
    result = {
        'defaced': False,
        'confidence': 0,
        'evidence': None,
        'defacement_text': None
    }
    
    try:
        # Parse the HTML content
        soup = BeautifulSoup(response_content, 'html.parser')
        
        # Common defacement markers/keywords
        defacement_keywords = [
            'hacked by', 'owned by', 'pwned by', 'h4ck3d', 'defaced', 
            'security breached', 'was here', 'cyber army', 'cyber team',
            'cyber caliphate', 'cyber soldiers', 'anonymous', 'legion',
            'security broken', 'r00t', 'hacktivist', 'owned'
        ]
        
        # Check for defacement markers in the page title
        title = soup.title.text.lower() if soup.title else ''
        for keyword in defacement_keywords:
            if keyword in title:
                result['defaced'] = True
                result['confidence'] = 90
                result['evidence'] = f"Title contains defacement marker: '{keyword}'"
                result['defacement_text'] = soup.title.text
                break
        
        # Check for defacement markers in headers (h1, h2, h3)
        if not result['defaced']:
            for header_tag in soup.find_all(['h1', 'h2', 'h3']):
                header_text = header_tag.text.lower()
                for keyword in defacement_keywords:
                    if keyword in header_text:
                        result['defaced'] = True
                        result['confidence'] = 85
                        result['evidence'] = f"Header contains defacement marker: '{keyword}'"
                        result['defacement_text'] = header_tag.text
                        break
                if result['defaced']:
                    break
        
        # Check for defacement images or background images
        if not result['defaced']:
            # Common defacement image names
            defacement_image_keywords = [
                'hacked', 'owned', 'pwned', 'defaced', 'anonymous', 'skull', 
                'hack', 'security', 'breach', 'cyber', 'legion', 'army'
            ]
            
            for img in soup.find_all('img'):
                img_src = img.get('src', '').lower()
                img_alt = img.get('alt', '').lower()
                
                for keyword in defacement_image_keywords:
                    if keyword in img_src or keyword in img_alt:
                        result['defaced'] = True
                        result['confidence'] = 75
                        result['evidence'] = f"Image with defacement marker: '{keyword}'"
                        result['defacement_text'] = f"Image: {img_src}"
                        break
                if result['defaced']:
                    break
        
        # Check for suspicious content modifications
        if not result['defaced']:
            body_text = soup.body.text.lower() if soup.body else ''
            for keyword in defacement_keywords:
                if keyword in body_text:
                    # Extract surrounding context (up to 100 chars)
                    index = body_text.find(keyword)
                    start = max(0, index - 50)
                    end = min(len(body_text), index + len(keyword) + 50)
                    context = body_text[start:end]
                    
                    result['defaced'] = True
                    result['confidence'] = 70
                    result['evidence'] = f"Body text contains defacement marker: '{keyword}'"
                    result['defacement_text'] = context.strip()
                    break
        
    except Exception as e:
        result['evidence'] = f"Error detecting defacement: {str(e)}"
    
    return result

def detect_phishing(url, response_content):
    """
    Detect if a website is a phishing page by looking for common phishing indicators
    Returns a dict with detection results
    """
    result = {
        'is_phishing': False,
        'confidence': 0,
        'evidence': None,
        'phishing_target': None
    }
    
    try:
        # Parse the URL and content
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        soup = BeautifulSoup(response_content, 'html.parser')
        
        # Extract the base domain (without subdomains)
        extracted = tldextract.extract(domain)
        base_domain = f"{extracted.domain}.{extracted.suffix}"
        
        # Dictionary of legitimate domains for common services
        legitimate_domains = {
            'google': ['google.com', 'accounts.google.com', 'mail.google.com', 'gmail.com'],
            'microsoft': ['microsoft.com', 'login.microsoftonline.com', 'outlook.com', 'office.com', 'live.com'],
            'apple': ['apple.com', 'icloud.com', 'appleid.apple.com'],
            'paypal': ['paypal.com', 'paypal.me'],
            'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 'amazon.fr', 'amazon.in'],
            'facebook': ['facebook.com', 'fb.com', 'messenger.com'],
            'instagram': ['instagram.com'],
            'discord': ['discord.com', 'discord.gg', 'discordapp.com'],
            'netflix': ['netflix.com'],
            'bank': []  # Will be handled differently
        }
        
        # Keywords that might indicate a login page for each service
        login_keywords = {
            'google': ['gmail', 'google account', 'google login', 'sign in with google'],
            'microsoft': ['microsoft account', 'outlook', 'office365', 'onedrive', 'sign in with microsoft'],
            'apple': ['apple id', 'icloud', 'sign in with apple'],
            'paypal': ['paypal'],
            'amazon': ['amazon', 'aws'],
            'facebook': ['facebook', 'fb login', 'sign in with facebook'],
            'instagram': ['instagram'],
            'discord': ['discord'],
            'netflix': ['netflix'],
            'bank': ['bank', 'banking', 'credit union', 'account access']
        }
        
        # Check if we're on a legitimate domain for any service
        current_service = None
        for service, domains in legitimate_domains.items():
            # Check if we're on a legitimate domain
            if any(domain.endswith(d) for d in domains):
                # This is a legitimate domain for this service
                current_service = service
                break
                
        # If we're already on a legitimate domain, it's not phishing
        if current_service:
            return result
            
        # Check for login forms that don't match the domain
        forms = soup.find_all('form')
        for form in forms:
            # Check if it looks like a login form
            input_types = [input_tag.get('type', '').lower() for input_tag in form.find_all('input')]
            if 'password' in input_types:
                # It's a login form, check for mismatches with domain
                form_text = form.text.lower()
                
                # Check for each service's keywords
                for service, keywords in login_keywords.items():
                    # Skip if we're on a legitimate domain for this service
                    if service == current_service:
                        continue
                        
                    # Check if form contains keywords for a different service
                    if any(keyword in form_text for keyword in keywords):
                        # Found keywords for a service on an unrelated domain
                        result['is_phishing'] = True
                        result['confidence'] = 85
                        result['evidence'] = f"Login form for {service} found on unrelated domain"
                        result['phishing_target'] = service
                        return result
        
        # Check for misleading domain names (typosquatting)
        for service, domains in legitimate_domains.items():
            if not domains:  # Skip if no domains listed
                continue
                
            for legit_domain in domains:
                # Extract the base domain without TLD
                extracted = tldextract.extract(legit_domain)
                legit_base = extracted.domain
                
                # Check for typosquatting
                if legit_base in base_domain and base_domain != legit_domain:
                    # Potential typosquatting
                    edit_distance = levenshtein_distance(base_domain, legit_domain)
                    if edit_distance <= 3:  # Close enough to be suspicious
                        result['is_phishing'] = True
                        result['confidence'] = 80
                        result['evidence'] = f"Domain appears to be typosquatting {legit_domain} (edit distance: {edit_distance})"
                        result['phishing_target'] = service
                        return result
        
        # Check for suspicious page titles
        title = soup.title.text.lower() if soup.title else ''
        for service, keywords in login_keywords.items():
            # Skip if we're on a legitimate domain for this service
            if service == current_service:
                continue
                
            # Check if title contains keywords for a different service
            if any(keyword in title for keyword in keywords):
                # Check if we're definitely not on a legitimate domain
                if not any(domain.endswith(d) for d in legitimate_domains.get(service, [])):
                    result['is_phishing'] = True
                    result['confidence'] = 75
                    result['evidence'] = f"Page title suggests {service} content on unrelated domain"
                    result['phishing_target'] = service
                    return result
        
        # Check for suspicious links or redirects
        suspicious_links_count = 0
        total_links = 0
        
        for link in soup.find_all('a', href=True):
            href = link.get('href', '').lower()
            if not href.startswith(('http://', 'https://', '/')):
                continue
                
            total_links += 1
            link_domain = urlparse(href).netloc if href.startswith(('http://', 'https://')) else domain
            
            # Check if link points to a legitimate domain
            for service, domains in legitimate_domains.items():
                if not domains:  # Skip if no domains listed
                    continue
                    
                # Check if link points to a legitimate domain but we're not on one
                if any(link_domain.endswith(d) for d in domains) and not current_service:
                    suspicious_links_count += 1
                    
                    # If we find multiple suspicious links, it's more likely to be phishing
                    if suspicious_links_count >= 3 and suspicious_links_count > total_links * 0.3:
                        result['is_phishing'] = True
                        result['confidence'] = 65
                        result['evidence'] = f"Page contains multiple links to {service} while pretending to be something else"
                        result['phishing_target'] = service
                        return result
        
    except Exception as e:
        result['evidence'] = f"Error detecting phishing: {str(e)}"
    
    return result

# Helper function for calculating string edit distance
def levenshtein_distance(s1, s2):
    """
    Calculate the Levenshtein distance between two strings
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def detect_malicious_content(url, response_content):
    """
    Detect potentially malicious content like malware, unwanted scripts, etc.
    Returns a dict with detection results
    """
    result = {
        'is_malicious': False,
        'confidence': 0,
        'evidence': None,
        'malicious_type': None,
        'malicious_content': None
    }
    
    try:
        # Parse the URL and content
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        soup = BeautifulSoup(response_content, 'html.parser')
        
        # Extract the base domain (without subdomains)
        extracted = tldextract.extract(domain)
        base_domain = f"{extracted.domain}.{extracted.suffix}"
        
        # List of trusted domains that commonly use obfuscated code legitimately
        trusted_domains = [
            'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'youtube.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'netflix.com',
            'discord.com', 'twitch.tv', 'github.com', 'stackoverflow.com', 'cloudflare.com',
            'akamai.com', 'adobe.com', 'shopify.com', 'wordpress.com', 'wix.com',
            'squarespace.com', 'salesforce.com', 'zoom.us', 'slack.com', 'dropbox.com',
            'paypal.com', 'ebay.com', 'yahoo.com', 'bing.com', 'office.com',
            'spotify.com', 'reddit.com', 'quora.com', 'medium.com', 'imgur.com',
            'cnn.com', 'nytimes.com', 'bbc.com', 'wsj.com', 'forbes.com',
            'walmart.com', 'target.com', 'bestbuy.com', 'etsy.com', 'aliexpress.com',
            'booking.com', 'airbnb.com', 'uber.com', 'lyft.com', 'doordash.com'
        ]
        
        # Check if we're on a trusted domain
        is_trusted_domain = any(domain.endswith(trusted) for trusted in trusted_domains)
        
        # Counters for suspicious elements
        suspicious_elements = 0
        malicious_indicators = 0
        
        # Check for obfuscated JavaScript
        scripts = soup.find_all('script')
        obfuscated_scripts = []
        
        for script in scripts:
            script_content = script.string if script.string else ''
            
            # Skip empty scripts or very short scripts
            if not script_content or len(script_content) < 100:
                continue
            
            # Check for common obfuscation patterns
            obfuscation_score = 0
            
            # Check for packed JS (often used by legitimate sites too)
            if re.search(r'eval\(\s*function\(p,a,c,k,e,[rd]', script_content):
                obfuscation_score += 1
            
            # Check for hex encoding (can be legitimate)
            if re.search(r'\\x[0-9a-fA-F]{2}', script_content):
                obfuscation_score += 1
            
            # Check for character code arrays (can be legitimate)
            if re.search(r'fromCharCode', script_content) and re.search(r'\d{2,3},\d{2,3},\d{2,3}', script_content):
                obfuscation_score += 1
            
            # Check for base64 (often used legitimately)
            if re.search(r'atob\s*\(', script_content):
                obfuscation_score += 1
            
            # Only consider it suspicious if multiple obfuscation techniques are used
            # or if it's not a trusted domain
            if obfuscation_score >= 2 and not is_trusted_domain:
                suspicious_elements += 1
                obfuscated_scripts.append(script_content)
            # For trusted domains, we need stronger evidence
            elif obfuscation_score >= 3 and is_trusted_domain:
                suspicious_elements += 1
                obfuscated_scripts.append(script_content)
        
        # Check for more definitively malicious patterns
        malicious_patterns = [
            # Cookie stealing
            (r'document\.cookie\s*=.*?;.*?location\s*=', 10, "Cookie stealing and redirect"),
            # Data exfiltration
            (r'new\s+Image\(\)\.src\s*=.*?\+\s*document\.cookie', 10, "Cookie exfiltration via image"),
            # Immediate redirects
            (r'<script>[^<]{0,10}(location|window\.location|self\.location|top\.location)\s*=', 8, "Immediate page redirect"),
            # Suspicious eval with encoded content
            (r'eval\(atob\(', 7, "Eval with base64 encoded content"),
            # Suspicious document writes with encoded content
            (r'document\.write\s*\(\s*unescape\s*\(\s*[\'"][%0-9a-fA-F]+', 7, "Document write with escaped content"),
            # Suspicious iframe creation
            (r'createElement\([\'"]iframe[\'"]\).*?style\.display\s*=\s*[\'"]none[\'"]', 9, "Hidden iframe creation"),
            # Suspicious local storage access with eval
            (r'localStorage\.getItem.*?eval\(', 8, "Eval of localStorage content"),
            # Crypto miners
            (r'coinhive|cryptonight|webminepool|cryptoloot|webmine.pro', 9, "Potential crypto miner"),
            # Unicode obfuscation that's more complex
            (r'\\u00[0-9a-fA-F]{2}\\u00[0-9a-fA-F]{2}\\u00[0-9a-fA-F]{2}\\u00[0-9a-fA-F]{2}', 6, "Complex unicode obfuscation")
        ]
        
        for pattern, score, description in malicious_patterns:
            matches = re.findall(pattern, response_content)
            if matches:
                malicious_indicators += 1
                # If we find a high-score pattern, mark as malicious immediately
                if score >= 9:
                    result['is_malicious'] = True
                    result['confidence'] = 85
                    result['evidence'] = f"Detected {description}"
                    result['malicious_type'] = "Malicious Code"
                    result['malicious_content'] = matches[0][:150] + ('...' if len(matches[0]) > 150 else '')
                    return result
        
        # Check for hidden iframes (more reliable indicator)
        hidden_iframes = []
        for iframe in soup.find_all('iframe'):
            width = iframe.get('width', '')
            height = iframe.get('height', '')
            style = iframe.get('style', '')
            
            # Check if iframe is hidden
            if (width == '0' or height == '0' or 
                'display:none' in style or 'visibility:hidden' in style or
                'opacity:0' in style):
                
                # Check if it's not a common legitimate use case
                src = iframe.get('src', '')
                if not src or not any(trusted in src for trusted in trusted_domains):
                    hidden_iframes.append(iframe)
                    malicious_indicators += 1
        
        if hidden_iframes and malicious_indicators >= 2:
            result['is_malicious'] = True
            result['confidence'] = 80
            result['evidence'] = "Hidden iframe detected"
            result['malicious_type'] = "Hidden Element"
            result['malicious_content'] = str(hidden_iframes[0])
            return result
        
        # Check for suspicious redirects
        suspicious_redirects = []
        meta_refresh = soup.find('meta', {'http-equiv': 'refresh'})
        if meta_refresh:
            content = meta_refresh.get('content', '')
            if ';url=' in content:
                redirect_url = content.split(';url=')[1]
                parsed_redirect = urlparse(redirect_url)
                
                # Check if redirect is to a different domain
                if parsed_redirect.netloc and parsed_redirect.netloc != parsed_url.netloc:
                    suspicious_redirects.append(meta_refresh)
                    malicious_indicators += 1
        
        # Make final determination based on combined evidence
        if suspicious_elements >= 3 and malicious_indicators >= 2 and not is_trusted_domain:
            result['is_malicious'] = True
            result['confidence'] = 75
            result['evidence'] = "Multiple suspicious elements detected"
            result['malicious_type'] = "Suspicious Code"
            result['malicious_content'] = obfuscated_scripts[0][:150] + ('...' if len(obfuscated_scripts[0]) > 150 else '')
        elif suspicious_elements >= 4 and malicious_indicators >= 3:
            # Even trusted domains can be compromised
            result['is_malicious'] = True
            result['confidence'] = 70
            result['evidence'] = "Multiple suspicious elements detected on trusted domain"
            result['malicious_type'] = "Potential Compromise"
            result['malicious_content'] = obfuscated_scripts[0][:150] + ('...' if len(obfuscated_scripts[0]) > 150 else '')
        
    except Exception as e:
        result['evidence'] = f"Error detecting malicious content: {str(e)}"
    
    return result


def analyze_content(url):
    """Analyze page content for trackers and suspicious elements"""
    trackers = []
    warnings = []
    
    try:
        response = requests.get(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }, timeout=10, verify=False)
        
        if response.status_code != 200:
            warnings.append(f"HTTP error: Status code {response.status_code}")
            return trackers, warnings
        
        # Parse HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Look for common trackers in script tags
        script_tags = soup.find_all('script')
        for script in script_tags:
            script_src = script.get('src', '')
            script_content = script.string if script.string else ''
            
            # Check for common analytics and tracking services
            if any(tracker in script_src.lower() for tracker in ['google-analytics', 'googletagmanager', 'analytics', 'tracking']):
                trackers.append({
                    'name': 'Google Analytics' if 'google' in script_src.lower() else 'Analytics Script',
                    'type': 'Analytics',
                    'url': script_src
                })
            
            if any(tracker in script_src.lower() for tracker in ['facebook', 'fbevents', 'fb-pixel']):
                trackers.append({
                    'name': 'Facebook Pixel',
                    'type': 'Social Media Tracking',
                    'url': script_src
                })
                
            # Check for other common trackers
            if any(tracker in script_src.lower() for tracker in ['hotjar', 'mixpanel', 'amplitude', 'segment']):
                trackers.append({
                    'name': script_src.split('/')[-1].split('.')[0].capitalize(),
                    'type': 'User Behavior Analytics',
                    'url': script_src
                })
                
            # Check for ad networks
            if any(tracker in script_src.lower() for tracker in ['doubleclick', 'adsense', 'adroll', 'taboola']):
                trackers.append({
                    'name': script_src.split('/')[-1].split('.')[0].capitalize(),
                    'type': 'Ad Network',
                    'url': script_src
                })
            
            # Check for obfuscated JavaScript
            # if script_content and len(script_content) > 100:
            #     if re.search(r'eval\(.*\)', script_content) or re.search(r'\\x[0-9a-fA-F]{2}', script_content):
            #         warnings.append("Potentially obfuscated JavaScript detected")
                    
        # Check for suspicious redirects
        meta_refresh = soup.find('meta', {'http-equiv': 'refresh'})
        if meta_refresh:
            content = meta_refresh.get('content', '')
            if ';url=' in content:
                redirect_url = content.split(';url=')[1]
                warnings.append(f"Meta refresh redirect detected to: {redirect_url}")
        
        # Check for iframe usage
        iframes = soup.find_all('iframe')
        if len(iframes) > 0:
            for iframe in iframes:
                iframe_src = iframe.get('src', '')
                if iframe_src and not iframe_src.startswith(('https://www.google.com', 'https://www.youtube.com')):
                    warnings.append(f"Third-party iframe detected: {iframe_src}")
        
        return trackers, warnings
        
    except Exception as e:
        warnings.append(f"Error analyzing content: {str(e)}")
        return trackers, warnings

def analyze_url(url, url_check):
    """Analyze a URL for safety and security issues"""
    # Extract domain from URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    if not domain:
        domain = url.split('/')[0].lower()
    
    # Check if domain is valid
    is_valid, validation_message = is_valid_domain(domain)
    
    # Initialize warnings list here at the top
    warning_list = []  # Use a different name to avoid conflicts
    
    # Start with a base safety rating
    safety_rating = 50  # Initialize safety_rating here
    
    # Initialize results dictionary
    results = {
        'url': url,
        'final_url': url,
        'domain': domain,
        'is_valid_domain': is_valid,
        'validation_message': validation_message,
        'safety_rating': safety_rating,
        'warnings': warning_list,  # Use the initialized list
        'redirect_chain': [],
        'ssl_valid': False,
        'domain_age_days': None,
        'domain_info': None,
        'trackers': [],
        'ip_info': None,
        'hosting_info': None,
        'discovered_content': None,
        'defacement_info': None,
        'phishing_info': None,
        'malicious_info': None,
        'is_shortened': url_check.is_shortened
    }
    
    # If domain is not valid, return limited results
    if not is_valid:
        results['safety_rating'] = 0
        warning_list.append(f"Invalid domain: {validation_message}")
        results['comments'] = f"This URL contains an invalid or unreachable domain. The domain '{domain}' could not be resolved."
        return results
    
    # Resolve domain to IP address
    ip_info = resolve_domain_to_ip(domain)
    results['ip_info'] = ip_info
    
    # If IP resolution failed, add warning but continue analysis
    if ip_info.get('error'):
        warning_list.append(f"IP resolution issue: {ip_info.get('error')}")
    
    # Get hosting provider and server information
    hosting_info = get_hosting_info(url)
    results['hosting_info'] = hosting_info
    
    # If hosting info resolution failed, add warning but continue analysis
    if hosting_info.get('error'):
        warning_list.append(f"Hosting info issue: {hosting_info.get('error')}")
    
    # Fetch the page content for analysis
    page_content = None
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        response = requests.get(url, headers=headers, timeout=15, verify=False)
        page_content = response.text
    except Exception as e:
        warning_list.append(f"Error fetching page content: {str(e)}")
    
    # If we have page content, perform security checks
    if page_content:
        # Detect website defacement
        defacement_info = detect_defacement(url, page_content)
        results['defacement_info'] = defacement_info
        
        if defacement_info['defaced']:
            warning_list.append(f"Website appears to be defaced ({defacement_info['confidence']}% confidence): {defacement_info['evidence']}")
            # Defacement is a serious security issue, reduce safety rating
            safety_rating -= 30
        
        # Detect phishing with improved accuracy
        phishing_info = detect_phishing(url, page_content)
        results['phishing_info'] = phishing_info
        
        if phishing_info['is_phishing']:
            warning_list.append(f"Website appears to be a phishing page ({phishing_info['confidence']}% confidence): {phishing_info['evidence']}")
            # Phishing is a serious security issue, reduce safety rating
            safety_rating -= 40
            
            # If high confidence phishing, mark as malicious
            if phishing_info['confidence'] >= 80:
                url_check.is_malicious = True
                url_check.save()
            
        # Detect other malicious content
        malicious_info = detect_malicious_content(url, page_content)
        results['malicious_info'] = malicious_info

        if malicious_info['is_malicious']:
            # For high confidence detections, add a warning and reduce safety rating
            if malicious_info['confidence'] >= 75:
                warning_list.append(f"Website contains potentially malicious content ({malicious_info['confidence']}% confidence): {malicious_info['evidence']}")
                safety_rating -= 35
                
                # If high confidence malicious, mark as malicious
                if malicious_info['confidence'] >= 80:
                    url_check.is_malicious = True
                    url_check.save()
            # For lower confidence detections, just add a softer warning
            else:
                warning_list.append(f"Website contains suspicious code that might be malicious ({malicious_info['confidence']}% confidence)")
                safety_rating -= 15
            
    # Follow redirects if necessary
    try:
        final_url, redirect_chain = follow_redirects(url)
        results['final_url'] = final_url
        results['redirect_chain'] = redirect_chain
        
        # Check if there's a redirect
        if len(redirect_chain) > 1:
            # Extract final domain
            final_domain = urlparse(final_url).netloc.lower()
            if not final_domain:
                final_domain = final_url.split('/')[0].lower()
            
            # Update URL check with final URL
            url_check.final_url = final_url
            url_check.save()
            
            # Store redirect chain in database
            for i, redirect in enumerate(redirect_chain):
                URLRedirect.objects.create(
                    url_check=url_check,
                    redirect_url=redirect.get('url', ''),
                    status_code=redirect.get('status_code'),
                    order=i
                )
            
            # Check if many redirects (potential redirect chain attack)
            if len(redirect_chain) > 4:
                warning_list.append(f"Long redirect chain ({len(redirect_chain)} redirects)")
                safety_rating -= 10
            
            # Check if redirect to a different domain
            if final_domain != domain:
                warning_list.append(f"Redirects to a different domain: {final_domain}")
                safety_rating -= 5
            
            # Double-check if this is a shortlink based on redirection
            # Get fresh list of URL shorteners
            shorteners = fetch_url_shorteners()
            
            if domain in shorteners:
                # For URL shorteners, this is expected behavior
                if not url_check.is_shortened:
                    url_check.is_shortened = True
                    url_check.save()
                results['is_shortened'] = True
                
                # Don't penalize for redirects from known shorteners
                safety_rating += 5
                
                # Check the reputation of the final domain instead
                domain = final_domain
        
    except Exception as e:
        warning_list.append(f"Error following redirects: {str(e)}")
    
    # Check SSL certificate
    ssl_info = check_ssl_certificate(domain)
    results['ssl_valid'] = ssl_info.get('valid', False)
    
    if ssl_info.get('valid', False):
        safety_rating += 15
        
        # Check if certificate is about to expire
        if ssl_info.get('expiry_days', 0) < 30:
            warning_list.append(f"SSL certificate expires soon ({ssl_info.get('expiry_days', 0)} days)")
            safety_rating -= 5
    else:
        warning_list.append("Website does not use a valid SSL certificate")
        safety_rating -= 15
    
    # Get domain age and registration info
    domain_age_days, domain_info = get_domain_info(domain)
    results['domain_age_days'] = domain_age_days
    results['domain_info'] = domain_info
    
    # Domain age affects trustworthiness
    if domain_age_days:
        if domain_age_days < 30:
            warning_list.append("Domain was registered recently (less than 30 days ago)")
            safety_rating -= 15
        elif domain_age_days < 90:
            warning_list.append("Domain is relatively new (less than 3 months old)")
            safety_rating -= 5
        elif domain_age_days > 365:
            # Boost for well-established domains
            safety_rating += 10
    
    # Check content for trackers and suspicious elements
    try:
        trackers, content_warnings = analyze_content(results['final_url'])
        
        # Store trackers in results
        results['trackers'] = trackers
        
        # Store trackers in database
        for tracker in trackers:
            TrackerDetection.objects.create(
                url_check=url_check,
                tracker_name=tracker.get('name', 'Unknown'),
                tracker_type=tracker.get('type', 'Unknown'),
                tracker_url=tracker.get('url', '')
            )
        
        # Add content warnings to overall warnings
        warning_list.extend(content_warnings)
        
        # Excessive trackers might indicate privacy concerns
        if len(trackers) > 10:
            warning_list.append(f"Excessive number of tracking scripts detected ({len(trackers)})")
            safety_rating -= 5
    except Exception as e:
        warning_list.append(f"Error analyzing page content: {str(e)}")
    
    # Discover page content (links, scripts, iframes)
    try:
        # Use final URL for content discovery
        discovered_content = discover_page_content(results['final_url'])
        results['discovered_content'] = discovered_content
        
        # Add warning if there was an error during discovery
        if discovered_content.get('error'):
            warning_list.append(discovered_content.get('error'))
    except Exception as e:
        warning_list.append(f"Error discovering page content: {str(e)}")
    
    # Update warnings in results
    results['warnings'] = warning_list
    
    # Calculate final safety rating (ensure between 0-100)
    results['safety_rating'] = max(0, min(100, safety_rating))
    
    # Generate analysis comments
    if results['safety_rating'] >= 80:
        results['comments'] = "This URL appears to be safe."
    elif results['safety_rating'] >= 60:
        results['comments'] = "This URL has some minor issues but appears mostly safe."
    elif results['safety_rating'] >= 40:
        results['comments'] = "This URL has several security concerns. Proceed with caution."
    else:
        results['comments'] = "This URL appears to be unsafe or potentially malicious. We recommend avoiding this site."
    
    return results

def validate_url(request):
    """Process and validate a URL"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    url = request.POST.get('url', '').strip()

    if not url:
        return JsonResponse({'error': 'Please enter a URL'}, status=400)
    
    # Ensure URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    # Check scan limit
    limit_check = ScanLimiter.check_limit(request, 'url')
    if not limit_check[0]:
        return JsonResponse({
            'error': limit_check[1],
            'remaining': limit_check[2]
        }, status=429)
    
    # Extract domain using tldextract for better accuracy
    try:
        extracted = tldextract.extract(url)
        if not extracted.domain:
            return JsonResponse({
                'success': True,
                'url': url,
                'domain': url,
                'is_valid_domain': False,
                'validation_message': 'Invalid URL format',
                'safety_rating': 0,
                'status': 'Invalid Domain',
                'ssl_valid': False,
                'domain_age': 'Unknown',
                'warnings': ['Invalid URL format - Could not extract domain'],
                'comments': 'This URL contains an invalid domain format.'
            })
    except Exception as e:
        return JsonResponse({
            'success': True,
            'url': url,
            'domain': url,
            'is_valid_domain': False,
            'validation_message': f'Error processing URL: {str(e)}',
            'safety_rating': 0,
            'status': 'Invalid Domain',
            'ssl_valid': False,
            'domain_age': 'Unknown',
            'warnings': [f'Error processing URL: {str(e)}'],
            'comments': 'This URL could not be processed due to an error.'
        })
    
    domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    
    # Get shorteners using memory cache
    shorteners = fetch_url_shorteners()
    
    is_shortlink = domain in shorteners
    
    # Start URL checking process
    try:
        # Create URLCheck record
        user_email = request.session.get('user_email')
        user_id = None
        if user_email:
            from accounts.models import User
            try:
                user = User.objects.get(email=user_email)
                user_id = user.user_id
            except User.DoesNotExist:
                pass

        url_check = URLCheck.objects.create(
            url=url,
            domain=domain,
            is_shortened=is_shortlink,  
            user_id=user_id
        )
        
        # Perform comprehensive URL analysis
        results = analyze_url(url, url_check)
        
        # Process dates in domain_info
        if 'domain_info' in results and results['domain_info']:
            for key, value in results['domain_info'].items():
                if isinstance(value, datetime):
                    results['domain_info'][key] = json_serialize_helper(value)
        
        # Create URL check result with updated data
        check_result = URLCheckResult.objects.create(
            url_check=url_check,
            safety_rating=results['safety_rating'],
            ssl_info={'valid': results.get('ssl_valid', False)},
            domain_age_days=results.get('domain_age_days'),
            domain_info=results.get('domain_info'),
            comments=results.get('comments'),
            warnings=results.get('warnings', []),
            ip_info=results.get('ip_info'),
            hosting_info=results.get('hosting_info'),
            discovered_content=results.get('discovered_content')
        )
        
        # Format domain age for display
        domain_age_display = "Unknown"
        if results.get('domain_age_days'):
            years = results['domain_age_days'] // 365
            months = (results['domain_age_days'] % 365) // 30
            days = results['domain_age_days'] % 30
            
            if years > 0:
                domain_age_display = f"{years} year{'s' if years != 1 else ''}"
                if months > 0:
                    domain_age_display += f", {months} month{'s' if months != 1 else ''}"
            elif months > 0:
                domain_age_display = f"{months} month{'s' if months != 1 else ''}"
                if days > 0 and months < 6:  # Only show days for domains less than 6 months old
                    domain_age_display += f", {days} day{'s' if days != 1 else ''}"
            else:
                domain_age_display = f"{results['domain_age_days']} day{'s' if results['domain_age_days'] != 1 else ''}"
            
            # Add indicator if this was an estimate
            if results.get('domain_info') and results['domain_info'].get('note') and 'estimate' in results['domain_info'].get('note').lower():
                domain_age_display += " (estimated)"

        # Define status_text based on safety rating
        if not results.get('is_valid_domain', False):
            status_text = "Invalid Domain"
        else:
            if results['safety_rating'] >= 80:
                status_text = "Safe"
            elif results['safety_rating'] >= 60:
                status_text = "Mostly Safe"
            elif results['safety_rating'] >= 40:
                status_text = "Exercise Caution"
            else:
                status_text = "Potentially Unsafe"

        # Check if URL is actually redirecting
        is_redirecting = False
        if results.get('redirect_chain') and len(results.get('redirect_chain')) > 1:
            original_parsed = urlparse(url)
            final_parsed = urlparse(results.get('final_url', url))
            
            original_domain = original_parsed.netloc.replace('www.', '')
            final_domain = final_parsed.netloc.replace('www.', '')
            
            original_path = original_parsed.path.rstrip('/')
            final_path = final_parsed.path.rstrip('/')
            
            if original_domain != final_domain or original_path != final_path:
                is_redirecting = True

        response_data = {
            'success': True,
            'url_id': url_check.id,
            'url': url,
            'domain': domain,
            'is_valid_domain': results.get('is_valid_domain', False),
            'validation_message': results.get('validation_message', ''),
            'safety_rating': results['safety_rating'],
            'status': status_text,
            'ssl_valid': results.get('ssl_valid', False),
            'domain_age': domain_age_display,
            'trackers_count': len(results.get('trackers', [])),
            'warnings': results.get('warnings', []),
            'tracker_summary': summarize_trackers(results.get('trackers', [])),
            'comments': results.get('comments'),
            'is_shortened': url_check.is_shortened,  # Make sure to include this
            'ip_address': results.get('ip_info', {}).get('primary_ip', 'Unknown'),
            'ip_range': results.get('ip_info', {}).get('ip_range', {}).get('cidr', 'Unknown'),
            'hosting_provider': results.get('hosting_info', {}).get('provider', 'Unknown'),
            'server': results.get('hosting_info', {}).get('server', 'Unknown'),
            'discovered_content': results.get('discovered_content', {}),
            'defacement_info': results.get('defacement_info', {'defaced': False, 'confidence': 0, 'evidence': None, 'defacement_text': None}),
            'phishing_info': results.get('phishing_info', {'is_phishing': False, 'confidence': 0, 'evidence': None, 'phishing_target': None}),
            'malicious_info': results.get('malicious_info', {'is_malicious': False, 'confidence': 0, 'evidence': None, 'malicious_type': None, 'malicious_content': None})
        }

        # Only add redirect info if needed
        if results.get('is_shortened') or is_redirecting:
            response_data['final_url'] = results.get('final_url', url)
            response_data['redirects'] = results.get('redirect_chain', [])
        
        return JsonResponse(response_data)
        
    except Exception as e:
        import traceback
        
        # Return structured error response instead of raw error
        return JsonResponse({
            'success': True,
            'url': url,
            'domain': domain,
            'is_valid_domain': False,
            'validation_message': 'Error processing URL',
            'safety_rating': 0,
            'status': 'Invalid Domain',
            'ssl_valid': False,
            'domain_age': 'Unknown',
            'warnings': [f'Error analyzing URL: The domain could not be validated.'],
            'comments': 'This URL could not be processed. It may contain an invalid domain or the server may be unreachable.',
            'trackers_count': 0,
            'tracker_summary': []
        })

def summarize_trackers(trackers):
    """Summarize tracker types for display"""
    summary = []
    tracker_types = {}
    
    for tracker in trackers:
        tracker_type = tracker.get('type', 'Unknown')
        if tracker_type in tracker_types:
            tracker_types[tracker_type] += 1
        else:
            tracker_types[tracker_type] = 1
    
    for tracker_type, count in tracker_types.items():
        summary.append(f"{tracker_type} ({count})")
    
    return summary

def generate_pdf_report(request):
    """Generate a PDF report of a URL scan"""
    url_id = request.GET.get('url_id')
    
    try:
        url_check = URLCheck.objects.get(id=url_id)
        
        # Get the scan results and related data
        result = URLCheckResult.objects.get(url_check=url_check)
        redirects = URLRedirect.objects.filter(url_check=url_check).order_by('order')
        trackers = TrackerDetection.objects.filter(url_check=url_check)
        
        comments_data = {}
        if result.comments:
            try:
                if result.comments.strip():
                    comments_data = json.loads(result.comments)
            except json.JSONDecodeError:
                print(f"Warning: Invalid JSON in comments for URL check {url_id}")
        
        # Prepare the report data
        domain = urlparse(url_check.url).netloc or url_check.url.split('/')[0]
        
        # Check if domain is valid
        is_valid, validation_message = is_valid_domain(domain)
        
        # Get final URL from redirects or use original
        final_url = url_check.url
        if redirects and redirects.count() > 0:
            final_url = redirects.last().redirect_url
        
        # Create the report data with safety checks for all fields
        report_data = {
            'url': url_check.url,
            'domain': domain,
            'is_valid_domain': is_valid,
            'scan_date': url_check.timestamp.strftime('%B %d, %Y at %H:%M:%S'),
            'safety_rating': getattr(result, 'safety_rating', 0),
            'final_url': final_url,
            'is_shortlink': url_check.is_shortened,  
            'ssl_valid': comments_data.get('ssl_valid', False),
            'domain_age': result.domain_info.get('age', 'Unknown') if result.domain_info else 'Unknown',
            'domain_info': result.domain_info if result.domain_info else {},
            'ip_info': result.ip_info if hasattr(result, 'ip_info') and result.ip_info else {'primary_ip': 'Unknown', 'all_ips': [], 'ip_range': {'cidr': 'Unknown'}},
            'warnings': result.warnings if hasattr(result, 'warnings') and result.warnings else [],
            'hosting_info': result.hosting_info if hasattr(result, 'hosting_info') and result.hosting_info else {'provider': 'Unknown', 'server': 'Unknown'},
            'discovered_content': result.discovered_content if hasattr(result, 'discovered_content') and result.discovered_content else {
            'links': [],
            'scripts': [],
            'iframes': [],
            'embedded_objects': []
            }
        }
        
        # Prepare the template context
        context = {
            'report': report_data,
            'redirects': redirects,
            'trackers': trackers,
            'generated_date': datetime.now().strftime('%B %d, %Y at %H:%M:%S')
        }
        
        # Create the PDF response
        template = get_template('services/url_report_pdf.html')
        html = template.render(context)
        result_file = BytesIO()
        pdf = pisa.pisaDocument(BytesIO(html.encode("UTF-8")), result_file)
        
        if not pdf.err:
            # Create response with PDF content
            response = HttpResponse(result_file.getvalue(), content_type='application/pdf')
            
            # Generate a filename based on the domain and current date
            date_str = datetime.now().strftime('%Y%m%d')
            filename = f"VAST_URL_Report_{domain.replace('.', '_')}_{date_str}.pdf"
            
            # Add Content-Disposition header to force download
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            
            return response
        
        return HttpResponse('Error generating PDF report', status=500)
        
    except URLCheck.DoesNotExist:
        return HttpResponse('URL scan not found', status=404)
    except Exception as e:
        import traceback
        return HttpResponse(f'Error generating report: {str(e)}', status=500)