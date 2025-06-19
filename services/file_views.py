import os
import io
import re
import hashlib
import magic
import json
import uuid
import time
import zipfile
import tarfile
import rarfile
import olefile
import exifread
import PyPDF2
import requests
import datetime
import tempfile
import subprocess
import threading
import concurrent.futures
import struct
import math
import pefile
from PIL import Image
from io import BytesIO
from pathlib import Path

from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.template.loader import get_template
from django.utils import timezone
from django.conf import settings
from xhtml2pdf import pisa
import base64

from .models import FileCheck, FileCheckResult, FileScanMetadata
from .scan_limiter import ScanLimiter

# Global variables
HASH_ALGORITHMS = ["md5", "sha1", "sha256"]
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB max file size
ALLOWED_FILE_TYPES = {
    # Documents
    'application/pdf': {'extension': '.pdf', 'category': 'document'},
    'application/msword': {'extension': '.doc', 'category': 'document'},
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': {'extension': '.docx', 'category': 'document'},
    'application/vnd.ms-excel': {'extension': '.xls', 'category': 'document'},
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': {'extension': '.xlsx', 'category': 'document'},
    'application/vnd.ms-powerpoint': {'extension': '.ppt', 'category': 'document'},
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': {'extension': '.pptx', 'category': 'document'},
    'text/plain': {'extension': '.txt', 'category': 'document'},
    'text/csv': {'extension': '.csv', 'category': 'document'},
    'text/html': {'extension': '.html', 'category': 'document'},
    'text/xml': {'extension': '.xml', 'category': 'document'},
    'application/json': {'extension': '.json', 'category': 'document'},
    'application/rtf': {'extension': '.rtf', 'category': 'document'},
    
    # Images
    'image/jpeg': {'extension': '.jpg', 'category': 'image'},
    'image/png': {'extension': '.png', 'category': 'image'},
    'image/gif': {'extension': '.gif', 'category': 'image'},
    'image/bmp': {'extension': '.bmp', 'category': 'image'},
    'image/webp': {'extension': '.webp', 'category': 'image'},
    'image/tiff': {'extension': '.tiff', 'category': 'image'},
    'image/svg+xml': {'extension': '.svg', 'category': 'image'},
    
    # Archives
    'application/zip': {'extension': '.zip', 'category': 'archive'},
    'application/x-rar-compressed': {'extension': '.rar', 'category': 'archive'},
    'application/x-zip-compressed': {'extension': '.zip', 'category': 'archive'}, 
    'application/x-tar': {'extension': '.tar', 'category': 'archive'},
    'application/gzip': {'extension': '.gz', 'category': 'archive'},
    'application/x-7z-compressed': {'extension': '.7z', 'category': 'archive'},
    
    # Executables
    'application/x-msdownload': {'extension': '.exe', 'category': 'executable'},
    'application/x-executable': {'extension': '.exe', 'category': 'executable'},
    'application/x-mach-binary': {'extension': '.bin', 'category': 'executable'},
    'application/x-mach-o-binary': {'extension': '.bin', 'category': 'executable'},
    'application/x-sharedlib': {'extension': '.so', 'category': 'executable'},
    'application/x-python-code': {'extension': '.pyc', 'category': 'executable'},
    'application/x-dosexec': {'extension': '.exe', 'category': 'executable'}, 
    
    # Audio/Video
    'audio/mpeg': {'extension': '.mp3', 'category': 'media'},
    'audio/wav': {'extension': '.wav', 'category': 'media'},
    'audio/ogg': {'extension': '.ogg', 'category': 'media'},
    'video/mp4': {'extension': '.mp4', 'category': 'media'},
    'video/mpeg': {'extension': '.mpeg', 'category': 'media'},
    'video/webm': {'extension': '.webm', 'category': 'media'},
    'video/x-msvideo': {'extension': '.avi', 'category': 'media'},
    
    # Scripts
    'text/javascript': {'extension': '.js', 'category': 'script'},
    'application/x-python': {'extension': '.py', 'category': 'script'},
    'application/x-php': {'extension': '.php', 'category': 'script'},
    'application/x-ruby': {'extension': '.rb', 'category': 'script'},
    'application/x-shellscript': {'extension': '.sh', 'category': 'script'},
    'application/x-perl': {'extension': '.pl', 'category': 'script'},
}

# Known malicious file signatures (magic bytes)
MALICIOUS_SIGNATURES = {
    b'MZ': {'type': 'Windows Executable', 'risk': 'high'},
    b'#!/': {'type': 'Script File', 'risk': 'medium'},
    b'<?php': {'type': 'PHP Script', 'risk': 'medium'},
    b'<script': {'type': 'HTML with Script', 'risk': 'medium'},
    b'eval(': {'type': 'JavaScript with eval', 'risk': 'high'},
    b'document.write(': {'type': 'JavaScript DOM manipulation', 'risk': 'medium'},
    b'exec(': {'type': 'Code execution function', 'risk': 'high'},
    b'system(': {'type': 'System command execution', 'risk': 'high'},
    b'powershell': {'type': 'PowerShell script', 'risk': 'high'},
    b'cmd.exe': {'type': 'Command prompt reference', 'risk': 'high'},
}

# Suspicious Windows API functions commonly used in malware
SUSPICIOUS_WINDOWS_APIS = {
    # Process manipulation
    'CreateRemoteThread': {'risk': 'high', 'category': 'process-injection'},
    'WriteProcessMemory': {'risk': 'high', 'category': 'process-injection'},
    'VirtualAllocEx': {'risk': 'high', 'category': 'process-injection'},
    'ReadProcessMemory': {'risk': 'medium', 'category': 'process-injection'},
    'NtUnmapViewOfSection': {'risk': 'high', 'category': 'process-hollowing'},
    'SetWindowsHookEx': {'risk': 'high', 'category': 'hooking'},
    
    # Code execution
    'CreateProcess': {'risk': 'medium', 'category': 'execution'},
    'ShellExecute': {'risk': 'medium', 'category': 'execution'},
    'WinExec': {'risk': 'medium', 'category': 'execution'},
    'system': {'risk': 'medium', 'category': 'execution'},
    
    # Network related
    'URLDownloadToFile': {'risk': 'medium', 'category': 'network'},
    'InternetOpenUrl': {'risk': 'medium', 'category': 'network'},
    'HttpSendRequest': {'risk': 'medium', 'category': 'network'},
    'connect': {'risk': 'low', 'category': 'network'},
    'WSAConnect': {'risk': 'medium', 'category': 'network'},
    
    # Registry manipulation
    'RegSetValue': {'risk': 'medium', 'category': 'persistence'},
    'RegCreateKey': {'risk': 'medium', 'category': 'persistence'},
    
    # Anti-analysis
    'IsDebuggerPresent': {'risk': 'medium', 'category': 'anti-analysis'},
    'CheckRemoteDebuggerPresent': {'risk': 'medium', 'category': 'anti-analysis'},
    'GetTickCount': {'risk': 'low', 'category': 'anti-analysis'},
    'OutputDebugString': {'risk': 'low', 'category': 'anti-analysis'},
    'FindWindow': {'risk': 'low', 'category': 'anti-analysis'},
    
    # Keylogging
    'SetWindowsHookEx': {'risk': 'high', 'category': 'keylogging'},
    'GetAsyncKeyState': {'risk': 'high', 'category': 'keylogging'},
    'GetKeyState': {'risk': 'medium', 'category': 'keylogging'},
    
    # Crypto (can be legitimate but also used in ransomware)
    'CryptEncrypt': {'risk': 'medium', 'category': 'crypto'},
    'CryptDecrypt': {'risk': 'medium', 'category': 'crypto'},
    'CryptHashData': {'risk': 'low', 'category': 'crypto'},
    
    # Memory manipulation
    'VirtualProtect': {'risk': 'medium', 'category': 'memory-manipulation'},
    'VirtualAlloc': {'risk': 'medium', 'category': 'memory-manipulation'},
    'HeapCreate': {'risk': 'low', 'category': 'memory-manipulation'},
    
    # DLL handling
    'LoadLibrary': {'risk': 'low', 'category': 'dll-loading'},
    'GetProcAddress': {'risk': 'low', 'category': 'dll-loading'},
    'LdrLoadDll': {'risk': 'medium', 'category': 'dll-loading'},
}

# Suspicious combinations of APIs that together are more indicative of malicious behavior
SUSPICIOUS_API_COMBINATIONS = [
    (['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'], 'Classic process injection technique', 'high'),
    (['VirtualAlloc', 'WriteProcessMemory', 'CreateThread'], 'Memory code injection', 'high'),
    (['ReadProcessMemory', 'WriteProcessMemory'], 'Process memory manipulation', 'medium'),
    (['URLDownloadToFile', 'WinExec'], 'Download and execute pattern', 'high'),
    (['HttpSendRequest', 'CreateProcess'], 'Network download and execution', 'high'),
    (['IsDebuggerPresent', 'ExitProcess'], 'Anti-debugging technique', 'medium'),
    (['RegCreateKey', 'LoadLibrary'], 'Possible persistence mechanism', 'medium'),
    (['GetProcAddress', 'VirtualProtect', 'WriteProcessMemory'], 'Runtime code patching', 'high'),
    (['GetAsyncKeyState', 'InternetOpenUrl'], 'Possible keylogging with exfiltration', 'high'),
    (['CryptEncrypt', 'FindFirstFile', 'FindNextFile'], 'Possible ransomware behavior', 'high'),
]

# Known packer signatures
PACKER_SIGNATURES = {
    'UPX': [b'UPX0', b'UPX1', b'UPX!'],
    'ASPack': [b'ASPack', b'ASPr'],
    'PECompact': [b'PEC2', b'PECompact2'],
    'MPRESS': [b'MPRESS1', b'MPRESS2'],
    'Themida': [b'Themida'],
    'VMProtect': [b'VMProtect'],
    'Obsidium': [b'Obsidium'],
    'Enigma': [b'Enigma'],
    'WinRAR SFX': [b'WinRAR SFX'],
    'InstallShield': [b'InstallShield'],
    'NSIS': [b'Nullsoft'],
    'Inno Setup': [b'Inno Setup']
}

# Global VirusTotal API key (you should store this securely in environment variables)
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')

def file_scanner_view(request):
    """Render the file scanner page"""
    context = {}

    # Check if user is logged in
    user_email = request.session.get('user_email')
    
    if user_email:
        # Get user info for display
        from accounts.models import User
        try:
            user = User.objects.get(email=user_email)
            context['username'] = user.username
            context['joined_date'] = user.date_joined
            context['is_guest'] = False
        except User.DoesNotExist:
            context['is_guest'] = True
    else:
        context['is_guest'] = True
        
    return render(request, 'services/file.html', context)

def scan_file(request):
    """Process and scan an uploaded file"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    # Check if file was uploaded
    if 'file' not in request.FILES:
        return JsonResponse({'error': 'No file uploaded'}, status=400)
    
    # Check scan limit
    allowed, message, remaining = ScanLimiter.check_limit(request, 'file')
    if not allowed:
        return JsonResponse({
            'error': message,
            'limit_reached': True,
            'remaining': remaining
        }, status=403)
    
    uploaded_file = request.FILES['file']
    file_name = uploaded_file.name
    file_size = uploaded_file.size
    
    # Check file size
    if file_size > MAX_FILE_SIZE:
        return JsonResponse({
            'error': f'File size exceeds maximum limit of {MAX_FILE_SIZE/1024/1024}MB',
            'file_name': file_name,
            'file_size': file_size
        }, status=400)
    
    # Generate a unique ID for this scan
    scan_id = str(uuid.uuid4())
    
    # Get user ID if logged in
    user_id = None
    if request.session.get('user_email'):
        from accounts.models import User
        try:
            user = User.objects.get(email=request.session.get('user_email'))
            user_id = user.user_id
        except User.DoesNotExist:
            pass
    
    try:
        # Read file content
        file_content = uploaded_file.read()
        
        # Detect file type
        file_type_info = detect_file_type(file_content, file_name)
        file_type = file_type_info['mime_type']
        detected_extension = file_type_info['extension']
        
        # Validate file type
        if file_type not in ALLOWED_FILE_TYPES and not file_type.startswith('text/'):
            return JsonResponse({
                'error': f'File type {file_type} is not allowed',
                'file_name': file_name,
                'file_type': file_type
            }, status=400)
        
        # Create file check record
        file_check = FileCheck.objects.create(
            file_name=file_name,
            file_size=file_size,
            file_type=file_type,
            detected_extension=detected_extension,
            user_id=user_id,
            scan_id=scan_id
        )
        
        # Begin comprehensive file analysis
        analysis_results = analyze_file(file_content, file_name, file_type, file_check)
        
        # Update scan count for guest users
        if not user_id and remaining is not None:
            analysis_results['remaining_scans'] = remaining
        
        return JsonResponse(analysis_results)
        
    except Exception as e:
        import traceback
        print(f"Error scanning file: {str(e)}")
        print(traceback.format_exc())
        return JsonResponse({'error': f'Error scanning file: {str(e)}'}, status=500)

def detect_file_type(file_content, file_name):
    """Detect the MIME type and extension of a file"""
    result = {
        'mime_type': 'application/octet-stream',  # Default
        'extension': os.path.splitext(file_name)[1].lower() if '.' in file_name else '',
        'detected_by': 'default'
    }
    
    try:
        # Use python-magic to detect MIME type
        mime = magic.Magic(mime=True)
        detected_mime = mime.from_buffer(file_content)
        result['mime_type'] = detected_mime
        result['detected_by'] = 'magic'
        
        # Get extension from ALLOWED_FILE_TYPES if available
        if detected_mime in ALLOWED_FILE_TYPES:
            result['extension'] = ALLOWED_FILE_TYPES[detected_mime]['extension']
        
        # Special handling for text files
        if detected_mime.startswith('text/'):
            # Try to determine more specific text type
            if file_name.endswith('.py'):
                result['mime_type'] = 'application/x-python'
                result['extension'] = '.py'
            elif file_name.endswith('.js'):
                result['mime_type'] = 'text/javascript'
                result['extension'] = '.js'
            elif file_name.endswith('.php'):
                result['mime_type'] = 'application/x-php'
                result['extension'] = '.php'
            elif file_name.endswith('.rb'):
                result['mime_type'] = 'application/x-ruby'
                result['extension'] = '.rb'
            elif file_name.endswith('.sh'):
                result['mime_type'] = 'application/x-shellscript'
                result['extension'] = '.sh'
            elif file_name.endswith('.pl'):
                result['mime_type'] = 'application/x-perl'
                result['extension'] = '.pl'
        
    except Exception as e:
        print(f"Error detecting file type: {str(e)}")
    
    return result

def analyze_file(file_content, file_name, file_type, file_check):
    """Perform comprehensive analysis on a file with improved accuracy"""
    # Start with a more balanced base safety rating
    safety_rating = 70  # Start with a more positive assumption
    
    # Initialize results dictionary
    results = {
        'file_name': file_name,
        'file_size': file_check.file_size,
        'file_type': file_type,
        'scan_id': file_check.scan_id,
        'safety_rating': safety_rating,
        'warnings': [],
        'is_malicious': False,
        'scan_date': timezone.now().strftime('%Y-%m-%d %H:%M:%S'),
    }

    # Initialize pe_analysis_results to avoid reference errors
    pe_analysis_results = {'pe_analysis': False}
    
    # Start multiple analysis tasks in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        # Calculate file hashes
        hash_future = executor.submit(calculate_file_hashes, file_content)
        
        # Extract metadata
        metadata_future = executor.submit(extract_file_metadata, file_content, file_name, file_type)
        
        # Check for malicious patterns
        malicious_future = executor.submit(check_malicious_patterns, file_content, file_type)
        
        # Check for steganography (for images)
        stego_future = executor.submit(check_steganography, file_content, file_type)
        
        # Check for code injection
        code_injection_future = executor.submit(check_code_injection, file_content, file_type)
        
        # Add specific executable analysis for PE files
        if file_type in ['application/x-msdownload', 'application/x-executable', 'application/x-mach-binary']:
            pe_analysis_future = executor.submit(analyze_pe_file, file_content, file_name)
        else:
            pe_analysis_future = executor.submit(lambda: {'pe_analysis': False})

        # Get results from parallel tasks
        hash_results = hash_future.result()
        metadata_results = metadata_future.result()
        malicious_results = malicious_future.result()
        stego_results = stego_future.result()
        code_injection_results = code_injection_future.result()
    
    # Process hash results
    results.update(hash_results)
    
    # Process metadata results
    results.update(metadata_results)
    
    # Check if file is a known malicious hash from VirusTotal
    if hash_results.get('is_known_malicious', False):
        results['is_malicious'] = True
        safety_rating -= 50
        results['warnings'].append(f"File hash matches known malware (VirusTotal: {hash_results.get('vt_detections', 0)}/{hash_results.get('vt_total', 0)} detections)")
    
    # Process malicious pattern check results - be more conservative
    results.update(malicious_results)
    if malicious_results.get('malicious_patterns_found', False):
        # Only mark as malicious if we have high confidence
        if any("High confidence" in warning for warning in malicious_results.get('warnings', [])):
            results['is_malicious'] = True
            safety_rating -= 30
        else:
            # Otherwise just reduce the safety rating
            safety_rating -= 15
        
        results['warnings'].extend(malicious_results.get('warnings', []))
    
    # Process steganography results - be more conservative
    results.update(stego_results)
    if stego_results.get('potential_steganography', False):
        # Don't mark as malicious just for steganography, but use a special status
        results['warnings'].append("Steganography detected in the file")
        results['stego_details'] = stego_results.get('stego_details', 'Hidden data may be present')
        results['extracted_steganography'] = stego_results.get('extracted_hidden_content', 'Could not extract hidden content')
        
        # Set specific status for steganography
        results['status'] = "Steganography Found"
        safety_rating -= 15
    
    # Process code injection results
    results.update(code_injection_results)
    if code_injection_results.get('code_injection_detected', False):
        # Only mark as malicious if it's a high confidence detection
        if code_injection_results.get('confidence', 0) > 80:
            results['is_malicious'] = True
            safety_rating -= 25
        else:
            safety_rating -= 15
            
        results['warnings'].extend(code_injection_results.get('warnings', []))

    # Process PE analysis results for executables
    if pe_analysis_results.get('pe_analysis', False):
        results.update(pe_analysis_results)
        
        # Handle suspicious API calls
        if pe_analysis_results.get('suspicious_apis_found', False):
            api_count = pe_analysis_results.get('suspicious_api_count', 0)
            results['warnings'].extend(pe_analysis_results.get('api_warnings', []))
            
            # Adjust safety rating based on severity of API findings
            if api_count >= 5 or any(warning for warning in pe_analysis_results.get('api_warnings', []) if 'high risk' in warning.lower()):
                results['is_malicious'] = True
                safety_rating -= 30
            elif api_count >= 3:
                safety_rating -= 20
            else:
                safety_rating -= 10
        
        # Handle suspicious sections
        if pe_analysis_results.get('suspicious_sections', False):
            results['warnings'].extend(pe_analysis_results.get('section_warnings', []))
            safety_rating -= 15
        
        # Handle packer detection
        if pe_analysis_results.get('is_packed', False):
            packer = pe_analysis_results.get('packer_type', 'Unknown')
            results['warnings'].append(f"Executable is packed with {packer}")
            
            # Some packers are more suspicious than others
            if packer not in ['UPX', 'WinRAR SFX', 'InstallShield', 'NSIS', 'Inno Setup']:
                safety_rating -= 20
                results['warnings'].append("Uncommon packer detected - may be used to hide malicious code")
            else:
                safety_rating -= 5
        
        # Handle high entropy detection
        if pe_analysis_results.get('high_entropy', False):
            results['warnings'].append("Executable contains high entropy sections, possibly indicating encryption or obfuscation")
            safety_rating -= 15
        
        # Handle suspicious strings
        if pe_analysis_results.get('suspicious_strings', False):
            results['warnings'].extend(pe_analysis_results.get('string_warnings', [])[:5])  # Limit to top 5 warnings
            
            if pe_analysis_results.get('suspicious_string_severity', 'low') == 'high':
                safety_rating -= 20
            else:
                safety_rating -= 10
        
        # Handle digital signature verification
        if pe_analysis_results.get('is_signed', False):
            if pe_analysis_results.get('signature_valid', False):
                results['warnings'].append("Executable is digitally signed with a valid certificate")
                safety_rating += 10  # Bonus for valid signature
            else:
                results['warnings'].append("Executable has an invalid digital signature")
                safety_rating -= 10
    
    # Adjust safety rating based on file type - be more lenient
    if file_type in ['application/x-msdownload', 'application/x-executable', 'application/x-mach-binary']:
        # Executables start with a slightly lower rating but aren't automatically suspicious
        safety_rating -= 5
        if not results['warnings']:
            results['warnings'].append("Executable files can potentially contain malicious code, but no specific threats were detected in this file.")
    
    # Give bonuses for common safe file types
    if file_type in ['image/jpeg', 'image/png', 'image/gif', 'image/webp'] and not results['warnings']:
        safety_rating += 10
        
    if file_type in ['text/plain', 'text/csv'] and not results['warnings']:
        safety_rating += 5
    
    # Calculate final safety rating
    results['safety_rating'] = max(0, min(100, safety_rating))
    
    # Generate status text based on safety rating - more balanced approach
    if results['is_malicious']:
        results['status'] = "Malicious"
    elif stego_results.get('potential_steganography', False):
        results['status'] = "Steganography Found"
    elif results['safety_rating'] >= 80:
        results['status'] = "Safe"
    elif results['safety_rating'] >= 60:
        results['status'] = "Probably Safe"
    elif results['safety_rating'] >= 40:
        results['status'] = "Suspicious"
    else:
        results['status'] = "High Risk"
    
    # Generate comments based on analysis
    comments = []
    
    # Basic file information comment
    comments.append(f"File: {file_name} ({format_file_size(file_check.file_size)})")
    comments.append(f"Type: {file_type}")
    
    # Add hash information
    comments.append(f"MD5: {hash_results['hashes'].get('md5', 'N/A')}")
    comments.append(f"SHA-1: {hash_results['hashes'].get('sha1', 'N/A')}")
    comments.append(f"SHA-256: {hash_results['hashes'].get('sha256', 'N/A')}")
    
    # Add VirusTotal information if available
    if 'virustotal' in hash_results and hash_results['virustotal'].get('found', False):
        vt_results = hash_results['virustotal']
        if vt_results.get('positives', 0) > 0:
            comments.append(f"VirusTotal: {vt_results.get('positives', 0)}/{vt_results.get('total', 0)} security vendors flagged this file as malicious")
            
            # Add some detected threats
            if vt_results.get('scans'):
                threat_names = [f"{av}: {scan.get('result')}" for av, scan in vt_results.get('scans', {}).items()]
                comments.append(f"Detected threats: {', '.join(threat_names)}")
        else:
            comments.append("VirusTotal: No security vendors flagged this file as malicious")
    
        # Add executable-specific information
    if file_type in ['application/x-msdownload', 'application/x-executable', 'application/x-mach-binary'] and pe_analysis_results.get('pe_analysis', False):
        if pe_analysis_results.get('pe_info'):
            pe_info = pe_analysis_results.get('pe_info')
            comments.append(f"PE Time Stamp: {pe_info.get('timestamp', 'N/A')}")
            comments.append(f"Entry Point: {pe_info.get('entrypoint', 'N/A')}")
            comments.append(f"Sections: {', '.join(pe_info.get('sections', []))}")
            
            if pe_info.get('subsystem'):
                comments.append(f"Subsystem: {pe_info.get('subsystem')}")
            
            if pe_info.get('compiler'):
                comments.append(f"Compiler: {pe_info.get('compiler')}")
        
        if pe_analysis_results.get('is_packed', False):
            comments.append(f"Packer detected: {pe_analysis_results.get('packer_type', 'Unknown')}")
        
        if pe_analysis_results.get('is_signed', False):
            if pe_analysis_results.get('signature_valid', False):
                comments.append(f"Digital Signature: Valid (Signed by: {pe_analysis_results.get('signer', 'Unknown')})")
            else:
                comments.append(f"Digital Signature: Invalid or expired")
        
        if pe_analysis_results.get('suspicious_apis_found', False):
            comments.append(f"Suspicious API calls: {pe_analysis_results.get('suspicious_api_count', 0)} detected")
            
            # Group APIs by category
            api_categories = {}
            for api in pe_analysis_results.get('detected_apis', []):
                category = SUSPICIOUS_WINDOWS_APIS.get(api, {}).get('category', 'other')
                if category not in api_categories:
                    api_categories[category] = []
                api_categories[category].append(api)
            
            for category, apis in api_categories.items():
                comments.append(f"  - {category.replace('-', ' ').title()}: {', '.join(apis[:5])}" + 
                                (f" and {len(apis)-5} more" if len(apis) > 5 else ""))
    
    # Add comments about malicious patterns - more informative
    if malicious_results.get('malicious_patterns_found', False):
        comments.append(f"Potentially concerning patterns detected: {', '.join(malicious_results.get('detected_patterns', []))}")
    
    # Add comments about steganography
    if stego_results.get('potential_steganography', False):
        comments.append(f"Steganography detected: {stego_results.get('stego_details', 'Hidden data may be present')}")
        
        # Add the extracted content to the comments
        if stego_results.get('extracted_hidden_content'):
            comments.append(f"Extracted hidden content:\n{stego_results.get('extracted_hidden_content')}")

    # Add comments about code injection
    if code_injection_results.get('code_injection_detected', False):
        comments.append(f"Code injection detected: {code_injection_results.get('injection_details', 'Suspicious code found')}")
    
    # Add overall assessment - more balanced
    if results['is_malicious']:
        comments.append(f"VERDICT: This file is likely MALICIOUS and should not be trusted")
    elif results['safety_rating'] < 40:
        comments.append(f"VERDICT: This file contains suspicious elements and should be handled with caution")
    elif results['safety_rating'] < 60:
        comments.append(f"VERDICT: This file contains some concerning elements but may be legitimate")
    else:
        comments.append(f"VERDICT: This file appears to be safe")
    
    # Join comments into a single string
    results['comments'] = "\n".join(comments)
    
    # Save results to database
    file_result = FileCheckResult.objects.create(
        file_check=file_check,
        safety_rating=results['safety_rating'],
        is_malicious=results['is_malicious'],
        comments=results['comments'],
        warnings=results['warnings'],
        hash_md5=hash_results['hashes'].get('md5'),
        hash_sha1=hash_results['hashes'].get('sha1'),
        hash_sha256=hash_results['hashes'].get('sha256')
    )
    
    # Save metadata to database
    FileScanMetadata.objects.create(
        file_check=file_check,
        metadata=metadata_results.get('extracted_metadata', {}),
        creation_time=metadata_results.get('creation_time'),
        modification_time=metadata_results.get('modification_time'),
        access_time=metadata_results.get('access_time')
    )
    
    return results

def analyze_pe_file(file_content, file_name):
    """Detailed analysis of PE (Portable Executable) files"""
    results = {
        'pe_analysis': False,
        'pe_info': {},
        'suspicious_apis_found': False,
        'suspicious_api_count': 0,
        'detected_apis': [],
        'api_warnings': [],
        'suspicious_sections': False,
        'section_warnings': [],
        'is_packed': False,
        'packer_type': None,
        'high_entropy': False,
        'suspicious_strings': False,
        'string_warnings': [],
        'suspicious_string_severity': 'low',
        'is_signed': False,
        'signature_valid': False,
        'signer': None
    }
    
    try:
        # Create a temporary file to analyze
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            temp.write(file_content)
            temp_path = temp.name
        
        # Load the PE file
        pe = pefile.PE(temp_path)
        
        # Mark PE analysis as successful
        results['pe_analysis'] = True
        
        # Extract basic PE information
        results['pe_info'] = {
            'entrypoint': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'imagebase': hex(pe.OPTIONAL_HEADER.ImageBase),
            'timestamp': datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S'),
            'sections': [section.Name.decode('utf-8', 'ignore').strip('\x00') for section in pe.sections],
            'subsystem': f"{pe.OPTIONAL_HEADER.Subsystem} ({get_subsystem_name(pe.OPTIONAL_HEADER.Subsystem)})",
            'compiler': detect_compiler(pe)
        }
        
        # Analyze imports (API calls)
        suspicious_apis = []
        api_categories = set()
        detected_apis = []
        high_risk_apis = 0
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode('utf-8', 'ignore')
                        
                        # Check if this API is in our suspicious list
                        if api_name in SUSPICIOUS_WINDOWS_APIS:
                            detected_apis.append(api_name)
                            api_info = SUSPICIOUS_WINDOWS_APIS[api_name]
                            api_categories.add(api_info['category'])
                            
                            if api_info['risk'] == 'high':
                                high_risk_apis += 1
                                suspicious_apis.append(f"{api_name} (high risk)")
                            elif api_info['risk'] == 'medium':
                                suspicious_apis.append(f"{api_name} (medium risk)")
        
        # Look for suspicious combinations of APIs
        for combo, description, risk in SUSPICIOUS_API_COMBINATIONS:
            if all(api in detected_apis for api in combo):
                if risk == 'high':
                    results['api_warnings'].append(f"High risk behavior detected: {description} ({', '.join(combo)})")
                else:
                    results['api_warnings'].append(f"Suspicious behavior detected: {description} ({', '.join(combo)})")
        
        # Update API detection results
        if detected_apis:
            results['suspicious_apis_found'] = True
            results['detected_apis'] = detected_apis
            results['suspicious_api_count'] = len(detected_apis)
            
            # Add warnings for high-risk APIs
            for api in suspicious_apis[:10]:  # Limit to top 10
                results['api_warnings'].append(f"Suspicious API detected: {api}")
            
            if len(suspicious_apis) > 10:
                results['api_warnings'].append(f"... and {len(suspicious_apis) - 10} more suspicious APIs")
            
            # Add a summary of suspicious categories
            if api_categories:
                categories_str = ", ".join([cat.replace('-', ' ').title() for cat in api_categories])
                results['api_warnings'].append(f"Suspicious behavior categories: {categories_str}")
        
        # Analyze sections
        suspicious_sections = []
        high_entropy_sections = []
        total_entropy = 0
        
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
            
            # Check for sections with both executable and writable flags
            if (section.Characteristics & 0x20000000) and (section.Characteristics & 0x80000000):
                suspicious_sections.append(section_name)
            
            # Calculate entropy to detect packed or encrypted sections
            entropy = calculate_entropy(section.get_data())
            if entropy > 7.0:  # High entropy threshold
                high_entropy_sections.append(f"{section_name} ({entropy:.2f})")
            
            total_entropy += entropy
        
        # Update section analysis results
        if suspicious_sections:
            results['suspicious_sections'] = True
            results['section_warnings'].append(f"Suspicious section permissions (executable+writable): {', '.join(suspicious_sections)}")
        
        if high_entropy_sections:
            results['high_entropy'] = True
            results['section_warnings'].append(f"High entropy sections detected: {', '.join(high_entropy_sections)}")
        
        # Check for packer signatures
        for packer_name, signatures in PACKER_SIGNATURES.items():
            for sig in signatures:
                if sig in file_content:
                    results['is_packed'] = True
                    results['packer_type'] = packer_name
                    break
            if results['is_packed']:
                break
        
        # If no known packer was found but high entropy is detected, mark as possibly packed
        if not results['is_packed'] and results['high_entropy']:
            avg_entropy = total_entropy / len(pe.sections)
            if avg_entropy > 6.5:
                results['is_packed'] = True
                results['packer_type'] = "Unknown packer"
        
        # Extract and analyze strings
        strings = extract_strings(file_content)
        
        # Categories of suspicious strings
        suspicious_string_categories = {
            'system_commands': [],
            'network': [],
            'registry': [],
            'anti_vm': [],
            'injection': [],
            'crypto': [],
            'other': []
        }
        
        # Check for suspicious strings
        for string in strings:
            string_lower = string.lower()
            
            # Command execution
            if any(cmd in string_lower for cmd in ['cmd.exe', 'powershell', 'wscript', 'cscript', 'regsvr32']):
                suspicious_string_categories['system_commands'].append(string)
                
            # Network indicators
            elif any(net in string_lower for net in ['http://', 'https://', 'ftp://', 'socket', 'connect']):
                suspicious_string_categories['network'].append(string)
                
            # Registry operations
            elif 'hkey_' in string_lower or 'registry' in string_lower:
                suspicious_string_categories['registry'].append(string)
                
            # Anti-VM/Anti-Analysis
            elif any(vm in string_lower for vm in ['vmware', 'virtualbox', 'vbox', 'qemu', 'sandbox', 'wireshark', 'debugger']):
                suspicious_string_categories['anti_vm'].append(string)
                
            # Injection related
            elif any(inj in string_lower for inj in ['inject', 'createremotethread', 'virtualalloc', 'memcpy']):
                suspicious_string_categories['injection'].append(string)
                
            # Encryption/Ransom
            elif any(crypt in string_lower for crypt in ['encrypt', 'decrypt', 'ransom', 'bitcoin', 'wallet', 'payment']):
                suspicious_string_categories['crypto'].append(string)
                
            # Other suspicious strings
            elif any(other in string_lower for other in ['shellcode', 'backdoor', 'rootkit', 'trojan', 'keylog', 'exploit']):
                suspicious_string_categories['other'].append(string)
        
        # Process string analysis results
        high_severity_categories = ['system_commands', 'injection', 'anti_vm', 'crypto']
        has_high_severity = any(len(suspicious_string_categories[cat]) > 0 for cat in high_severity_categories)
        
        total_suspicious_strings = sum(len(strings) for strings in suspicious_string_categories.values())
        
        if total_suspicious_strings > 0:
            results['suspicious_strings'] = True
            results['suspicious_string_severity'] = 'high' if has_high_severity else 'medium'
            
            # Add warnings for suspicious strings by category
            for category, strings in suspicious_string_categories.items():
                if strings:
                    if len(strings) > 3:
                        sample = ", ".join(strings[:3]) + f" and {len(strings)-3} more"
                    else:
                        sample = ", ".join(strings)
                    
                    category_name = category.replace('_', ' ').title()
                    results['string_warnings'].append(f"Suspicious strings found ({category_name}): {sample}")
        
        # Check for digital signature
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            import win32api
            
            # Get signature information using win32api
            signatures = win32api.GetSignerInfo(temp_path)
            if signatures:
                results['is_signed'] = True
                cert_data = signatures[0]
                
                # Verify signature
                if win32api.VerifySignature(temp_path, cert_data):
                    results['signature_valid'] = True
                    
                    # Extract signer information
                    if 'signer' in cert_data:
                        results['signer'] = cert_data['signer']
        except:
            # Fallback if win32api is not available or fails
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') and pe.DIRECTORY_ENTRY_SECURITY:
                results['is_signed'] = True
                # Cannot verify without win32api
                results['signature_valid'] = False
    
    except Exception as e:
        import traceback
        print(f"Error analyzing PE file: {str(e)}")
        print(traceback.format_exc())
    
    finally:
        # Clean up the temporary file
        try:
            if 'temp_path' in locals():
                os.unlink(temp_path)
        except:
            pass
    
    return results


def get_subsystem_name(subsystem_id):
    """Return the name of a PE subsystem based on its ID"""
    subsystems = {
        0: "UNKNOWN",
        1: "NATIVE",
        2: "WINDOWS_GUI",
        3: "WINDOWS_CUI",
        5: "OS2_CUI",
        7: "POSIX_CUI",
        8: "NATIVE_WINDOWS",
        9: "WINDOWS_CE_GUI",
        10: "EFI_APPLICATION",
        11: "EFI_BOOT_SERVICE_DRIVER",
        12: "EFI_RUNTIME_DRIVER",
        13: "EFI_ROM",
        14: "XBOX",
        16: "WINDOWS_BOOT_APPLICATION"
    }
    return subsystems.get(subsystem_id, f"UNKNOWN ({subsystem_id})")

def detect_compiler(pe):
    """Attempt to detect the compiler used to build the executable"""
    # Check for specific compiler signatures in the rich header
    if hasattr(pe, 'RICH_HEADER'):
        if b'VS2019' in pe.RICH_HEADER.raw:
            return "Visual Studio 2019"
        elif b'VS2017' in pe.RICH_HEADER.raw:
            return "Visual Studio 2017"
        elif b'VS2015' in pe.RICH_HEADER.raw:
            return "Visual Studio 2015"
        elif b'VS2013' in pe.RICH_HEADER.raw:
            return "Visual Studio 2013"
        elif b'VS2012' in pe.RICH_HEADER.raw:
            return "Visual Studio 2012"
        elif b'VS2010' in pe.RICH_HEADER.raw:
            return "Visual Studio 2010"
        elif b'VS2008' in pe.RICH_HEADER.raw:
            return "Visual Studio 2008"
        elif b'VS2005' in pe.RICH_HEADER.raw:
            return "Visual Studio 2005"
    
    # Look for specific sections or strings
    sections = [section.Name.decode('utf-8', 'ignore').strip('\x00') for section in pe.sections]
    
    if '.text' in sections and '.rdata' in sections and '.data' in sections:
        # Generic Visual C++ pattern
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if entry.dll.decode('utf-8', 'ignore').lower() == "msvcrt.dll":
                    return "Microsoft Visual C++"
                elif entry.dll.decode('utf-8', 'ignore').lower() == "libgcc_s_dw2-1.dll":
                    return "MinGW GCC"
    
    if '.ndata' in sections or any(section.startswith('.idata') for section in sections):
        return "Borland Delphi/C++"
    
    # Check for Go binaries
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if any(imp.name and b'go' in imp.name.lower() for imp in entry.imports if imp.name):
                return "Go Compiler"
    
    # Check for .NET assemblies
    if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
        return ".NET Framework"
    
    # Default if we can't determine the compiler
    return "Unknown"

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0
    
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
            
    return entropy

def extract_strings(data, min_length=4):
    """Extract printable strings from binary data"""
    strings = []
    current_string = ""
    
    for byte in data:
        char = chr(byte)
        if 32 <= byte <= 126:  # Printable ASCII
            current_string += char
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
            current_string = ""
    
    # Don't forget the last string if it meets the length requirement
    if len(current_string) >= min_length:
        strings.append(current_string)
    
    # Filter out common uninteresting strings and limit the number
    filtered_strings = [s for s in strings if len(s) > min_length and not s.isdigit()]
    
    # Remove duplicates and limit to 1000 strings
    return list(set(filtered_strings))[:1000]


def calculate_file_hashes(file_content):
    """Calculate various hash values for a file"""
    hash_results = {
        'hashes': {}
    }
    
    # Calculate common hash types
    for algorithm in HASH_ALGORITHMS:
        hasher = getattr(hashlib, algorithm)()
        hasher.update(file_content)
        hash_results['hashes'][algorithm] = hasher.hexdigest()
    
    # Check hashes against VirusTotal if API key is available
    if VIRUSTOTAL_API_KEY:
        vt_results = check_virustotal(hash_results['hashes']['sha256'])
        hash_results['virustotal'] = vt_results
        
        # Update malicious status based on VirusTotal results
        if vt_results.get('positives', 0) > 0:
            hash_results['vt_detections'] = vt_results.get('positives', 0)
            hash_results['vt_total'] = vt_results.get('total', 0)
            hash_results['is_known_malicious'] = True
    
    return hash_results

def check_virustotal(file_hash):
    """Check a file hash against VirusTotal API"""
    results = {
        'found': False,
        'positives': 0,
        'total': 0,
        'scan_date': None,
        'permalink': None,
        'scans': {}
    }
    
    try:
        url = f'https://www.virustotal.com/vtapi/v2/file/report'
        params = {
            'apikey': VIRUSTOTAL_API_KEY,
            'resource': file_hash
        }
        
        response = requests.get(url, params=params, timeout=15)
        if response.status_code == 200:
            data = response.json()
            
            if data.get('response_code') == 1:  # File found in VT database
                results['found'] = True
                results['positives'] = data.get('positives', 0)
                results['total'] = data.get('total', 0)
                results['scan_date'] = data.get('scan_date')
                results['permalink'] = data.get('permalink')
                
                # Get top antivirus results (limit to 5 for brevity)
                av_count = 0
                for av_name, av_result in data.get('scans', {}).items():
                    if av_result.get('detected') and av_count < 5:
                        results['scans'][av_name] = {
                            'detected': True,
                            'result': av_result.get('result')
                        }
                        av_count += 1
    
    except Exception as e:
        print(f"Error checking VirusTotal: {str(e)}")
    
    return results

def extract_file_metadata(file_content, file_name, file_type):
    """Extract metadata from the file based on its type"""
    metadata = {
        'metadata': {
            'file_name': file_name,
            'file_size_bytes': len(file_content),
            'file_size_formatted': format_file_size(len(file_content)),
            'mime_type': file_type,
        },
        'creation_time': None,
        'modification_time': None,
        'access_time': None,
        'extracted_metadata': {}
    }
    
    # Create a temporary file to work with
    temp_file = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            temp.write(file_content)
            temp_file = temp.name
        
        # Extract file metadata based on file type
        if file_type.startswith('image/'):
            metadata.update(extract_image_metadata(file_content, temp_file))
        
        elif file_type == 'application/pdf':
            metadata.update(extract_pdf_metadata(file_content, temp_file))
        
        elif file_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
            metadata.update(extract_office_metadata(temp_file, 'word'))
            
        elif file_type in ['application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']:
            metadata.update(extract_office_metadata(temp_file, 'excel'))
            
        elif file_type in ['application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation']:
            metadata.update(extract_office_metadata(temp_file, 'powerpoint'))
        
        elif file_type.startswith('text/'):
            metadata.update(extract_text_metadata(file_content))
        
        elif file_type.startswith('audio/') or file_type.startswith('video/'):
            metadata.update(extract_media_metadata(temp_file))
        
        elif file_type.startswith('application/zip') or file_type.startswith('application/x-'):
            metadata.update(extract_archive_metadata(file_content, temp_file, file_type))
    
    except Exception as e:
        print(f"Error extracting metadata: {str(e)}")
    
    finally:
        # Clean up temporary file
        if temp_file and os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
            except:
                pass
    
    return metadata

def extract_image_metadata(file_content, temp_file):
    """Extract metadata from image files"""
    metadata = {
        'image_metadata': {},
        'extracted_metadata': {}
    }
    
    try:
        # Use PIL to get basic image info
        with Image.open(BytesIO(file_content)) as img:
            metadata['image_metadata'] = {
                'width': img.width,
                'height': img.height,
                'format': img.format,
                'mode': img.mode,
                'animation': hasattr(img, 'is_animated') and img.is_animated,
                'frames': getattr(img, 'n_frames', 1) if hasattr(img, 'n_frames') else 1
            }
        
        # Use exifread for detailed EXIF data
        with open(temp_file, 'rb') as f:
            exif_tags = exifread.process_file(f, details=False)
            
            # Extract useful EXIF data
            if exif_tags:
                extracted = {}
                
                # Camera information
                if 'Image Make' in exif_tags:
                    extracted['camera_make'] = str(exif_tags['Image Make'])
                if 'Image Model' in exif_tags:
                    extracted['camera_model'] = str(exif_tags['Image Model'])
                
                # Date information
                if 'EXIF DateTimeOriginal' in exif_tags:
                    extracted['date_taken'] = str(exif_tags['EXIF DateTimeOriginal'])
                
                # GPS information (if available)
                gps_latitude = None
                gps_longitude = None
                
                if 'GPS GPSLatitude' in exif_tags and 'GPS GPSLatitudeRef' in exif_tags:
                    lat = exif_tags['GPS GPSLatitude'].values
                    lat_ref = str(exif_tags['GPS GPSLatitudeRef'])
                    
                    lat_value = float(lat[0].num) / float(lat[0].den) + \
                                (float(lat[1].num) / float(lat[1].den)) / 60 + \
                                (float(lat[2].num) / float(lat[2].den)) / 3600
                    
                    if lat_ref == 'S':
                        lat_value = -lat_value
                    
                    gps_latitude = lat_value
                
                if 'GPS GPSLongitude' in exif_tags and 'GPS GPSLongitudeRef' in exif_tags:
                    lon = exif_tags['GPS GPSLongitude'].values
                    lon_ref = str(exif_tags['GPS GPSLongitudeRef'])
                    
                    lon_value = float(lon[0].num) / float(lon[0].den) + \
                                (float(lon[1].num) / float(lon[1].den)) / 60 + \
                                (float(lon[2].num) / float(lon[2].den)) / 3600
                    
                    if lon_ref == 'W':
                        lon_value = -lon_value
                    
                    gps_longitude = lon_value
                
                if gps_latitude is not None and gps_longitude is not None:
                    extracted['gps_coordinates'] = {
                        'latitude': gps_latitude,
                        'longitude': gps_longitude
                    }
                
                # Software information
                if 'Image Software' in exif_tags:
                    extracted['software'] = str(exif_tags['Image Software'])
                
                metadata['extracted_metadata'] = extracted
    
    except Exception as e:
        print(f"Error extracting image metadata: {str(e)}")
    
    return metadata

def extract_pdf_metadata(file_content, temp_file):
    """Extract metadata from PDF files"""
    metadata = {
        'pdf_metadata': {},
        'extracted_metadata': {}
    }
    
    try:
        with open(temp_file, 'rb') as f:
            pdf = PyPDF2.PdfReader(f)
            
            # Basic PDF info
            metadata['pdf_metadata'] = {
                'pages': len(pdf.pages),
                'encrypted': pdf.is_encrypted
            }
            
            # Extract document info if available
            if pdf.metadata:
                extracted = {}
                
                # Standard metadata fields
                info_fields = [
                    ('title', 'Title'), 
                    ('author', 'Author'),
                    ('subject', 'Subject'),
                    ('creator', 'Creator'),
                    ('producer', 'Producer'),
                    ('creation_date', 'CreationDate'),
                    ('modification_date', 'ModDate')
                ]
                
                for field, key in info_fields:
                    if key in pdf.metadata:
                        value = pdf.metadata[key]
                        # Clean up date strings
                        if 'date' in field.lower() and value:
                            # Try to parse PDF date format (D:YYYYMMDDHHmmSSOHH'mm')
                            if isinstance(value, str) and value.startswith('D:'):
                                try:
                                    date_str = value[2:]
                                    year = date_str[0:4]
                                    month = date_str[4:6]
                                    day = date_str[6:8]
                                    hour = date_str[8:10]
                                    minute = date_str[10:12]
                                    second = date_str[12:14] if len(date_str) > 12 else '00'
                                    value = f"{year}-{month}-{day} {hour}:{minute}:{second}"
                                except:
                                    pass  # Keep original value if parsing fails
                        
                        extracted[field] = str(value)
                
                metadata['extracted_metadata'] = extracted
    
    except Exception as e:
        print(f"Error extracting PDF metadata: {str(e)}")
    
    return metadata

def extract_office_metadata(temp_file, office_type):
    """Extract metadata from Microsoft Office files"""
    metadata = {
        'office_metadata': {},
        'extracted_metadata': {}
    }
    
    try:
        # Use olefile for legacy Office documents
        if olefile.isOleFile(temp_file):
            with olefile.OleFile(temp_file) as ole:
                if ole.exists('\x05DocumentSummaryInformation'):
                    summary = ole.getproperties('\x05DocumentSummaryInformation')
                    metadata['office_metadata']['summary'] = {str(k): str(v) for k, v in summary.items() if k != 0}
                
                if ole.exists('\x05SummaryInformation'):
                    info = ole.getproperties('\x05SummaryInformation')
                    
                    extracted = {}
                    
                    # Map property IDs to names
                    prop_map = {
                        2: 'title',
                        3: 'subject',
                        4: 'author',
                        5: 'keywords',
                        6: 'comments',
                        8: 'last_saved_by',
                        9: 'revision',
                        12: 'creation_date',
                        13: 'last_saved_date',
                        18: 'application',
                        19: 'security'
                    }
                    
                    for prop_id, name in prop_map.items():
                        if prop_id in info:
                            value = info[prop_id]
                            
                            # Convert timestamps to readable format
                            if name in ['creation_date', 'last_saved_date'] and isinstance(value, float):
                                try:
                                    # Convert OLE timestamp (days since 1899-12-30) to datetime
                                    date_obj = datetime.datetime(1899, 12, 30) + datetime.timedelta(days=value)
                                    value = date_obj.strftime('%Y-%m-%d %H:%M:%S')
                                except:
                                    pass
                            
                            extracted[name] = str(value)
                    
                    metadata['extracted_metadata'] = extracted
    
    except Exception as e:
        print(f"Error extracting Office metadata: {str(e)}")
    
    return metadata

def extract_text_metadata(file_content):
    """Extract metadata from text files"""
    metadata = {
        'text_metadata': {},
        'extracted_metadata': {}
    }
    
    try:
        # Determine encoding
        encoding = 'utf-8'  # Default
        try:
            file_content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                file_content.decode('latin-1')
                encoding = 'latin-1'
            except:
                encoding = 'unknown'
        
        # Count lines and characters
        if encoding != 'unknown':
            text = file_content.decode(encoding)
            lines = text.splitlines()
            
            metadata['text_metadata'] = {
                'encoding': encoding,
                'line_count': len(lines),
                'character_count': len(text),
                'word_count': len(text.split())
            }
            
            # Check for shebang in script files
            if lines and lines[0].startswith('#!'):
                metadata['extracted_metadata']['interpreter'] = lines[0][2:].strip()
            
            # Look for author/version comments in common formats
            for line in lines[:20]:  # Check first 20 lines
                line_lower = line.lower()
                
                # Author patterns
                author_patterns = [
                    r'@author\s*:\s*([^\n]+)',
                    r'author\s*:\s*([^\n]+)',
                    r'created by\s*:\s*([^\n]+)',
                    r'copyright\s*\(c\)\s*([^\n]+)'
                ]
                
                for pattern in author_patterns:
                    match = re.search(pattern, line_lower)
                    if match:
                        metadata['extracted_metadata']['author'] = match.group(1).strip()
                        break
                
                # Version patterns
                version_patterns = [
                    r'@version\s*:\s*([^\n]+)',
                    r'version\s*:\s*([^\n]+)',
                    r'v(\d+\.\d+\.\d+)',
                ]
                
                for pattern in version_patterns:
                    match = re.search(pattern, line_lower)
                    if match:
                        metadata['extracted_metadata']['version'] = match.group(1).strip()
                        break
                
                # Date patterns
                date_patterns = [
                    r'@date\s*:\s*([^\n]+)',
                    r'date\s*:\s*([^\n]+)',
                    r'created on\s*:\s*([^\n]+)'
                ]
                
                for pattern in date_patterns:
                    match = re.search(pattern, line_lower)
                    if match:
                        metadata['extracted_metadata']['date'] = match.group(1).strip()
                        break
    
    except Exception as e:
        print(f"Error extracting text metadata: {str(e)}")
    
    return metadata

def extract_media_metadata(temp_file):
    """Extract metadata from audio/video files"""
    metadata = {
        'media_metadata': {},
        'extracted_metadata': {}
    }
    
    # This would typically use a library like mutagen or ffmpeg
    # For simplicity, we'll return minimal metadata
    try:
        pass  # Placeholder for media metadata extraction
    except Exception as e:
        print(f"Error extracting media metadata: {str(e)}")
    
    return metadata

def extract_archive_metadata(file_content, temp_file, file_type):
    """Extract metadata from archive files"""
    metadata = {
        'archive_metadata': {},
        'extracted_metadata': {},
        'file_listing': []
    }
    
    try:
        # Handle different archive types
        if file_type == 'application/zip':
            with zipfile.ZipFile(BytesIO(file_content)) as zip_file:
                file_list = zip_file.namelist()
                file_count = len(file_list)
                
                # Get archive comment if any
                comment = zip_file.comment
                if comment:
                    metadata['extracted_metadata']['comment'] = comment.decode('utf-8', errors='ignore')
                
                # Get info about files in the archive
                total_size = 0
                compressed_size = 0
                newest_file_date = None
                oldest_file_date = None
                
                for info in zip_file.infolist():
                    total_size += info.file_size
                    compressed_size += info.compress_size
                    
                    # Convert DOS time to datetime
                    date_time = datetime.datetime(*info.date_time)
                    
                    if newest_file_date is None or date_time > newest_file_date:
                        newest_file_date = date_time
                    
                    if oldest_file_date is None or date_time < oldest_file_date:
                        oldest_file_date = date_time
                    
                    # Add file to listing (limit to first 100 files)
                    if len(metadata['file_listing']) < 100:
                        metadata['file_listing'].append({
                            'name': info.filename,
                            'size': info.file_size,
                            'compressed_size': info.compress_size,
                            'date': date_time.strftime('%Y-%m-%d %H:%M:%S')
                        })
                
                # Calculate compression ratio
                compression_ratio = 0
                if total_size > 0:
                    compression_ratio = (total_size - compressed_size) / total_size * 100
                
                metadata['archive_metadata'] = {
                    'file_count': file_count,
                    'total_size': total_size,
                    'compressed_size': compressed_size,
                    'compression_ratio': round(compression_ratio, 2),
                    'newest_file_date': newest_file_date.strftime('%Y-%m-%d %H:%M:%S') if newest_file_date else None,
                    'oldest_file_date': oldest_file_date.strftime('%Y-%m-%d %H:%M:%S') if oldest_file_date else None
                }
        
        elif file_type == 'application/x-tar':
            with tarfile.open(temp_file, 'r') as tar_file:
                file_list = tar_file.getnames()
                file_count = len(file_list)
                
                # Get info about files in the archive
                total_size = 0
                newest_file_date = None
                oldest_file_date = None
                
                for member in tar_file.getmembers():
                    total_size += member.size
                    
                    # Convert timestamp to datetime
                    date_time = datetime.datetime.fromtimestamp(member.mtime)
                    
                    if newest_file_date is None or date_time > newest_file_date:
                        newest_file_date = date_time
                    
                    if oldest_file_date is None or date_time < oldest_file_date:
                        oldest_file_date = date_time
                    
                    # Add file to listing (limit to first 100 files)
                    if len(metadata['file_listing']) < 100:
                        metadata['file_listing'].append({
                            'name': member.name,
                            'size': member.size,
                            'date': date_time.strftime('%Y-%m-%d %H:%M:%S'),
                            'type': tarfile.REGTYPE if member.isfile() else tarfile.DIRTYPE if member.isdir() else 'other'
                        })
                
                metadata['archive_metadata'] = {
                    'file_count': file_count,
                    'total_size': total_size,
                    'newest_file_date': newest_file_date.strftime('%Y-%m-%d %H:%M:%S') if newest_file_date else None,
                    'oldest_file_date': oldest_file_date.strftime('%Y-%m-%d %H:%M:%S') if oldest_file_date else None
                }
    
    except Exception as e:
        print(f"Error extracting archive metadata: {str(e)}")
    
    return metadata


def check_malicious_patterns(file_content, file_type):
    """Check for known malicious patterns in file content with improved accuracy"""
    results = {
        'malicious_patterns_found': False,
        'detected_patterns': [],
        'suspicious_string_count': 0,
        'warnings': []
    }
    
    try:
        # For PDF files, we need special handling to avoid false positives
        if file_type == 'application/pdf':
            # Common legitimate PDF features that shouldn't trigger alerts
            legitimate_pdf_features = [
                b'/JavaScript', b'/JS',  # PDFs can legitimately contain JavaScript
                b'/OpenAction',          # Used for legitimate opening actions
                b'/Launch',              # Can be legitimate in enterprise PDFs
                b'/URL'                  # Normal hyperlinks
            ]
            
            # Only check for truly suspicious combinations
            suspicious_pdf_patterns = [
                (b'/JavaScript', b'/AA', b'/OpenAction'),  # Auto-executing JS
                (b'/JavaScript', b'/Launch'),              # JS launching something
                (b'/JS', b'/RichMedia'),                   # JS with rich media (often exploits)
                (b'/ObjStm', b'/JavaScript'),              # Obfuscated JS in object stream
                (b'/URI', b'/S', b'/Launch')               # URI launching actions
            ]
            
            for pattern_combo in suspicious_pdf_patterns:
                if all(p in file_content for p in pattern_combo):
                    results['malicious_patterns_found'] = True
                    results['detected_patterns'].append("Suspicious PDF structure")
                    results['warnings'].append(f"PDF contains potentially dangerous combination: {[p.decode('utf-8', errors='ignore') for p in pattern_combo]}")
            
            # Check for specific malicious PDF techniques
            if b'/JBIG2Decode' in file_content and b'/JavaScript' in file_content:
                results['malicious_patterns_found'] = True
                results['detected_patterns'].append("PDF with JBIG2 + JavaScript (potential CVE exploit)")
                results['warnings'].append("PDF contains JBIG2 decoder with JavaScript (commonly used in exploits)")
        
        # For executable files, maintain stricter checking
        elif file_type in ['application/x-msdownload', 'application/x-executable', 'application/x-mach-binary']:
            # It's normal for executables to contain these patterns, so look for combinations
            suspicious_count = 0
            
            suspicious_patterns = [
                (b'URLDownloadToFile', b'ShellExecute'),
                (b'CreateProcess', b'WriteProcessMemory'),
                (b'VirtualAlloc', b'WriteProcessMemory'),
                (b'CreateRemoteThread', b'LoadLibrary'),
                (b'GetProcAddress', b'VirtualProtect', b'WriteProcessMemory')
            ]
            
            for pattern_combo in suspicious_patterns:
                if all(p in file_content for p in pattern_combo):
                    suspicious_count += 1
                    results['warnings'].append(f"Executable contains potentially suspicious API combination: {[p.decode('utf-8', errors='ignore') for p in pattern_combo]}")
            
            # Only mark as malicious if multiple suspicious patterns are found
            if suspicious_count >= 2:
                results['malicious_patterns_found'] = True
                results['detected_patterns'].append("Multiple suspicious code patterns")
        
        # For Office documents, check for macros and suspicious content
        elif file_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                          'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']:
            
            # Check for macros with suspicious functions
            macro_indicators = [b'AutoOpen', b'AutoExec', b'AutoClose', b'Document_Open', b'Workbook_Open']
            suspicious_functions = [b'Shell', b'WScript.Shell', b'powershell', b'cmd.exe', b'CreateObject', b'ActiveXObject']
            
            has_macros = b'VBA' in file_content or any(m in file_content for m in macro_indicators)
            has_suspicious_functions = any(f in file_content for f in suspicious_functions)
            
            if has_macros and has_suspicious_functions:
                results['malicious_patterns_found'] = True
                results['detected_patterns'].append("Office document with suspicious macros")
                results['warnings'].append("Document contains macros with potentially dangerous functions")
            elif has_macros:
                # Just having macros isn't necessarily malicious, just suspicious
                results['warnings'].append("Document contains macros - use caution when enabling")
        
        # For script files, check for obfuscation and suspicious patterns
        elif file_type in ['text/javascript', 'application/x-python', 'application/x-php', 'application/x-shellscript']:
            # Look for obfuscation techniques
            obfuscation_patterns = [
                (b'eval', b'fromCharCode'),
                (b'eval', b'unescape'),
                (b'eval', b'atob'),
                (b'document.write', b'unescape'),
                (b'base64_decode', b'eval'),
                (b'gzinflate', b'base64_decode')
            ]
            
            for pattern_combo in obfuscation_patterns:
                if all(p in file_content for p in pattern_combo):
                    results['malicious_patterns_found'] = True
                    results['detected_patterns'].append("Obfuscated script code")
                    results['warnings'].append(f"Script contains obfuscation techniques: {[p.decode('utf-8', errors='ignore') for p in pattern_combo]}")
        
        # For all other file types, use a more relaxed approach
        else:
            # Only check for very specific malicious signatures
            high_confidence_signatures = [
                b'TVqQAAMAAAAEAAAA',  # MZ header in base64
                b'TVpQAAIAAAAEAA8A',  # MZ header variant in base64
                b'TVoAAAAAAAAAAAAA',  # MZ header variant in base64
                b'UEsDBAoAAAAAAOCjZ',  # PK header with specific pattern
                b'<script>evil',
                b'<script>alert',
                b'wget http',
                b'curl http',
                b'nc -e /bin/sh'
            ]
            
            for signature in high_confidence_signatures:
                if signature in file_content:
                    results['malicious_patterns_found'] = True
                    results['detected_patterns'].append("High confidence malicious pattern")
                    results['warnings'].append(f"File contains known malicious pattern: {signature.decode('utf-8', errors='ignore')}")
    
    except Exception as e:
        print(f"Error checking malicious patterns: {str(e)}")
    
    return results

def check_steganography(file_content, file_type):
    """Check for potential steganography in the file"""
    results = {
        'potential_steganography': False,
        'stego_details': None,
        'extracted_hidden_content': None
    }
    
    # Only check for steganography in images, PDFs, and audio files
    if file_type.startswith('image/') or file_type == 'application/pdf' or file_type.startswith('audio/'):
        try:
            # For images
            if file_type.startswith('image/'):
                try:
                    img = Image.open(BytesIO(file_content))
                    
                    # Try LSB steganography extraction first
                    extracted_text = extract_lsb_steganography(img)
                    if extracted_text:
                        results['potential_steganography'] = True
                        results['stego_details'] = "Hidden text detected using LSB steganography"
                        results['extracted_hidden_content'] = extracted_text
                        return results
                    
                    # If no text found, check for unusual patterns that indicate steganography
                    has_unusual = has_unusual_bit_distribution(img)
                    if has_unusual:
                        results['potential_steganography'] = True
                        results['stego_details'] = "Unusual bit distribution detected, possible steganography"
                        results['extracted_hidden_content'] = "Could not extract hidden content automatically, but unusual patterns detected. Try specialized tools for extraction."
                        return results
                    
                    # Look for EXIF-based steganography
                    exif_data = check_exif_steganography(file_content)
                    if exif_data:
                        results['potential_steganography'] = True
                        results['stego_details'] = "Hidden data found in EXIF metadata"
                        results['extracted_hidden_content'] = exif_data
                        return results
                    
                    
                except Exception as e:
                    print(f"Error analyzing image for steganography: {str(e)}")
            
            # For PDFs
            elif file_type == 'application/pdf':
                # Try to extract and analyze PDF for actual steganography
                try:
                    with BytesIO(file_content) as f:
                        from PyPDF2 import PdfReader
                        pdf = PdfReader(f)
                        
                        # Check for hidden objects in PDF
                        hidden_content = check_pdf_for_hidden_objects(pdf)
                        if hidden_content:
                            results['potential_steganography'] = True
                            results['stego_details'] = "Hidden content detected in PDF"
                            results['extracted_hidden_content'] = hidden_content
                            return results
                        
                        # Check for JavaScript that might hide content
                        js_content = extract_pdf_javascript(pdf)
                        if js_content and ('eval(' in js_content or 'unescape(' in js_content):
                            results['potential_steganography'] = True
                            results['stego_details'] = "Potentially obfuscated JavaScript in PDF"
                            results['extracted_hidden_content'] = js_content[:1000] + "..."
                            return results
                except Exception as e:
                    print(f"Error analyzing PDF for steganography: {str(e)}")
                
        except Exception as e:
            print(f"Error in steganography check: {str(e)}")
    
    return results

def check_exif_steganography(file_content):
    """Check for steganography in EXIF metadata"""
    try:
        with BytesIO(file_content) as f:
            tags = exifread.process_file(f)
            
            # Look for unusually large comment or user comment fields
            for tag in tags:
                if 'comment' in tag.lower() or 'user' in tag.lower():
                    value = str(tags[tag])
                    if len(value) > 100:  # Long comment may contain hidden data
                        return f"Large data found in EXIF tag {tag}: {value[:100]}..."
            
            # Look for unusual EXIF tags
            unusual_tags = []
            for tag in tags:
                if tag.startswith('Unknown '):
                    unusual_tags.append(f"{tag}: {str(tags[tag])}")
            
            if unusual_tags:
                return "Unusual EXIF tags found:\n" + "\n".join(unusual_tags)
        
        return None
    except:
        return None

def extract_lsb_steganography(img):
    """Extract hidden text using LSB steganography method"""
    try:
        # First try with stegano library if available
        try:
            import stegano
            from stegano import lsb
            
            hidden_text = lsb.reveal(img)
            
            if hidden_text and isinstance(hidden_text, str) and len(hidden_text.strip()) > 0:
                return hidden_text
        except ImportError:
            print("Stegano library not available, using basic LSB extraction")
            pass
        
        # Fall back to basic implementation
        return basic_lsb_extraction(img)
    except Exception as e:
        print(f"Error in LSB steganography extraction: {str(e)}")
        return None
    
def basic_lsb_extraction(img):
    """Enhanced basic LSB extraction implementation"""
    try:
        # Convert image to RGB if it's not already
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        pixels = list(img.getdata())
        total_pixels = len(pixels)
        
        # Sample more pixels for better detection
        sample_size = min(total_pixels, 5000)  # Check up to 5000 pixels
        
        # Take a distributed sample
        step = max(1, total_pixels // sample_size)
        sampled_pixels = [pixels[i] for i in range(0, total_pixels, step)][:sample_size]
        
        binary_string = ''
        
        # Extract the least significant bit from each color channel
        for pixel in sampled_pixels:
            for color in pixel:
                binary_string += str(color & 1)  # Get LSB
        
        # Try to convert binary to text
        text = ''
        for i in range(0, len(binary_string) - 7, 8):
            byte = binary_string[i:i+8]
            char_code = int(byte, 2)
            if 32 <= char_code <= 126:  # Printable ASCII
                text += chr(char_code)
            else:
                text += '.'
        
        # Check if the text contains enough printable characters to be meaningful
        printable_ratio = sum(c.isprintable() and c != '.' for c in text) / len(text) if text else 0
        if printable_ratio > 0.7 and len(text) > 10:  # At least 70% printable and 10+ chars
            return text[:1000]  # Limit to 1000 chars
            
        return None
    except Exception as e:
        print(f"Error in basic LSB extraction: {str(e)}")
        return None
    
def has_unusual_bit_distribution(img):
    """Enhanced check for unusual patterns in the LSBs"""
    try:
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        pixels = list(img.getdata())
        total_pixels = len(pixels)
        
        # Sample more pixels
        sample_size = min(total_pixels, 10000)  # Use up to 10,000 pixels
        
        # Take a distributed sample
        step = max(1, total_pixels // sample_size)
        sampled_pixels = [pixels[i] for i in range(0, total_pixels, step)][:sample_size]
        
        lsbs = []
        for pixel in sampled_pixels:
            for color in pixel:
                lsbs.append(color & 1)
        
        # Count zeros and ones
        zeros = lsbs.count(0)
        ones = lsbs.count(1)
        
        # In natural images, LSBs should be roughly 50/50
        # A significant deviation could indicate steganography
        if zeros == 0 or ones == 0:
            return True  # All 0s or all 1s is very suspicious
            
        ratio = min(zeros, ones) / max(zeros, ones)
        return ratio < 0.4  # More strict threshold
    except:
        return False

    
def check_pdf_for_hidden_objects(pdf):
    """Check for hidden objects in PDF"""
    try:
        hidden_content = []
        
        # Check for metadata
        if pdf.documentInfo:
            for key, value in pdf.documentInfo.items():
                if len(str(value)) > 100:  # Long metadata could hide information
                    hidden_content.append(f"Suspicious metadata in {key}: {str(value)[:100]}...")
        
        # Check for attachments
        if '/EmbeddedFiles' in pdf.trailer['/Root']:
            hidden_content.append("PDF contains embedded files")
        
        return "\n".join(hidden_content) if hidden_content else None
    except:
        return None

def extract_pdf_javascript(pdf):
    """Extract JavaScript from PDF"""
    try:
        js_content = []
        
        # Try to get JavaScript from document
        for js in pdf.getJSObject():
            js_content.append(str(js))
        
        return "\n".join(js_content) if js_content else None
    except:
        return None

def check_code_injection(file_content, file_type):
    """Check for code injection in various file types with improved accuracy"""
    results = {
        'code_injection_detected': False,
        'injection_details': None,
        'warnings': [],
        'confidence': 0
    }
    
    try:
        # Check for code injection based on file type
        if file_type == 'application/pdf':
            # More nuanced PDF analysis
            js_indicators = [b'/JavaScript', b'/JS']
            action_indicators = [b'/OpenAction', b'/AA', b'/Launch']
            
            # Count indicators
            js_count = sum(1 for indicator in js_indicators if indicator in file_content)
            action_count = sum(1 for indicator in action_indicators if indicator in file_content)
            
            # JavaScript alone isn't necessarily malicious in PDFs
            if js_count > 0 and action_count > 0:
                # Only if JavaScript is combined with auto-actions
                results['code_injection_detected'] = True
                results['confidence'] = 70
                results['injection_details'] = "JavaScript with automatic actions in PDF"
                results['warnings'].append("PDF contains JavaScript with automatic actions which may be malicious")
            elif b'/EmbeddedFile' in file_content and b'/Launch' in file_content:
                results['code_injection_detected'] = True
                results['confidence'] = 75
                results['injection_details'] = "PDF contains embedded files with launch actions"
                results['warnings'].append("PDF contains embedded files with launch actions which may be malicious")
        
        elif file_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
            # More nuanced Office document analysis
            macro_indicators = [b'VBA', b'macro', b'Module1', b'ThisDocument', b'AutoOpen', b'Document_Open']
            suspicious_functions = [b'Shell', b'WScript.Shell', b'CreateObject', b'ActiveXObject']
            
            # Count indicators
            macro_count = sum(1 for indicator in macro_indicators if indicator in file_content)
            suspicious_count = sum(1 for func in suspicious_functions if func in file_content)
            
            # Only flag if both macros and suspicious functions are present
            if macro_count >= 2 and suspicious_count >= 1:
                results['code_injection_detected'] = True
                results['confidence'] = 65
                results['injection_details'] = "Office document contains macros with suspicious functions"
                results['warnings'].append("Document contains macros with potentially malicious functions")
        
        elif file_type.startswith('image/'):
            # More precise image analysis
            if file_type == 'image/svg+xml':
                # SVG can contain JavaScript
                if b'<script' in file_content:
                    script_content = file_content[file_content.find(b'<script'):file_content.find(b'</script>')]
                    # Only flag if script contains suspicious patterns
                    suspicious_js = [b'eval(', b'document.location', b'window.location', b'XMLHttpRequest']
                    if any(pattern in script_content for pattern in suspicious_js):
                        results['code_injection_detected'] = True
                        results['confidence'] = 80
                        results['injection_details'] = "SVG image contains suspicious JavaScript"
                        results['warnings'].append("SVG image contains potentially malicious JavaScript")
            
            # For other image formats, only flag if clearly unusual
            elif b'<script' in file_content[:1000] or b'eval(' in file_content[:1000]:
                # Scripts near the beginning of image files are very suspicious
                results['code_injection_detected'] = True
                results['confidence'] = 90
                results['injection_details'] = "Image file contains code in header area"
                results['warnings'].append("Image file contains unusual code which may be malicious")
        
        elif file_type.startswith('text/html'):
            # More sophisticated HTML analysis
            obfuscation_patterns = [
                (b'eval', b'unescape'),
                (b'document.write', b'fromCharCode'),
                (b'String.fromCharCode', b'eval'),
                (b'atob', b'eval')
            ]
            
            # Look for combinations of suspicious patterns
            for pattern_pair in obfuscation_patterns:
                if all(p in file_content for p in pattern_pair):
                    results['code_injection_detected'] = True
                    results['confidence'] = 75
                    results['injection_details'] = "Obfuscated JavaScript detected"
                    results['warnings'].append("HTML contains obfuscated JavaScript which may be malicious")
                    break
    
    except Exception as e:
        print(f"Error checking code injection: {str(e)}")
    
    return results

def format_file_size(size_bytes):
    """Format file size in bytes to human-readable format"""
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

def generate_pdf_report(request):
    """Generate a PDF report of a file scan"""
    scan_id = request.GET.get('scan_id')
    
    try:
        # Get the file check record
        file_check = FileCheck.objects.get(scan_id=scan_id)
        
        # Get the scan results and metadata
        result = FileCheckResult.objects.get(file_check=file_check)
        metadata = FileScanMetadata.objects.get(file_check=file_check)
        
        # Prepare the report data
        report_data = {
            'file_name': file_check.file_name,
            'file_size': format_file_size(file_check.file_size),
            'file_type': file_check.file_type,
            'scan_date': file_check.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'safety_rating': result.safety_rating,
            'status': "Malicious" if result.is_malicious else "Safe" if result.safety_rating >= 80 else "Suspicious",
            'is_malicious': result.is_malicious,
            'warnings': result.warnings,
            'comments': result.comments,
            'hash_md5': result.hash_md5,
            'hash_sha1': result.hash_sha1,
            'hash_sha256': result.hash_sha256,
            'metadata': metadata.metadata,
            'creation_time': metadata.creation_time.strftime('%Y-%m-%d %H:%M:%S') if metadata.creation_time else "Unknown",
            'modification_time': metadata.modification_time.strftime('%Y-%m-%d %H:%M:%S') if metadata.modification_time else "Unknown",
        }
        
        # Create the template context
        context = {
            'report': report_data,
            'generated_date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Create the PDF
        template = get_template('services/file_report_pdf.html')
        html = template.render(context)
        result_file = BytesIO()
        pdf = pisa.pisaDocument(BytesIO(html.encode("UTF-8")), result_file)
        
        if not pdf.err:
            # Create response with PDF content
            response = HttpResponse(result_file.getvalue(), content_type='application/pdf')
            
            # Generate filename based on the file name and current date
            date_str = datetime.datetime.now().strftime('%Y%m%d')
            safe_filename = re.sub(r'[^a-zA-Z0-9_-]', '_', file_check.file_name)
            filename = f"VAST_File_Report_{safe_filename}_{date_str}.pdf"
            
            # Add Content-Disposition header to force download
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            
            return response
        
        return HttpResponse('Error generating PDF report', status=500)
    
    except FileCheck.DoesNotExist:
        return HttpResponse('File scan not found', status=404)
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return HttpResponse(f'Error generating report: {str(e)}', status=500)

def get_file_report(request):
    """Get the results of a file scan"""
    scan_id = request.GET.get('scan_id')
    
    try:
        # Get the file check record
        file_check = FileCheck.objects.get(scan_id=scan_id)
        
        # Get the scan results and metadata
        result = FileCheckResult.objects.get(file_check=file_check)
        metadata = FileScanMetadata.objects.get(file_check=file_check)
        
        # Prepare the response data
        response_data = {
            'success': True,
            'file_name': file_check.file_name,
            'file_size': file_check.file_size,
            'formatted_file_size': format_file_size(file_check.file_size),
            'file_type': file_check.file_type,
            'scan_date': file_check.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'safety_rating': result.safety_rating,
            'status': "Malicious" if result.is_malicious else "Safe" if result.safety_rating >= 80 else "Suspicious",
            'is_malicious': result.is_malicious,
            'warnings': result.warnings,
            'comments': result.comments,
            'hashes': {
                'md5': result.hash_md5,
                'sha1': result.hash_sha1,
                'sha256': result.hash_sha256
            },
            'metadata': metadata.metadata,
            'creation_time': metadata.creation_time.strftime('%Y-%m-%d %H:%M:%S') if metadata.creation_time else None,
            'modification_time': metadata.modification_time.strftime('%Y-%m-%d %H:%M:%S') if metadata.modification_time else None,
            'access_time': metadata.access_time.strftime('%Y-%m-%d %H:%M:%S') if metadata.access_time else None,
        }
        
        return JsonResponse(response_data)
    
    except FileCheck.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'File scan not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Error retrieving scan results: {str(e)}'}, status=500)
