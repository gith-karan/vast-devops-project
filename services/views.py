from django.shortcuts import render
from . import email_views , url_views , file_views

#for email scanners
def email_scanner_view(request):
    return email_views.email_scanner_view(request)

def validate_email(request):
    return email_views.validate_email(request)

def generate_pdf_report(request):
    return email_views.generate_pdf_report(request)

def feedback_submit(request):
    return email_views.feedback_submit(request)

#for url scannrs 
def url_scanner_view(request):
    """Render the URL scanner page"""
    return url_views.url_scanner_view(request)

def validate_url(request):
    """Process URL validation request"""
    return url_views.validate_url(request)

def generate_url_pdf(request):
    """Generate PDF report for URL scan"""
    return url_views.generate_pdf_report(request)

#for file scanners
def file_scanner_view(request):
    """Render the file scanner page"""
    return file_views.file_scanner_view(request)

def scan_file(request):
    """Process file scanning request"""
    return file_views.scan_file(request)

def generate_file_pdf(request):
    """Generate PDF report for file scan"""
    return file_views.generate_pdf_report(request)

def get_file_report(request):
    """Get the results of a file scan"""
    return file_views.get_file_report(request)

#other scanners
def network_scanner_view(request):
    """Render the network scanner page"""
    return render(request, 'services/network.html')