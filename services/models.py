# from django.db import models

# Create your models here.
from django.db import models
from django.utils import timezone

#email scanner models
class EmailCheck(models.Model):
    email = models.EmailField(max_length=255)
    is_valid = models.BooleanField(default=False)
    is_disposable = models.BooleanField(default=False)
    domain_type = models.CharField(max_length=50, default='unknown')  # personal, business, etc.
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.email

class EmailCheckResult(models.Model):
    email_check = models.OneToOneField(EmailCheck, on_delete=models.CASCADE, related_name='result')
    safety_rating = models.IntegerField(default=0)  # 0-100 safety rating
    comments = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return f"Result for {self.email_check.email}"

class DisposableDomain(models.Model):
    """Model to store discovered disposable domains"""
    domain = models.CharField(max_length=255, unique=True)
    date_added = models.DateTimeField(auto_now_add=True)
    confidence_score = models.FloatField(default=1.0)
    
    def __str__(self):
        return self.domain
    
class SpamDatabaseEntry(models.Model):
    """Model to store domains/IPs found in spam databases"""
    identifier = models.CharField(max_length=255, unique=True)  # Domain or IP
    is_domain = models.BooleanField(default=True)  # True if domain, False if IP
    blacklists = models.JSONField(default=list)  # List of blacklists where it was found
    last_checked = models.DateTimeField(default=timezone.now)
    score = models.FloatField(default=0.0)  # Spam score based on number of blacklists
    
    def __str__(self):
        return f"{self.identifier} ({len(self.blacklists) if isinstance(self.blacklists, list) else 0} listings)"

#URL scanner models
class URLCheck(models.Model):
    url = models.URLField(max_length=2000)
    final_url = models.URLField(max_length=2000, null=True, blank=True)
    is_valid = models.BooleanField(default=False)
    is_malicious = models.BooleanField(default=False)
    has_ssl = models.BooleanField(default=False)
    is_shortened = models.BooleanField(default=False)
    domain = models.CharField(max_length=255)
    timestamp = models.DateTimeField(default=timezone.now)
    user_id = models.CharField(max_length=255, null=True, blank=True)
    
    def __str__(self):
        return self.url

class URLCheckResult(models.Model):
    url_check = models.OneToOneField(URLCheck, on_delete=models.CASCADE, related_name='result')
    safety_rating = models.IntegerField(default=0)  # 0-100 safety rating
    ssl_info = models.JSONField(null=True, blank=True)
    domain_age_days = models.IntegerField(null=True, blank=True)
    domain_info = models.JSONField(null=True, blank=True)
    comments = models.TextField(blank=True, null=True)
    warnings = models.JSONField(default=list)
    ip_info = models.JSONField(null=True, blank=True)
    hosting_info = models.JSONField(null=True, blank=True)
    discovered_content = models.JSONField(null=True, blank=True)
    
    def __str__(self):
        return f"Result for {self.url_check.url}"

class URLRedirect(models.Model):
    url_check = models.ForeignKey(URLCheck, on_delete=models.CASCADE, related_name='redirects')
    order = models.IntegerField()
    redirect_url = models.URLField(max_length=2000)
    status_code = models.IntegerField(null=True, blank=True)
    
    class Meta:
        ordering = ['order']
    
    def __str__(self):
        return f"Redirect {self.order} for {self.url_check.url}"

class TrackerDetection(models.Model):
    url_check = models.ForeignKey(URLCheck, on_delete=models.CASCADE, related_name='trackers')
    tracker_name = models.CharField(max_length=255)
    tracker_type = models.CharField(max_length=100)  # analytics, advertising, social
    script_url = models.URLField(max_length=2000, null=True, blank=True)
    
    def __str__(self):
        return f"{self.tracker_name} on {self.url_check.url}"
    

#file scanner models
class FileCheck(models.Model):
    file_name = models.CharField(max_length=255)
    file_size = models.BigIntegerField()  # Size in bytes
    file_type = models.CharField(max_length=255)  # MIME type
    detected_extension = models.CharField(max_length=20, blank=True, null=True)
    is_malicious = models.BooleanField(default=False)
    timestamp = models.DateTimeField(default=timezone.now)
    user_id = models.CharField(max_length=255, null=True, blank=True)
    scan_id = models.CharField(max_length=36, unique=True)  # UUID for referencing the scan

    def __str__(self):
        return f"{self.file_name} ({self.file_type})"

class FileCheckResult(models.Model):
    file_check = models.OneToOneField(FileCheck, on_delete=models.CASCADE, related_name='result')
    safety_rating = models.IntegerField(default=0)  # 0-100 safety rating
    is_malicious = models.BooleanField(default=False)
    comments = models.TextField(blank=True, null=True)
    warnings = models.JSONField(default=list)
    hash_md5 = models.CharField(max_length=32, blank=True, null=True)
    hash_sha1 = models.CharField(max_length=40, blank=True, null=True)
    hash_sha256 = models.CharField(max_length=64, blank=True, null=True)
    
    def __str__(self):
        return f"Result for {self.file_check.file_name}"

class FileScanMetadata(models.Model):
    file_check = models.OneToOneField(FileCheck, on_delete=models.CASCADE, related_name='metadata')
    metadata = models.JSONField(default=dict)  # Extracted metadata
    creation_time = models.DateTimeField(null=True, blank=True)
    modification_time = models.DateTimeField(null=True, blank=True)
    access_time = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"Metadata for {self.file_check.file_name}"

#feedback model
class Feedback(models.Model):
    user_id = models.IntegerField(blank=True, null=True)  # Replace email field with user_id
    feedback_text = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return f"Feedback at {self.timestamp}"