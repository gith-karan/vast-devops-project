from django.db import models
from django.utils import timezone
import random
from datetime import timedelta

class User(models.Model):
    user_id = models.AutoField(primary_key=True)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=100)
    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(null=True, blank=True)
    login_count = models.IntegerField(default=0)
    # feedback = models.TextField(null=True, blank=True)
    
    def save(self, *args, **kwargs):
        if not self.username and self.email:
            self.username = self.email.split('@')[0]
        super().save(*args, **kwargs)
    
    def __str__(self):
        return self.email

class OTP(models.Model):
    email = models.EmailField(max_length=255)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    failed_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    
    def is_valid(self):
        return (self.created_at + timedelta(minutes=5) >= timezone.now() and 
                (self.locked_until is None or self.locked_until <= timezone.now()))
    
    def is_locked(self):
        return self.locked_until is not None and self.locked_until > timezone.now()
    
    def get_lockout_time(self):
        if self.is_locked():
            return (self.locked_until - timezone.now()).total_seconds()
        return 0
        
    def increment_failed_attempts(self):
        self.failed_attempts += 1
        if self.failed_attempts >= 5:
            lockout_multiplier = (self.failed_attempts - 1) // 5
            lockout_minutes = 3 * (2 ** lockout_multiplier)
            self.locked_until = timezone.now() + timedelta(minutes=lockout_minutes)
            self.failed_attempts = 0
        self.save()
    
    @classmethod
    def generate_otp(cls, email):
        recent_otps = cls.objects.filter(
            email=email, 
            created_at__gte=timezone.now() - timedelta(minutes=2)
        ).count()
        
        if recent_otps >= 3:
            return None, "Too many OTP requests. Please wait for 2 minutes before trying again."
        
        otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        
        cls.objects.filter(email=email).delete()
        
        otp_obj = cls.objects.create(email=email, otp=otp)
        return otp, "OTP generated successfully"
    


# #to clean up accounts_otp table increament id

# # add this in accounts/models.py
# @classmethod
# def cleanup_and_reset_ids(cls):
#     """Periodically clean up expired OTPs and reset ID sequence"""
#     from django.db import connection
#     from django.utils import timezone
    
#     # Delete expired OTPs (older than 10 minutes)
#     expired_time = timezone.now() - timezone.timedelta(minutes=10)
#     cls.objects.filter(created_at__lt=expired_time).delete()
    
#     # If using PostgreSQL
#     with connection.cursor() as cursor:
#         try:
#             # Check the database type
#             if connection.vendor == 'postgresql':
#                 cursor.execute("SELECT setval(pg_get_serial_sequence('accounts_otp', 'id'), 1, false);")
#             elif connection.vendor == 'sqlite':
#                 cursor.execute("DELETE FROM sqlite_sequence WHERE name='accounts_otp';")
#             elif connection.vendor == 'mysql':
#                 cursor.execute("ALTER TABLE accounts_otp AUTO_INCREMENT = 1;")
#         except Exception as e:
#             print(f"Error resetting OTP ID sequence: {e}")


# # Then modify the OTP verification function in accounts/views.py to call this cleanup occasionally:
# def verify_otp(request):
#     # Existing code...
    
#     # Add this section near the end, where otp_obj is deleted
#     if random.random() < 0.1:  # 10% chance to run cleanup
#         OTP.cleanup_and_reset_ids()
        
#     # Rest of the existing code...