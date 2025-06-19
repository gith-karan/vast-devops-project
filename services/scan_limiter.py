from django.http import JsonResponse
from django.utils import timezone
import hashlib
from django.core.cache import cache

class ScanLimiter:
    
    GUEST_DAILY_LIMIT = 3
    REGISTERED_USER_DAILY_LIMIT = None  #can change later
    
    @staticmethod
    def get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    @staticmethod
    def get_identifier(request):
        is_logged_in = bool(request.session.get('user_id'))
        
        if is_logged_in:
            return f"user_{request.session.get('user_id')}"
        else:
            ip = ScanLimiter.get_client_ip(request)
            day_key = timezone.now().strftime('%Y-%m-%d')
            return f"ip_{hashlib.md5(f'{ip}|{day_key}'.encode()).hexdigest()}"
    
    @staticmethod
    def check_limit(request, scan_type):
        is_logged_in = bool(request.session.get('user_id'))
        
        limit = ScanLimiter.REGISTERED_USER_DAILY_LIMIT if is_logged_in else ScanLimiter.GUEST_DAILY_LIMIT
        
        if limit is None:
            return True, None, None
        
        identifier = ScanLimiter.get_identifier(request)
        cache_key = f"{scan_type}_limit_{identifier}"
        
        count = cache.get(cache_key, 0)
        
        if count >= limit:
            message = "Daily scan limit reached."
            if not is_logged_in:
                message += " Please log in to perform more scans."
            return False, message, 0
        
        count += 1
        seconds_until_midnight = (24 - timezone.now().hour) * 3600 - timezone.now().minute * 60
        cache.set(cache_key, count, timeout=seconds_until_midnight)
        
        remaining = limit - count
        return True, None, remaining