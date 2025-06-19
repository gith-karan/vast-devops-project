from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.utils import timezone
from .models import User, OTP
from .utils import send_otp_email
from services.email_views import check_email_format, check_disposable_email, check_low_quality_email, check_mx_records

def send_otp(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        if not email:
            return JsonResponse({'status': 'error', 'message': 'Email is required'})
        
        if not check_email_format(email):
            return JsonResponse({'status': 'error', 'message': 'Invalid email format'})
        
        domain = email.split('@')[-1]
        mx_records = check_mx_records(domain)
        if not mx_records:
            return JsonResponse({'status': 'error', 'message': 'Please use a different email address'})
        
        if check_disposable_email(domain):
            return JsonResponse({'status': 'error', 'message': 'Please use a different email address'})
        
        if check_low_quality_email(email):
            return JsonResponse({'status': 'error', 'message': 'Please use a different email address'})
        
        otp, message = OTP.generate_otp(email)
        
        if not otp:
            return JsonResponse({'status': 'error', 'message': message})
        
        try:
            send_otp_email(email, otp)
            return JsonResponse({'status': 'success', 'message': 'OTP sent successfully'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': f'Failed to send OTP: {str(e)}'})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request'})

def verify_otp(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        otp = request.POST.get('otp')
        
        if not email or not otp:
            return JsonResponse({'status': 'error', 'message': 'Email and OTP are required'})
        
        try:
            otp_obj = OTP.objects.get(email=email)
            
            if otp_obj.is_locked():
                lockout_seconds = int(otp_obj.get_lockout_time())
                lockout_minutes = lockout_seconds // 60
                return JsonResponse({
                    'status': 'error', 
                    'message': f'Account locked due to too many failed attempts. Please try again in {lockout_minutes} minutes.'
                })
            
            if not otp_obj.is_valid():
                return JsonResponse({'status': 'error', 'message': 'OTP has expired'})
            
            if otp_obj.otp != otp:
                otp_obj.increment_failed_attempts()
                return JsonResponse({'status': 'error', 'message': 'Invalid OTP'})
            
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    'username': email.split('@')[0],
                    'date_joined': timezone.now(),
                    'login_count': 0
                }
            )
            
            user.last_login = timezone.now()
            user.login_count = user.login_count + 1 if hasattr(user, 'login_count') else 1
            user.save()
            
            request.session['user_email'] = email
            request.session['user_id'] = user.user_id
            request.session['just_logged_in'] = True
            
            otp_obj.delete()
            
            return JsonResponse({'status': 'success', 'message': 'Login successful'})
            
        except OTP.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Invalid OTP'})
        
    return JsonResponse({'status': 'error', 'message': 'Invalid request'})

def login_page(request):
    if request.session.get('user_email'):
        return redirect('home')
    return render(request, 'login.html')

def home(request):
    context = {
        'is_guest': True
    }
    
    if request.session.get('user_email'):
        user_email = request.session.get('user_email')
        try:
            user = User.objects.get(email=user_email)
            context = {
                'username': user.username,
                'email': user.email,
                'is_guest': False,
                'joined_date': user.date_joined
            }
            
            if request.session.get('just_logged_in'):
                if user.login_count == 1:
                    context['welcome_message'] = f"Welcome {user.username}!"
                else:
                    context['welcome_message'] = f"Welcome back, {user.username}!"
                
                request.session['just_logged_in'] = False
                request.session.modified = True
                
        except User.DoesNotExist:
            pass
    
    return render(request, 'home.html', context)

def logout(request):
    request.session.flush()
    return redirect('accounts:login')

def about(request):
    context = {
        'is_guest': True
    }
    
    if request.session.get('user_email'):
        user_email = request.session.get('user_email')
        try:
            user = User.objects.get(email=user_email)
            context = {
                'username': user.username,
                'email': user.email,
                'is_guest': False,
                'joined_date': user.date_joined
            }
            
            if request.session.get('just_logged_in'):
                if user.login_count == 1:
                    context['welcome_message'] = f"Welcome {user.username}!"
                else:
                    context['welcome_message'] = f"Welcome back, {user.username}!"
                
                request.session['just_logged_in'] = False
                request.session.modified = True
                
        except User.DoesNotExist:
            pass
    
    return render(request, 'about.html', context)

def contact(request):
    context = {
        'is_guest': True
    }
    
    if request.session.get('user_email'):
        user_email = request.session.get('user_email')
        try:
            user = User.objects.get(email=user_email)
            context = {
                'username': user.username,
                'email': user.email,
                'is_guest': False,
                'joined_date': user.date_joined
            }
            
            if request.session.get('just_logged_in'):
                if user.login_count == 1:
                    context['welcome_message'] = f"Welcome {user.username}!"
                else:
                    context['welcome_message'] = f"Welcome back, {user.username}!"
                
                request.session['just_logged_in'] = False
                request.session.modified = True
                
        except User.DoesNotExist:
            pass
    
    return render(request, 'contact.html', context)