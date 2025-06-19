from django.core.mail import send_mail
from django.conf import settings

def send_otp_email(email, otp):
    subject = 'V.A.S.T. - Your OTP for Login'
    message = f'Your OTP for login is: {otp}. This OTP is valid for 5 minutes.'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]
    
    send_mail(subject, message, from_email, recipient_list)