from django.urls import path
from . import views
from . import feedback

app_name = 'services'

urlpatterns = [
    path('email/', views.email_scanner_view, name='email_scanner'),
    path('email/validate/', views.validate_email, name='validate_email'),
    path('email/generate-pdf/', views.generate_pdf_report, name='generate_pdf_report'),
    # path('email/feedback/', views.feedback_submit, name='email_feedback'),

    path('url/', views.url_scanner_view, name='url_scanner'),
    path('url/validate/', views.validate_url, name='validate_url'),
    path('url/generate-pdf/', views.generate_url_pdf, name='generate_url_pdf'),

    path('file/', views.file_scanner_view, name='file_scanner'),
    path('file/scan/', views.scan_file, name='scan_file'),
    path('file/generate-pdf/', views.generate_file_pdf, name='generate_file_pdf'),
    path('file/report/', views.get_file_report, name='get_file_report'),

    path('feedback/submit/', feedback.handle_feedback_submission, name='feedback_submit'),

    path('network/', views.network_scanner_view, name='network_scanner'),
]   