import json
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import Feedback
from django.utils import timezone

def handle_feedback_submission(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    feedback_text = request.POST.get('feedback', '').strip()
    
    if not feedback_text:
        return JsonResponse({'error': 'Please enter feedback'}, status=400)
    
    # Check if user is logged in
    if not request.session.get('user_id'):
        return JsonResponse({
            'error': 'login_required',
            'message': 'Please log in to submit feedback'
        }, status=403)
    
    try:
        from accounts.models import User
        user_id = request.session.get('user_id')
        user = User.objects.get(user_id=user_id)
        
        feedback = Feedback.objects.create(
            user_id=user_id,
            feedback_text=feedback_text,
            timestamp=timezone.now()
        )
        
        return JsonResponse({
            'success': True, 
            'message': 'Thank you for your feedback!'
        })
    except Exception as e:
        print(f"Error saving feedback: {str(e)}")
        return JsonResponse({
            'error': f'Error saving feedback: {str(e)}'
        }, status=500)