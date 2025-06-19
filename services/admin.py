# from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import EmailCheck, EmailCheckResult, Feedback


class EmailCheckResultInline(admin.StackedInline):
    model = EmailCheckResult
    can_delete = False

@admin.register(EmailCheck)
class EmailCheckAdmin(admin.ModelAdmin):
    list_display = ('email', 'is_valid', 'is_disposable', 'domain_type', 'timestamp')
    search_fields = ('email',)
    list_filter = ('is_valid', 'is_disposable', 'domain_type')
    inlines = [EmailCheckResultInline]

@admin.register(Feedback)
class FeedbackAdmin(admin.ModelAdmin):
    list_display = ('user_id', 'timestamp')
    search_fields = ('user_id', 'feedback_text')
    list_filter = ('timestamp',)