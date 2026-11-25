from django.contrib import admin

from privacy.models import PrivacyAssessment


@admin.register(PrivacyAssessment)
class PrivacyAssessmentAdmin(admin.ModelAdmin):
    list_display = ("assessment", "status", "method", "indicator", "confidence_gap", "created_at")
    list_filter = ("status", "indicator")
