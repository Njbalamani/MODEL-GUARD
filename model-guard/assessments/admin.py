from django.contrib import admin

from assessments.models import (
    AssessmentComment, FindingSuppression, RescanSchedule, SecurityAssessment,
    VulnerabilityFinding,
)


@admin.register(SecurityAssessment)
class SecurityAssessmentAdmin(admin.ModelAdmin):
    list_display = ("id", "model_version", "project", "status", "risk_score", "created_at")
    list_filter = ("status",)
    search_fields = ("model_version__model__name", "project__name")
    readonly_fields = ("risk_score", "summary", "error")


@admin.register(VulnerabilityFinding)
class VulnerabilityFindingAdmin(admin.ModelAdmin):
    list_display = ("title", "severity", "category", "assessment", "source")
    list_filter = ("severity", "category", "source")
    search_fields = ("title", "description")


@admin.register(FindingSuppression)
class FindingSuppressionAdmin(admin.ModelAdmin):
    list_display = ("finding", "status", "requested_by", "approved_by", "expires_at")
    list_filter = ("status",)
    search_fields = ("finding__title", "reason")


@admin.register(AssessmentComment)
class AssessmentCommentAdmin(admin.ModelAdmin):
    list_display = ("assessment", "user", "created_at")
    search_fields = ("body", "user__username")


@admin.register(RescanSchedule)
class RescanScheduleAdmin(admin.ModelAdmin):
    list_display = ("model_version", "project", "interval_minutes", "enabled", "next_run_at")
    list_filter = ("enabled",)
