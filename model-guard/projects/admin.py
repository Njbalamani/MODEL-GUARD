from django.contrib import admin

from projects.models import (
    DeploymentPolicy, PolicyEvaluation, Project, ProjectMember, ReferenceDataset,
)


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "created_at", "updated_at")
    list_filter = ("created_at",)
    search_fields = ("name", "owner__username")


@admin.register(ProjectMember)
class ProjectMemberAdmin(admin.ModelAdmin):
    list_display = ("project", "user", "role", "created_at")
    list_filter = ("role",)
    search_fields = ("project__name", "user__username")


@admin.register(DeploymentPolicy)
class DeploymentPolicyAdmin(admin.ModelAdmin):
    list_display = ("name", "project", "max_risk_score", "require_report", "enabled")
    list_filter = ("enabled", "require_report")
    search_fields = ("name", "project__name")


@admin.register(PolicyEvaluation)
class PolicyEvaluationAdmin(admin.ModelAdmin):
    list_display = ("policy", "assessment", "result", "created_at")
    list_filter = ("result",)


@admin.register(ReferenceDataset)
class ReferenceDatasetAdmin(admin.ModelAdmin):
    list_display = ("name", "project", "rows", "uploaded_by", "created_at")
    search_fields = ("name", "project__name")
