from django.contrib import admin

from explainability.models import ExplainabilityResult


@admin.register(ExplainabilityResult)
class ExplainabilityResultAdmin(admin.ModelAdmin):
    list_display = ("assessment", "method", "status", "created_at")
    list_filter = ("method", "status")
