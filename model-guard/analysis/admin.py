from django.contrib import admin

from analysis.models import DataDriftResult


@admin.register(DataDriftResult)
class DataDriftResultAdmin(admin.ModelAdmin):
    list_display = ("assessment", "feature", "psi", "status", "reference_source")
    list_filter = ("status",)
    search_fields = ("feature", "reference_source")
