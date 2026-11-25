from django.contrib import admin

from reports.models import GeneratedReport


@admin.register(GeneratedReport)
class GeneratedReportAdmin(admin.ModelAdmin):
    list_display = ("id", "assessment", "report_type", "format", "generated_by", "created_at")
    list_filter = ("format", "report_type")
    readonly_fields = ("sha256",)
