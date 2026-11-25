from django.contrib import admin

from modelregistry.models import ModelVersion, UploadedModel


@admin.register(UploadedModel)
class UploadedModelAdmin(admin.ModelAdmin):
    list_display = ("name", "project", "created_by", "created_at")
    search_fields = ("name", "project__name")


@admin.register(ModelVersion)
class ModelVersionAdmin(admin.ModelAdmin):
    list_display = ("model", "version_label", "file_format", "status", "sha256", "created_at")
    list_filter = ("status", "file_format", "is_descriptor")
    search_fields = ("model__name", "original_name", "sha256")
    readonly_fields = ("sha256", "size_bytes", "file_format", "is_descriptor", "metadata")
