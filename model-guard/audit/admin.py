from django.contrib import admin

from audit.models import AuditLog, WebhookDelivery, WebhookEndpoint


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("user", "action", "object_type", "object_id", "created_at")
    list_filter = ("action", "object_type")
    search_fields = ("action", "object_type", "user__username")
    readonly_fields = ("user", "action", "object_type", "object_id", "detail", "ip_address", "created_at")


@admin.register(WebhookEndpoint)
class WebhookEndpointAdmin(admin.ModelAdmin):
    list_display = ("name", "url", "active", "created_by", "created_at")
    list_filter = ("active",)
    search_fields = ("name", "url")


@admin.register(WebhookDelivery)
class WebhookDeliveryAdmin(admin.ModelAdmin):
    list_display = ("endpoint", "event", "status", "response_code", "created_at")
    list_filter = ("status", "event")
