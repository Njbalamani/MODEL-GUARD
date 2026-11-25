from django.conf import settings
from django.db import models


class AuditLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="audit_logs")
    action = models.CharField(max_length=120, db_index=True)
    object_type = models.CharField(max_length=80, blank=True)
    object_id = models.CharField(max_length=80, blank=True)
    detail = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["action", "created_at"])]

    def __str__(self):
        return f"{self.action} at {self.created_at.isoformat()}"


def log_action(user, action, object_type="", object_id="", detail=None, ip_address=None):
    return AuditLog.objects.create(
        user=user,
        action=action,
        object_type=object_type,
        object_id=str(object_id or ""),
        detail=detail or {},
        ip_address=ip_address,
    )


class WebhookEndpoint(models.Model):
    name = models.CharField(max_length=160)
    url = models.URLField(max_length=500)
    secret = models.CharField(max_length=200)
    events = models.JSONField(default=list, blank=True)
    active = models.BooleanField(default=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="webhook_endpoints")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["active", "created_at"])]

    def __str__(self):
        return f"{self.name} ({self.url})"


class WebhookDelivery(models.Model):
    endpoint = models.ForeignKey(WebhookEndpoint, on_delete=models.CASCADE, related_name="deliveries")
    event = models.CharField(max_length=120, db_index=True)
    status = models.CharField(max_length=20, default="PENDING")
    response_code = models.IntegerField(null=True, blank=True)
    error = models.TextField(blank=True)
    payload = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["endpoint", "created_at"])]

    def __str__(self):
        return f"{self.event} -> {self.status}"
