from django.conf import settings
from django.db import models
from django.db.models import Q


class SecurityAssessment(models.Model):
    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        RUNNING = "RUNNING", "Running"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"

    model_version = models.ForeignKey("modelregistry.ModelVersion", on_delete=models.CASCADE, related_name="assessments")
    project = models.ForeignKey("projects.Project", on_delete=models.CASCADE, related_name="assessments")
    triggered_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="assessments")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING, db_index=True)
    risk_score = models.IntegerField(default=0)
    summary = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True)
    engine_version = models.CharField(max_length=40, default="1.0.0")
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["project", "status"]), models.Index(fields=["model_version", "created_at"])]

    def __str__(self):
        return f"Assessment #{self.pk} - {self.model_version}"


class VulnerabilityFinding(models.Model):
    class Severity(models.TextChoices):
        CRITICAL = "CRITICAL", "Critical"
        HIGH = "HIGH", "High"
        MEDIUM = "MEDIUM", "Medium"
        LOW = "LOW", "Low"
        INFO = "INFO", "Informational"

    assessment = models.ForeignKey(SecurityAssessment, on_delete=models.CASCADE, related_name="findings")
    severity = models.CharField(max_length=20, choices=Severity.choices, db_index=True)
    category = models.CharField(max_length=80)
    title = models.CharField(max_length=240)
    description = models.TextField()
    evidence = models.JSONField(default=dict, blank=True)
    recommendation = models.TextField()
    confidence = models.CharField(max_length=20, default="MEDIUM")
    source = models.CharField(max_length=80, default="static-inspection")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["assessment", "severity"]), models.Index(fields=["category"])]
        ordering = ["-created_at"]

    def __str__(self):
        return self.title


class FindingSuppression(models.Model):
    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        ACTIVE = "ACTIVE", "Active"
        REVOKED = "REVOKED", "Revoked"
        EXPIRED = "EXPIRED", "Expired"

    finding = models.ForeignKey(VulnerabilityFinding, on_delete=models.CASCADE, related_name="suppressions")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    reason = models.TextField()
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="requested_suppressions")
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="approved_suppressions")
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["finding"],
                condition=Q(status="ACTIVE"),
                name="uniq_active_suppression_per_finding",
            )
        ]
        indexes = [models.Index(fields=["status", "expires_at"])]

    def __str__(self):
        return f"Suppression for {self.finding_id} ({self.status})"


class AssessmentComment(models.Model):
    assessment = models.ForeignKey(SecurityAssessment, on_delete=models.CASCADE, related_name="comments")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="assessment_comments")
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["assessment", "created_at"])]

    def __str__(self):
        return f"Comment by {self.user.username}"


class RescanSchedule(models.Model):
    model_version = models.ForeignKey("modelregistry.ModelVersion", on_delete=models.CASCADE, related_name="rescan_schedules")
    project = models.ForeignKey("projects.Project", on_delete=models.CASCADE, related_name="rescan_schedules")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="rescan_schedules")
    interval_minutes = models.PositiveIntegerField(default=1440)
    enabled = models.BooleanField(default=True)
    next_run_at = models.DateTimeField(db_index=True)
    last_run_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [models.Index(fields=["enabled", "next_run_at"])]

    def __str__(self):
        return f"Rescan {self.model_version} every {self.interval_minutes}m"
