import os

from django.conf import settings
from django.db import models


def model_upload_path(instance, filename):
    safe_name = os.path.basename(filename).replace(" ", "_")
    return f"models/{instance.model.project_id}/{instance.model_id}/{instance.version_label}/{safe_name}"


class UploadedModel(models.Model):
    project = models.ForeignKey("projects.Project", on_delete=models.CASCADE, related_name="models")
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="uploaded_models")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "name"], name="uniq_model_project_name")]
        indexes = [models.Index(fields=["project", "created_at"])]

    def __str__(self):
        return self.name

    @property
    def latest_version(self):
        return self.versions.order_by("-created_at").first()


class ModelVersion(models.Model):
    class Status(models.TextChoices):
        UPLOADED = "UPLOADED", "Uploaded"
        ANALYZING = "ANALYZING", "Analyzing"
        READY = "READY", "Ready"
        REJECTED = "REJECTED", "Rejected"

    model = models.ForeignKey(UploadedModel, on_delete=models.CASCADE, related_name="versions")
    version_label = models.CharField(max_length=80)
    file = models.FileField(upload_to=model_upload_path)
    original_name = models.CharField(max_length=300)
    sha256 = models.CharField(max_length=64, db_index=True)
    size_bytes = models.PositiveBigIntegerField()
    file_format = models.CharField(max_length=30, db_index=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.UPLOADED)
    is_descriptor = models.BooleanField(default=False)
    metadata = models.JSONField(default=dict, blank=True)
    notes = models.TextField(blank=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="model_versions")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["model", "version_label"], name="uniq_model_version_label")]
        indexes = [models.Index(fields=["model", "created_at"]), models.Index(fields=["file_format"])]

    def __str__(self):
        return f"{self.model.name} {self.version_label}"
