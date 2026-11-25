import os

from django.conf import settings
from django.db import models


def report_upload_path(instance, filename):
    safe_name = os.path.basename(filename).replace(" ", "_")
    return f"reports/{instance.assessment.project_id}/{instance.assessment_id}/{safe_name}"


class GeneratedReport(models.Model):
    assessment = models.ForeignKey("assessments.SecurityAssessment", on_delete=models.CASCADE, related_name="reports")
    report_type = models.CharField(max_length=60, default="security-assessment")
    file = models.FileField(upload_to=report_upload_path)
    sha256 = models.CharField(max_length=64, db_index=True)
    format = models.CharField(max_length=10, default="pdf")
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="generated_reports")
    signature = models.CharField(max_length=512, blank=True)
    signature_algorithm = models.CharField(max_length=40, default="HMAC-SHA256")
    signed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["assessment", "created_at"])]

    def __str__(self):
        return f"Report #{self.pk}"
