from django.db import models


class PrivacyAssessment(models.Model):
    class Status(models.TextChoices):
        COMPLETED = "COMPLETED", "Completed"
        UNSUPPORTED = "UNSUPPORTED", "Unsupported"
        FAILED = "FAILED", "Failed"

    assessment = models.OneToOneField("assessments.SecurityAssessment", on_delete=models.CASCADE, related_name="privacy")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.COMPLETED)
    method = models.CharField(max_length=80, default="train-vs-holdout-confidence-gap")
    train_confidence = models.FloatField(null=True, blank=True)
    holdout_confidence = models.FloatField(null=True, blank=True)
    confidence_gap = models.FloatField(null=True, blank=True)
    indicator = models.BooleanField(default=False)
    limitations = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Privacy assessment ({self.status})"
