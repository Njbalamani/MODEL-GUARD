from django.db import models


class DataDriftResult(models.Model):
    class Status(models.TextChoices):
        STABLE = "STABLE", "Stable"
        WATCH = "WATCH", "Watch"
        DRIFT = "DRIFT", "Drift"

    assessment = models.ForeignKey("assessments.SecurityAssessment", on_delete=models.CASCADE, related_name="drift_results")
    feature = models.CharField(max_length=160)
    psi = models.FloatField()
    threshold = models.FloatField()
    status = models.CharField(max_length=20, choices=Status.choices)
    reference_source = models.CharField(max_length=160, default="synthetic-baseline")
    limitations = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["assessment", "feature"], name="uniq_drift_assessment_feature")]
        indexes = [models.Index(fields=["assessment", "status"])]

    def __str__(self):
        return f"{self.feature} drift ({self.status})"
