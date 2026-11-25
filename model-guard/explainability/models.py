from django.db import models


def explanation_plot_path(instance, filename):
    return f"explainability/{instance.assessment.project_id}/{instance.assessment_id}/{filename}"


class ExplainabilityResult(models.Model):
    class Status(models.TextChoices):
        COMPLETED = "COMPLETED", "Completed"
        FALLBACK = "FALLBACK", "Fallback"
        UNSUPPORTED = "UNSUPPORTED", "Unsupported"
        FAILED = "FAILED", "Failed"

    assessment = models.OneToOneField("assessments.SecurityAssessment", on_delete=models.CASCADE, related_name="explainability")
    method = models.CharField(max_length=60)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.COMPLETED)
    feature_importances = models.JSONField(default=list, blank=True)
    base_value = models.FloatField(null=True, blank=True)
    sample_prediction = models.FloatField(null=True, blank=True)
    limitations = models.JSONField(default=list, blank=True)
    plot_image = models.ImageField(upload_to=explanation_plot_path, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Explainability ({self.method})"
