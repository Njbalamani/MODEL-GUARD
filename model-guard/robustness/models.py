from django.db import models


class RobustnessTest(models.Model):
    class Status(models.TextChoices):
        COMPLETED = "COMPLETED", "Completed"
        UNSUPPORTED = "UNSUPPORTED", "Unsupported"
        FAILED = "FAILED", "Failed"

    assessment = models.ForeignKey("assessments.SecurityAssessment", on_delete=models.CASCADE, related_name="robustness_tests")
    attack = models.CharField(max_length=30)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.COMPLETED)
    epsilon = models.FloatField(default=0.0)
    steps = models.PositiveIntegerField(default=1)
    step_size = models.FloatField(default=0.0)
    samples = models.PositiveIntegerField(default=0)
    original_accuracy = models.FloatField(null=True, blank=True)
    perturbed_accuracy = models.FloatField(null=True, blank=True)
    accuracy_drop = models.FloatField(null=True, blank=True)
    mean_confidence_drop = models.FloatField(null=True, blank=True)
    mean_l2_perturbation = models.FloatField(null=True, blank=True)
    limitations = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["assessment", "attack"], name="uniq_assessment_attack")]
        indexes = [models.Index(fields=["assessment", "attack"])]

    def __str__(self):
        return f"{self.attack} robustness"
