import os

from django.conf import settings
from django.db import models


def reference_upload_path(instance, filename):
    safe_name = os.path.basename(filename).replace(" ", "_")
    return f"references/{instance.project_id}/{safe_name}"


class Project(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="projects")
    name = models.CharField(max_length=160)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["owner", "name"], name="uniq_project_owner_name")]
        indexes = [models.Index(fields=["owner", "created_at"])]

    def __str__(self):
        return self.name


class ProjectMember(models.Model):
    class Role(models.TextChoices):
        OWNER = "OWNER", "Owner"
        ADMIN = "ADMIN", "Admin"
        MEMBER = "MEMBER", "Member"
        VIEWER = "VIEWER", "Viewer"

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="members")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="project_memberships")
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.MEMBER)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "user"], name="uniq_project_member")]
        indexes = [models.Index(fields=["project", "role"])]

    def __str__(self):
        return f"{self.user.username} - {self.project.name}"


class DeploymentPolicy(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="policies")
    name = models.CharField(max_length=160)
    max_risk_score = models.IntegerField(default=30)
    blocked_severities = models.JSONField(default=list, blank=True)
    require_report = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="deployment_policies")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "name"], name="uniq_policy_project_name")]
        indexes = [models.Index(fields=["project", "enabled"])]

    def __str__(self):
        return f"{self.name} ({self.project.name})"


class PolicyEvaluation(models.Model):
    class Result(models.TextChoices):
        PASS = "PASS", "Pass"
        FAIL = "FAIL", "Fail"

    policy = models.ForeignKey(DeploymentPolicy, on_delete=models.CASCADE, related_name="evaluations")
    assessment = models.ForeignKey("assessments.SecurityAssessment", on_delete=models.CASCADE, related_name="policy_evaluations")
    result = models.CharField(max_length=10, choices=Result.choices)
    reasons = models.JSONField(default=list, blank=True)
    evaluated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["policy", "created_at"]), models.Index(fields=["assessment", "result"])]

    def __str__(self):
        return f"{self.result} {self.policy.name}"


class ReferenceDataset(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="reference_datasets")
    name = models.CharField(max_length=160)
    file = models.FileField(upload_to=reference_upload_path)
    feature_names = models.JSONField(default=list, blank=True)
    rows = models.PositiveIntegerField(default=0)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="reference_datasets")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["project", "name"], name="uniq_reference_project_name")]
        indexes = [models.Index(fields=["project", "created_at"])]

    def __str__(self):
        return f"{self.name} ({self.project.name})"
