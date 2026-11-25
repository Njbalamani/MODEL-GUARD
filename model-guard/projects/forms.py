from django import forms

from projects.models import DeploymentPolicy, Project, ReferenceDataset

SEVERITY_CHOICES = [
    ("CRITICAL", "Critical"),
    ("HIGH", "High"),
    ("MEDIUM", "Medium"),
    ("LOW", "Low"),
    ("INFO", "Informational"),
]


class ProjectForm(forms.ModelForm):
    class Meta:
        model = Project
        fields = ["name", "description"]


class DeploymentPolicyForm(forms.ModelForm):
    blocked_severities = forms.MultipleChoiceField(choices=SEVERITY_CHOICES, required=False)

    class Meta:
        model = DeploymentPolicy
        fields = ["name", "max_risk_score", "blocked_severities", "require_report", "enabled"]


class ReferenceDatasetForm(forms.ModelForm):
    class Meta:
        model = ReferenceDataset
        fields = ["name", "file"]
