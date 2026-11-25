from django import forms
from django.conf import settings
from django.utils import timezone

from assessments.models import AssessmentComment, FindingSuppression, RescanSchedule


class SuppressionRequestForm(forms.ModelForm):
    expires_at = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={"type": "datetime-local"}),
    )

    class Meta:
        model = FindingSuppression
        fields = ["reason", "expires_at"]

    def clean_expires_at(self):
        value = self.cleaned_data.get("expires_at")
        if value and value <= timezone.now():
            raise forms.ValidationError("Expiry must be in the future.")
        return value


class AssessmentCommentForm(forms.ModelForm):
    class Meta:
        model = AssessmentComment
        fields = ["body"]
        widgets = {"body": forms.Textarea(attrs={"rows": 3})}


class RescanScheduleForm(forms.ModelForm):
    class Meta:
        model = RescanSchedule
        fields = ["interval_minutes", "next_run_at", "enabled"]
        widgets = {"next_run_at": forms.DateTimeInput(attrs={"type": "datetime-local"})}

    def clean_interval_minutes(self):
        value = self.cleaned_data["interval_minutes"]
        minimum = max(1, settings.MG_RESCAN_MIN_INTERVAL_MINUTES)
        if value < minimum:
            raise forms.ValidationError(f"Interval must be at least {minimum} minutes.")
        return value
