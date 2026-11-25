from django import forms

from audit.models import WebhookEndpoint
from audit.notifications import WEBHOOK_EVENTS, WebhookValidationError, validate_webhook_url


class WebhookEndpointForm(forms.ModelForm):
    events = forms.MultipleChoiceField(choices=[(item, item) for item in WEBHOOK_EVENTS])

    class Meta:
        model = WebhookEndpoint
        fields = ["name", "url", "secret", "events", "active"]
        widgets = {"secret": forms.PasswordInput(render_value=True)}

    def clean_url(self):
        value = self.cleaned_data["url"]
        try:
            return validate_webhook_url(value)
        except WebhookValidationError as exc:
            raise forms.ValidationError(str(exc)) from exc
