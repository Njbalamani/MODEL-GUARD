from django import forms

from modelregistry.models import UploadedModel


class ModelUploadForm(forms.Form):
    project = forms.ModelChoiceField(queryset=UploadedModel._meta.get_field("project").related_model.objects.none())
    model_name = forms.CharField(max_length=200)
    version_label = forms.CharField(max_length=80, initial="v1")
    description = forms.CharField(widget=forms.Textarea(attrs={"rows": 3}), required=False)
    file = forms.FileField()

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if user is not None:
            from projects.permissions import accessible_project_ids
            from projects.models import Project

            self.fields["project"].queryset = Project.objects.filter(id__in=accessible_project_ids(user))
