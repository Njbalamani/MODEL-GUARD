from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views.generic import DetailView, FormView, ListView

from analysis.diff_engine import compare_assessments
from analysis.tasks import dispatch_assessment
from assessments.models import SecurityAssessment
from audit.models import log_action
from modelregistry.forms import ModelUploadForm
from modelregistry.models import ModelVersion, UploadedModel
from modelregistry.services import validate_and_store
from projects.models import Project
from projects.permissions import project_access


def accessible_models(user):
    if user.is_superuser or user.role == "ADMIN":
        return UploadedModel.objects.all()
    return UploadedModel.objects.filter(Q(project__owner=user) | Q(project__members__user=user)).distinct()


class ModelListView(LoginRequiredMixin, ListView):
    model = UploadedModel
    template_name = "modelregistry/list.html"
    context_object_name = "models"

    def get_queryset(self):
        return accessible_models(self.request.user).select_related("project")


class ModelUploadView(LoginRequiredMixin, FormView):
    template_name = "modelregistry/upload.html"
    form_class = ModelUploadForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        project = form.cleaned_data["project"]
        project_access(self.request.user, project, write=True)
        uploaded = form.cleaned_data["file"]
        with transaction.atomic():
            model, _ = UploadedModel.objects.get_or_create(
                project=project,
                name=form.cleaned_data["model_name"],
                defaults={"description": form.cleaned_data["description"], "created_by": self.request.user},
            )
            result = validate_and_store(
                uploaded,
                uploaded.name,
                model.pk,
                form.cleaned_data["version_label"],
            )
            version = ModelVersion.objects.create(
                model=model,
                version_label=form.cleaned_data["version_label"],
                file=result["stored_name"],
                original_name=result["original_name"],
                sha256=result["sha256"],
                size_bytes=result["size_bytes"],
                file_format=result["file_format"],
                is_descriptor=result["is_descriptor"],
                metadata=result["metadata"],
                uploaded_by=self.request.user,
            )
            assessment = SecurityAssessment.objects.create(
                model_version=version,
                project=project,
                triggered_by=self.request.user,
            )
            log_action(self.request.user, "model.uploaded", "ModelVersion", version.pk, {"sha256": version.sha256})
        dispatch_assessment(assessment.pk)
        return HttpResponseRedirect(reverse("assessments:detail", kwargs={"pk": assessment.pk}))


class ModelDetailView(LoginRequiredMixin, DetailView):
    model = UploadedModel
    template_name = "modelregistry/detail.html"
    context_object_name = "model"

    def get_queryset(self):
        return accessible_models(self.request.user)


class VersionDetailView(LoginRequiredMixin, DetailView):
    model = ModelVersion
    template_name = "modelregistry/version_detail.html"
    context_object_name = "version"

    def get_queryset(self):
        ids = accessible_models(self.request.user).values_list("id", flat=True)
        return ModelVersion.objects.filter(model_id__in=ids).select_related("model")


@login_required
def start_assessment(request, version_id):
    version = get_object_or_404(
        ModelVersion,
        pk=version_id,
        model_id__in=accessible_models(request.user).values_list("id", flat=True),
    )
    project_access(request.user, version.model.project, write=True)
    assessment = SecurityAssessment.objects.create(
        model_version=version,
        project=version.model.project,
        triggered_by=request.user,
    )
    log_action(request.user, "assessment.queued", "SecurityAssessment", assessment.pk)
    dispatch_assessment(assessment.pk)
    return HttpResponseRedirect(reverse("assessments:detail", kwargs={"pk": assessment.pk}))


@login_required
def compare_versions(request, pk):
    model = get_object_or_404(accessible_models(request.user), pk=pk)
    versions = model.versions.select_related("model").order_by("-created_at")
    comparison = None
    error = ""
    previous_id = request.GET.get("previous")
    current_id = request.GET.get("current")
    if previous_id and current_id:
        if previous_id == current_id:
            error = "Select two different versions."
        else:
            try:
                previous = versions.get(pk=previous_id).assessments.filter(
                    status=SecurityAssessment.Status.COMPLETED
                ).order_by("-created_at").first()
                current = versions.get(pk=current_id).assessments.filter(
                    status=SecurityAssessment.Status.COMPLETED
                ).order_by("-created_at").first()
                if not previous or not current:
                    error = "Both selected versions need a completed assessment."
                else:
                    comparison = compare_assessments(previous, current)
            except (ValueError, ModelVersion.DoesNotExist):
                error = "Invalid version selection."
    return render(request, "modelregistry/compare.html", {
        "model": model,
        "versions": versions,
        "comparison": comparison,
        "error": error,
        "previous_id": previous_id,
        "current_id": current_id,
    })
