from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.views.generic import CreateView, DetailView, ListView

from assessments.models import SecurityAssessment
from audit.models import log_action
from projects.forms import DeploymentPolicyForm, ProjectForm, ReferenceDatasetForm
from projects.models import DeploymentPolicy, Project, ReferenceDataset
from projects.permissions import accessible_project_ids, project_access
from projects.services import evaluate_policy


class ProjectListView(LoginRequiredMixin, ListView):
    model = Project
    template_name = "projects/list.html"
    context_object_name = "projects"

    def get_queryset(self):
        if self.request.user.is_superuser or self.request.user.role == "ADMIN":
            return Project.objects.all()
        return Project.objects.filter(
            id__in=accessible_project_ids(self.request.user)
        ).distinct()


class ProjectCreateView(LoginRequiredMixin, CreateView):
    model = Project
    form_class = ProjectForm
    template_name = "projects/create.html"

    def form_valid(self, form):
        form.instance.owner = self.request.user
        response = super().form_valid(form)
        log_action(self.request.user, "project.created", "Project", self.object.pk)
        return response

    def get_success_url(self):
        return reverse_lazy("projects:detail", kwargs={"pk": self.object.pk})


class ProjectDetailView(LoginRequiredMixin, DetailView):
    model = Project
    template_name = "projects/detail.html"
    context_object_name = "project"

    def get_queryset(self):
        return Project.objects.filter(id__in=accessible_project_ids(self.request.user)).distinct()


class PolicyListView(LoginRequiredMixin, ListView):
    template_name = "projects/policies.html"
    context_object_name = "policies"

    def get_queryset(self):
        return DeploymentPolicy.objects.filter(
            project_id__in=accessible_project_ids(self.request.user)
        ).select_related("project").order_by("project__name", "name")


@login_required
def create_policy(request, project_id):
    project = get_object_or_404(Project, pk=project_id, id__in=accessible_project_ids(request.user))
    project_access(request.user, project, write=True)
    if request.method == "POST":
        form = DeploymentPolicyForm(request.POST)
        if form.is_valid():
            policy = form.save(commit=False)
            policy.project = project
            policy.created_by = request.user
            policy.save()
            log_action(request.user, "policy.created", "DeploymentPolicy", policy.pk)
            messages.success(request, "Deployment policy created.")
            return redirect("projects:policy-list")
    else:
        form = DeploymentPolicyForm(initial={"max_risk_score": 30, "enabled": True})
    return render(request, "projects/policy_form.html", {"form": form, "project": project})


@login_required
def policy_detail(request, pk):
    policy = get_object_or_404(
        DeploymentPolicy,
        pk=pk,
        project_id__in=accessible_project_ids(request.user),
    )
    evaluations = policy.evaluations.select_related("assessment", "evaluated_by").order_by("-created_at")[:50]
    assessments = SecurityAssessment.objects.filter(
        project=policy.project,
        status=SecurityAssessment.Status.COMPLETED,
    ).select_related("model_version").order_by("-created_at")[:50]
    return render(request, "projects/policy_detail.html", {
        "policy": policy,
        "evaluations": evaluations,
        "assessments": assessments,
    })


@login_required
def evaluate_policy_view(request, pk):
    policy = get_object_or_404(
        DeploymentPolicy,
        pk=pk,
        project_id__in=accessible_project_ids(request.user),
    )
    project_access(request.user, policy.project, write=True)
    assessment = get_object_or_404(
        SecurityAssessment,
        pk=request.POST.get("assessment_id"),
        project=policy.project,
    )
    result = evaluate_policy(policy, assessment, user=request.user)
    log_action(request.user, "policy.evaluated", "DeploymentPolicy", policy.pk, {
        "assessment_id": assessment.pk,
        "result": result["result"],
        "reasons": result["reasons"],
    })
    messages.success(
        request,
        f"Policy {policy.name}: {result['result']}" + (f" ({', '.join(result['reasons'])})" if result["reasons"] else ""),
    )
    return redirect("projects:policy-detail", pk=policy.pk)


class ReferenceDatasetListView(LoginRequiredMixin, ListView):
    template_name = "projects/reference_datasets.html"
    context_object_name = "datasets"

    def get_queryset(self):
        return ReferenceDataset.objects.filter(
            project_id__in=accessible_project_ids(self.request.user)
        ).select_related("project").order_by("-created_at")


@login_required
def upload_reference(request, project_id):
    project = get_object_or_404(Project, pk=project_id, id__in=accessible_project_ids(request.user))
    project_access(request.user, project, write=True)
    if request.method == "POST":
        form = ReferenceDatasetForm(request.POST, request.FILES)
        if form.is_valid():
            dataset = form.save(commit=False)
            dataset.project = project
            dataset.uploaded_by = request.user
            dataset.save()
            try:
                import pandas as pd

                frame = pd.read_csv(dataset.file.path)
                dataset.feature_names = list(frame.columns)
                dataset.rows = len(frame)
                dataset.save(update_fields=["feature_names", "rows"])
            except Exception as exc:
                dataset.delete()
                messages.error(request, f"Could not parse CSV: {exc}")
                return redirect("projects:reference-list")
            log_action(request.user, "reference.uploaded", "ReferenceDataset", dataset.pk)
            messages.success(request, "Reference dataset uploaded.")
            return redirect("projects:reference-list")
    else:
        form = ReferenceDatasetForm()
    return render(request, "projects/reference_upload.html", {"form": form, "project": project})
