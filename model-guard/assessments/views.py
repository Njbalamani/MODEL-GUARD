from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.generic import DetailView, ListView

from analysis.tasks import dispatch_assessment
from assessments.forms import AssessmentCommentForm, RescanScheduleForm, SuppressionRequestForm
from assessments.models import (
    AssessmentComment,
    FindingSuppression,
    RescanSchedule,
    SecurityAssessment,
)
from assessments.services import activate_suppression, recalculate_assessment, revoke_suppression
from audit.models import log_action
from audit.notifications import notify
from modelregistry.models import ModelVersion
from projects.permissions import accessible_project_ids, project_access


def _is_admin(user):
    return user.is_superuser or getattr(user, "role", "") == "ADMIN"


class AssessmentListView(LoginRequiredMixin, ListView):
    model = SecurityAssessment
    template_name = "assessments/list.html"
    context_object_name = "assessments"

    def get_queryset(self):
        return SecurityAssessment.objects.filter(
            project_id__in=accessible_project_ids(self.request.user)
        ).select_related("model_version", "project").order_by("-created_at")


class AssessmentDetailView(LoginRequiredMixin, DetailView):
    model = SecurityAssessment
    template_name = "assessments/detail.html"
    context_object_name = "assessment"

    def get_queryset(self):
        return SecurityAssessment.objects.filter(
            project_id__in=accessible_project_ids(self.request.user)
        ).select_related(
            "model_version", "model_version__model", "project", "triggered_by"
        ).prefetch_related(
            "findings__suppressions", "robustness_tests", "reports", "comments",
            "drift_results", "policy_evaluations__policy",
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["comment_form"] = AssessmentCommentForm()
        context["can_administer"] = _is_admin(self.request.user)
        return context


@login_required
def requeue_assessment(request, pk):
    assessment = get_object_or_404(
        SecurityAssessment,
        pk=pk,
        project_id__in=accessible_project_ids(request.user),
    )
    project_access(request.user, assessment.project, write=True)
    assessment.status = SecurityAssessment.Status.PENDING
    assessment.error = ""
    assessment.summary = {}
    assessment.save(update_fields=["status", "error", "summary"])
    log_action(request.user, "assessment.requeued", "SecurityAssessment", assessment.pk)
    dispatch_assessment(assessment.pk)
    return HttpResponseRedirect(reverse("assessments:detail", kwargs={"pk": assessment.pk}))


@login_required
def request_suppression(request, finding_id):
    from assessments.models import VulnerabilityFinding

    finding = get_object_or_404(
        VulnerabilityFinding,
        pk=finding_id,
        assessment__project_id__in=accessible_project_ids(request.user),
    )
    project_access(request.user, finding.assessment.project, write=True)
    if request.method == "POST":
        form = SuppressionRequestForm(request.POST)
        if form.is_valid():
            suppression = form.save(commit=False)
            suppression.finding = finding
            suppression.requested_by = request.user
            if _is_admin(request.user):
                activate_suppression(suppression, request.user)
            else:
                suppression.save()
            log_action(request.user, "suppression.requested", "VulnerabilityFinding", finding.pk)
            if suppression.status == FindingSuppression.Status.ACTIVE:
                log_action(request.user, "suppression.approved", "FindingSuppression", suppression.pk)
                notify("suppression.approved", {
                    "suppression_id": suppression.pk,
                    "finding_id": finding.pk,
                    "expires_at": suppression.expires_at.isoformat() if suppression.expires_at else None,
                })
            recalculate_assessment(finding.assessment)
            messages.success(request, "Suppression submitted.")
            return redirect("assessments:detail", pk=finding.assessment_id)
    else:
        form = SuppressionRequestForm()
    return render(request, "assessments/suppress.html", {"form": form, "finding": finding})


@login_required
def approve_suppression(request, pk):
    suppression = get_object_or_404(
        FindingSuppression,
        pk=pk,
        finding__assessment__project_id__in=accessible_project_ids(request.user),
    )
    if not _is_admin(request.user):
        messages.error(request, "Administrator role required.")
        return redirect("assessments:detail", pk=suppression.finding.assessment_id)
    activate_suppression(suppression, request.user)
    log_action(request.user, "suppression.approved", "FindingSuppression", suppression.pk)
    notify("suppression.approved", {
        "suppression_id": suppression.pk,
        "finding_id": suppression.finding_id,
        "expires_at": suppression.expires_at.isoformat() if suppression.expires_at else None,
    })
    recalculate_assessment(suppression.finding.assessment)
    return redirect("assessments:detail", pk=suppression.finding.assessment_id)


@login_required
def revoke_suppression(request, pk):
    suppression = get_object_or_404(
        FindingSuppression,
        pk=pk,
        finding__assessment__project_id__in=accessible_project_ids(request.user),
    )
    if not _is_admin(request.user):
        messages.error(request, "Administrator role required.")
        return redirect("assessments:detail", pk=suppression.finding.assessment_id)
    revoke_suppression(suppression)
    log_action(request.user, "suppression.revoked", "FindingSuppression", suppression.pk)
    recalculate_assessment(suppression.finding.assessment)
    return redirect("assessments:detail", pk=suppression.finding.assessment_id)


@login_required
def add_comment(request, pk):
    assessment = get_object_or_404(
        SecurityAssessment,
        pk=pk,
        project_id__in=accessible_project_ids(request.user),
    )
    project_access(request.user, assessment.project, write=True)
    if request.method == "POST":
        form = AssessmentCommentForm(request.POST)
        if form.is_valid():
            comment = form.save(commit=False)
            comment.assessment = assessment
            comment.user = request.user
            comment.save()
            log_action(request.user, "comment.created", "SecurityAssessment", assessment.pk)
            return redirect("assessments:detail", pk=assessment.pk)
    return redirect("assessments:detail", pk=assessment.pk)


class RescanScheduleListView(LoginRequiredMixin, ListView):
    template_name = "assessments/schedules.html"
    context_object_name = "schedules"

    def get_queryset(self):
        return RescanSchedule.objects.filter(
            project_id__in=accessible_project_ids(self.request.user)
        ).select_related("model_version", "project").order_by("next_run_at")


@login_required
def create_rescan_schedule(request, version_id):
    from modelregistry.views import accessible_models

    version = get_object_or_404(
        ModelVersion,
        pk=version_id,
        model_id__in=accessible_models(request.user).values_list("id", flat=True),
    )
    project_access(request.user, version.model.project, write=True)
    if request.method == "POST":
        form = RescanScheduleForm(request.POST)
        if form.is_valid():
            schedule = form.save(commit=False)
            schedule.model_version = version
            schedule.project = version.model.project
            schedule.created_by = request.user
            schedule.save()
            log_action(request.user, "rescan.scheduled", "RescanSchedule", schedule.pk)
            messages.success(request, "Rescan schedule created.")
            return redirect("assessments:schedules")
    else:
        form = RescanScheduleForm(initial={"interval_minutes": 1440, "enabled": True})
    return render(request, "assessments/schedule_form.html", {"form": form, "version": version})


@login_required
def toggle_rescan_schedule(request, pk):
    schedule = get_object_or_404(
        RescanSchedule,
        pk=pk,
        project_id__in=accessible_project_ids(request.user),
    )
    project_access(request.user, schedule.project, write=True)
    schedule.enabled = not schedule.enabled
    schedule.save(update_fields=["enabled", "updated_at"])
    log_action(request.user, "rescan.toggled", "RescanSchedule", schedule.pk)
    return redirect("assessments:schedules")


@login_required
def delete_rescan_schedule(request, pk):
    schedule = get_object_or_404(
        RescanSchedule,
        pk=pk,
        project_id__in=accessible_project_ids(request.user),
    )
    project_access(request.user, schedule.project, write=True)
    schedule.delete()
    log_action(request.user, "rescan.deleted", "RescanSchedule", pk)
    return redirect("assessments:schedules")
