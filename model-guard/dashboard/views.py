import json

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count
from django.http import JsonResponse
from django.views.generic import TemplateView

from assessments.models import SecurityAssessment, VulnerabilityFinding
from modelregistry.models import UploadedModel
from projects.models import Project
from projects.permissions import accessible_project_ids


class HomeView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/home.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        project_ids = accessible_project_ids(self.request.user)
        assessments = SecurityAssessment.objects.filter(project_id__in=project_ids)
        context["assessments"] = assessments.select_related("model_version", "project").order_by("-created_at")[:12]
        context["total_assessments"] = assessments.count()
        context["projects"] = Project.objects.filter(id__in=project_ids).count()
        context["models"] = UploadedModel.objects.filter(project_id__in=project_ids).count()
        context["completed"] = assessments.filter(status=SecurityAssessment.Status.COMPLETED).count()
        context["critical"] = VulnerabilityFinding.objects.filter(assessment__project_id__in=project_ids, severity="CRITICAL").count()
        context["high"] = VulnerabilityFinding.objects.filter(assessment__project_id__in=project_ids, severity="HIGH").count()
        context["severity_data"] = list(
            VulnerabilityFinding.objects.filter(assessment__project_id__in=project_ids)
            .values("severity").annotate(total=Count("id"))
        )
        latest = assessments.filter(explainability__isnull=False).order_by("-created_at").first()
        context["feature_json"] = json.dumps(
            (latest.explainability.feature_importances if latest else []) or []
        )
        return context


class ChartDataView(LoginRequiredMixin, TemplateView):
    def get(self, request, *args, **kwargs):
        project_ids = accessible_project_ids(request.user)
        assessments = SecurityAssessment.objects.filter(project_id__in=project_ids)
        severity = list(
            VulnerabilityFinding.objects.filter(assessment__project_id__in=project_ids)
            .values("severity").annotate(total=Count("id"))
        )
        timeline = list(
            assessments.order_by("created_at").values("created_at", "risk_score")
        )
        return JsonResponse({"severity": severity, "timeline": timeline})
