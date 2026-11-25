from django.conf import settings
from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response

from accounts.models import User
from analysis.models import DataDriftResult
from assessments.models import (
    AssessmentComment, FindingSuppression, RescanSchedule, SecurityAssessment,
    VulnerabilityFinding,
)
from audit.models import AuditLog, WebhookDelivery, WebhookEndpoint, log_action
from audit.notifications import WEBHOOK_EVENTS, WebhookValidationError, validate_webhook_url
from config.serializers import (
    AssessmentCommentSerializer, AuditLogSerializer, DataDriftResultSerializer,
    DeploymentPolicySerializer, ExplainabilityResultSerializer, FindingSuppressionSerializer,
    GeneratedReportSerializer, ModelVersionSerializer, PolicyEvaluationSerializer,
    PrivacyAssessmentSerializer, ProjectSerializer, ReferenceDatasetSerializer,
    RescanScheduleSerializer, RobustnessTestSerializer, SecurityAssessmentSerializer,
    UploadedModelSerializer, UserSerializer, VulnerabilityFindingSerializer,
    WebhookDeliverySerializer, WebhookEndpointSerializer,
)
from explainability.models import ExplainabilityResult
from modelregistry.models import ModelVersion, UploadedModel
from privacy.models import PrivacyAssessment
from projects.models import (
    DeploymentPolicy, PolicyEvaluation, Project, ReferenceDataset,
)
from projects.permissions import accessible_project_ids, project_access
from projects.services import evaluate_policy
from reports.models import GeneratedReport
from robustness.models import RobustnessTest

from analysis.tasks import dispatch_assessment
from assessments.services import activate_suppression, recalculate_assessment, revoke_suppression


def _is_admin(user):
    return user.is_superuser or getattr(user, "role", "") == "ADMIN"


class CurrentUserViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = UserSerializer

    def get_queryset(self):
        return User.objects.filter(pk=self.request.user.pk).order_by("-id")


class ProjectViewSet(viewsets.ModelViewSet):
    serializer_class = ProjectSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or user.role == User.Role.ADMIN:
            return Project.objects.all().order_by("-id")
        return Project.objects.filter(Q(owner=user) | Q(members__user=user)).distinct().order_by("-id")

    def perform_create(self, serializer):
        project = serializer.save(owner=self.request.user)
        log_action(self.request.user, "project.created", "Project", project.pk)


class UploadedModelViewSet(viewsets.ModelViewSet):
    serializer_class = UploadedModelSerializer

    def get_queryset(self):
        return UploadedModel.objects.filter(project_id__in=accessible_project_ids(self.request.user)).order_by("-id")

    def perform_create(self, serializer):
        project = serializer.validated_data["project"]
        project_access(self.request.user, project, write=True)
        model = serializer.save(created_by=self.request.user)
        log_action(self.request.user, "model.created", "UploadedModel", model.pk)


class ModelVersionViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ModelVersionSerializer

    def get_queryset(self):
        return ModelVersion.objects.filter(model__project_id__in=accessible_project_ids(self.request.user)).select_related("model").order_by("-id")


class SecurityAssessmentViewSet(viewsets.ModelViewSet):
    serializer_class = SecurityAssessmentSerializer

    def get_queryset(self):
        return SecurityAssessment.objects.filter(project_id__in=accessible_project_ids(self.request.user)).select_related("model_version").order_by("-id")

    def perform_create(self, serializer):
        project = serializer.validated_data["project"]
        project_access(self.request.user, project, write=True)
        assessment = serializer.save(triggered_by=self.request.user)
        dispatch_assessment(assessment.pk)
        log_action(self.request.user, "assessment.queued", "SecurityAssessment", assessment.pk)

    @action(detail=True, methods=["post"])
    def queue(self, request, pk=None):
        assessment = self.get_object()
        project_access(request.user, assessment.project, write=True)
        if assessment.status in {SecurityAssessment.Status.RUNNING, SecurityAssessment.Status.PENDING}:
            return Response({"detail": "Assessment is already queued or running."}, status=409)
        assessment.status = SecurityAssessment.Status.PENDING
        assessment.error = ""
        assessment.summary = {}
        assessment.save(update_fields=["status", "error", "summary"])
        dispatch_assessment(assessment.pk)
        log_action(request.user, "assessment.requeued", "SecurityAssessment", assessment.pk)
        return Response({"detail": "Assessment queued."})


class VulnerabilityFindingViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = VulnerabilityFindingSerializer

    def get_queryset(self):
        return VulnerabilityFinding.objects.filter(assessment__project_id__in=accessible_project_ids(self.request.user)).order_by("-id")


class RobustnessTestViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = RobustnessTestSerializer

    def get_queryset(self):
        return RobustnessTest.objects.filter(assessment__project_id__in=accessible_project_ids(self.request.user)).order_by("-id")


class ExplainabilityResultViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = ExplainabilityResultSerializer

    def get_queryset(self):
        return ExplainabilityResult.objects.filter(assessment__project_id__in=accessible_project_ids(self.request.user)).order_by("-id")


class PrivacyAssessmentViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = PrivacyAssessmentSerializer

    def get_queryset(self):
        return PrivacyAssessment.objects.filter(assessment__project_id__in=accessible_project_ids(self.request.user)).order_by("-id")


class GeneratedReportViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = GeneratedReportSerializer

    def get_queryset(self):
        return GeneratedReport.objects.filter(assessment__project_id__in=accessible_project_ids(self.request.user)).order_by("-id")


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AuditLogSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or user.role == User.Role.ADMIN:
            return AuditLog.objects.all().order_by("-id")
        return AuditLog.objects.filter(user=user).order_by("-id")


class FindingSuppressionViewSet(viewsets.ModelViewSet):
    serializer_class = FindingSuppressionSerializer

    def get_queryset(self):
        return FindingSuppression.objects.filter(
            finding__assessment__project_id__in=accessible_project_ids(self.request.user)
        ).select_related("finding").order_by("-id")

    def perform_create(self, serializer):
        finding = serializer.validated_data["finding"]
        project_access(self.request.user, finding.assessment.project, write=True)
        serializer.save(requested_by=self.request.user)

    @action(detail=True, methods=["post"])
    def approve(self, request, pk=None):
        suppression = self.get_object()
        if not _is_admin(request.user):
            raise PermissionDenied("Administrator role required.")
        project_access(request.user, suppression.finding.assessment.project, write=True)
        activate_suppression(suppression, request.user)
        recalculate_assessment(suppression.finding.assessment)
        log_action(request.user, "suppression.approved", "FindingSuppression", suppression.pk)
        return Response({"status": suppression.status})

    @action(detail=True, methods=["post"])
    def revoke(self, request, pk=None):
        suppression = self.get_object()
        if not _is_admin(request.user):
            raise PermissionDenied("Administrator role required.")
        project_access(request.user, suppression.finding.assessment.project, write=True)
        revoke_suppression(suppression)
        recalculate_assessment(suppression.finding.assessment)
        log_action(request.user, "suppression.revoked", "FindingSuppression", suppression.pk)
        return Response({"status": suppression.status})


class AssessmentCommentViewSet(viewsets.ModelViewSet):
    serializer_class = AssessmentCommentSerializer

    def get_queryset(self):
        return AssessmentComment.objects.filter(
            assessment__project_id__in=accessible_project_ids(self.request.user)
        ).select_related("user").order_by("-id")

    def perform_create(self, serializer):
        assessment = serializer.validated_data["assessment"]
        project_access(self.request.user, assessment.project, write=True)
        serializer.save(user=self.request.user)


class RescanScheduleViewSet(viewsets.ModelViewSet):
    serializer_class = RescanScheduleSerializer

    def get_queryset(self):
        return RescanSchedule.objects.filter(
            project_id__in=accessible_project_ids(self.request.user)
        ).select_related("model_version").order_by("-id")

    def perform_create(self, serializer):
        version = serializer.validated_data["model_version"]
        project_access(self.request.user, version.model.project, write=True)
        minimum = max(1, settings.MG_RESCAN_MIN_INTERVAL_MINUTES)
        if serializer.validated_data["interval_minutes"] < minimum:
            raise ValidationError({"interval_minutes": f"Must be at least {minimum} minutes."})
        serializer.save(project=version.model.project, created_by=self.request.user)


class DeploymentPolicyViewSet(viewsets.ModelViewSet):
    serializer_class = DeploymentPolicySerializer

    def get_queryset(self):
        return DeploymentPolicy.objects.filter(
            project_id__in=accessible_project_ids(self.request.user)
        ).select_related("project").order_by("-id")

    def perform_create(self, serializer):
        project = serializer.validated_data["project"]
        project_access(self.request.user, project, write=True)
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=["post"])
    def evaluate(self, request, pk=None):
        policy = self.get_object()
        project_access(request.user, policy.project, write=True)
        assessment = get_object_or_404(
            SecurityAssessment,
            pk=request.data.get("assessment_id"),
            project=policy.project,
        )
        result = evaluate_policy(policy, assessment, user=request.user)
        log_action(request.user, "policy.evaluated", "DeploymentPolicy", policy.pk, {
            "assessment_id": assessment.pk,
            "result": result["result"],
            "reasons": result["reasons"],
        })
        return Response({
            "result": result["result"],
            "passed": result["passed"],
            "reasons": result["reasons"],
        })


class PolicyEvaluationViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = PolicyEvaluationSerializer

    def get_queryset(self):
        return PolicyEvaluation.objects.filter(
            policy__project_id__in=accessible_project_ids(self.request.user)
        ).select_related("policy", "assessment").order_by("-id")


class ReferenceDatasetViewSet(viewsets.ModelViewSet):
    serializer_class = ReferenceDatasetSerializer

    def get_queryset(self):
        return ReferenceDataset.objects.filter(
            project_id__in=accessible_project_ids(self.request.user)
        ).select_related("project").order_by("-id")

    def perform_create(self, serializer):
        project = serializer.validated_data["project"]
        project_access(self.request.user, project, write=True)
        dataset = serializer.save(uploaded_by=self.request.user)
        try:
            import pandas as pd

            if dataset.file.size > settings.MG_MAX_UPLOAD_BYTES:
                raise ValueError("Reference dataset exceeds the upload size limit.")
            frame = pd.read_csv(dataset.file.path)
            dataset.feature_names = list(frame.columns)
            dataset.rows = len(frame)
            dataset.save(update_fields=["feature_names", "rows"])
        except Exception as exc:
            dataset.delete()
            raise ValidationError({"file": str(exc)}) from exc


class DataDriftResultViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = DataDriftResultSerializer

    def get_queryset(self):
        return DataDriftResult.objects.filter(
            assessment__project_id__in=accessible_project_ids(self.request.user)
        ).select_related("assessment").order_by("-id")


class WebhookEndpointViewSet(viewsets.ModelViewSet):
    serializer_class = WebhookEndpointSerializer

    def get_queryset(self):
        if not (self.request.user.is_superuser or getattr(self.request.user, "role", "") == "ADMIN"):
            return WebhookEndpoint.objects.none()
        return WebhookEndpoint.objects.all().select_related("created_by").order_by("-id")

    def _validate(self, serializer):
        url = serializer.validated_data.get("url")
        if url is not None:
            try:
                validate_webhook_url(url)
            except WebhookValidationError as exc:
                raise ValidationError({"url": str(exc)}) from exc
        if "events" in serializer.validated_data:
            events = serializer.validated_data.get("events") or []
            unknown = [item for item in events if item not in WEBHOOK_EVENTS]
            if unknown:
                raise ValidationError({"events": f"Unknown events: {unknown}"})

    def perform_create(self, serializer):
        if not _is_admin(self.request.user):
            raise PermissionDenied("Administrator role required.")
        self._validate(serializer)
        serializer.save(created_by=self.request.user)

    def perform_update(self, serializer):
        if not _is_admin(self.request.user):
            raise PermissionDenied("Administrator role required.")
        self._validate(serializer)
        serializer.save()


class WebhookDeliveryViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = WebhookDeliverySerializer

    def get_queryset(self):
        if not (self.request.user.is_superuser or getattr(self.request.user, "role", "") == "ADMIN"):
            return WebhookDelivery.objects.none()
        return WebhookDelivery.objects.all().select_related("endpoint").order_by("-id")
