from django.urls import include, path
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework.renderers import BrowsableAPIRenderer, JSONOpenAPIRenderer
from rest_framework.routers import DefaultRouter
from rest_framework.schemas import get_schema_view

from config.api_views import DashboardSummaryAPIView, ModelUploadAPIView
from config.viewsets import (
    AssessmentCommentViewSet, AuditLogViewSet, CurrentUserViewSet,
    DataDriftResultViewSet, DeploymentPolicyViewSet, ExplainabilityResultViewSet,
    FindingSuppressionViewSet, GeneratedReportViewSet, ModelVersionViewSet,
    PolicyEvaluationViewSet, PrivacyAssessmentViewSet, ProjectViewSet,
    ReferenceDatasetViewSet, RescanScheduleViewSet, RobustnessTestViewSet,
    SecurityAssessmentViewSet, UploadedModelViewSet, VulnerabilityFindingViewSet,
    WebhookDeliveryViewSet, WebhookEndpointViewSet,
)

router = DefaultRouter()
router.register("me", CurrentUserViewSet, basename="me")
router.register("projects", ProjectViewSet, basename="project")
router.register("models", UploadedModelViewSet, basename="model")
router.register("versions", ModelVersionViewSet, basename="version")
router.register("assessments", SecurityAssessmentViewSet, basename="assessment")
router.register("findings", VulnerabilityFindingViewSet, basename="finding")
router.register("robustness", RobustnessTestViewSet, basename="robustness")
router.register("explainability", ExplainabilityResultViewSet, basename="explainability")
router.register("privacy", PrivacyAssessmentViewSet, basename="privacy")
router.register("reports", GeneratedReportViewSet, basename="report")
router.register("audit", AuditLogViewSet, basename="audit")
router.register("suppressions", FindingSuppressionViewSet, basename="suppression")
router.register("comments", AssessmentCommentViewSet, basename="comment")
router.register("schedules", RescanScheduleViewSet, basename="schedule")
router.register("policies", DeploymentPolicyViewSet, basename="policy")
router.register("policy-evaluations", PolicyEvaluationViewSet, basename="policy-evaluation")
router.register("reference-datasets", ReferenceDatasetViewSet, basename="reference-dataset")
router.register("drift", DataDriftResultViewSet, basename="drift")
router.register("webhooks", WebhookEndpointViewSet, basename="webhook")
router.register("webhook-deliveries", WebhookDeliveryViewSet, basename="webhook-delivery")

schema_view = get_schema_view(
    title="ModelGuard API",
    description="AI-powered machine learning model security assessment API.",
    version="1.0.0",
    public=False,
    renderer_classes=[JSONOpenAPIRenderer, BrowsableAPIRenderer],
)

urlpatterns = [
    path("auth/token/", obtain_auth_token, name="auth-token"),
    path("dashboard/summary/", DashboardSummaryAPIView.as_view(), name="dashboard-summary"),
    path("upload/", ModelUploadAPIView.as_view(), name="model-upload"),
    path("schema/", schema_view, name="schema"),
    path("", include(router.urls)),
]
