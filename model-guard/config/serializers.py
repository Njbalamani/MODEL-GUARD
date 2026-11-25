from rest_framework import serializers

from accounts.models import User
from analysis.models import DataDriftResult
from assessments.models import (
    AssessmentComment, FindingSuppression, RescanSchedule, SecurityAssessment,
    VulnerabilityFinding,
)
from audit.models import AuditLog, WebhookDelivery, WebhookEndpoint
from explainability.models import ExplainabilityResult
from modelregistry.models import ModelVersion, UploadedModel
from privacy.models import PrivacyAssessment
from projects.models import (
    DeploymentPolicy, PolicyEvaluation, Project, ProjectMember, ReferenceDataset,
)
from reports.models import GeneratedReport
from robustness.models import RobustnessTest


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "role", "organization", "created_at"]


class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = ["id", "name", "description", "owner", "created_at", "updated_at"]
        read_only_fields = ["owner"]


class ProjectMemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProjectMember
        fields = ["id", "project", "user", "role", "created_at"]


class UploadedModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadedModel
        fields = ["id", "project", "name", "description", "created_by", "created_at", "updated_at"]
        read_only_fields = ["created_by"]


class ModelVersionSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()

    class Meta:
        model = ModelVersion
        fields = [
            "id", "model", "version_label", "file", "file_url", "original_name",
            "sha256", "size_bytes", "file_format", "status", "is_descriptor",
            "metadata", "notes", "created_at",
        ]
        read_only_fields = ["sha256", "size_bytes", "file_format", "is_descriptor", "metadata"]

    def get_file_url(self, obj):
        request = self.context.get("request")
        return request.build_absolute_uri(obj.file.url) if request and obj.file else obj.file.url


class SecurityAssessmentSerializer(serializers.ModelSerializer):
    model_name = serializers.SerializerMethodField()

    class Meta:
        model = SecurityAssessment
        fields = [
            "id", "project", "model_version", "model_name", "triggered_by", "status",
            "risk_score", "summary", "error", "engine_version", "created_at",
            "started_at", "completed_at",
        ]
        read_only_fields = ["triggered_by", "risk_score", "summary", "error"]

    def get_model_name(self, obj):
        return str(obj.model_version)


class VulnerabilityFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilityFinding
        fields = [
            "id", "assessment", "severity", "category", "title", "description",
            "evidence", "recommendation", "confidence", "source", "created_at",
        ]


class RobustnessTestSerializer(serializers.ModelSerializer):
    class Meta:
        model = RobustnessTest
        fields = [
            "id", "assessment", "attack", "status", "epsilon", "steps", "step_size",
            "samples", "original_accuracy", "perturbed_accuracy", "accuracy_drop",
            "mean_confidence_drop", "mean_l2_perturbation", "limitations", "created_at",
        ]


class ExplainabilityResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExplainabilityResult
        fields = [
            "id", "assessment", "method", "status", "feature_importances",
            "base_value", "sample_prediction", "limitations", "plot_image", "created_at",
        ]


class PrivacyAssessmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = PrivacyAssessment
        fields = [
            "id", "assessment", "status", "method", "train_confidence",
            "holdout_confidence", "confidence_gap", "indicator", "limitations", "created_at",
        ]


class GeneratedReportSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()

    class Meta:
        model = GeneratedReport
        fields = [
            "id", "assessment", "report_type", "file", "file_url", "sha256",
            "signature", "signature_algorithm", "signed_at", "format", "generated_by", "created_at",
        ]
        read_only_fields = ["sha256", "generated_by"]

    def get_file_url(self, obj):
        request = self.context.get("request")
        return request.build_absolute_uri(obj.file.url) if request and obj.file else obj.file.url


class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = ["id", "user", "action", "object_type", "object_id", "detail", "ip_address", "created_at"]


class FindingSuppressionSerializer(serializers.ModelSerializer):
    class Meta:
        model = FindingSuppression
        fields = [
            "id", "finding", "status", "reason", "requested_by", "approved_by",
            "expires_at", "created_at", "updated_at",
        ]
        read_only_fields = ["status", "requested_by", "approved_by"]


class AssessmentCommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssessmentComment
        fields = ["id", "assessment", "user", "body", "created_at"]
        read_only_fields = ["user"]


class RescanScheduleSerializer(serializers.ModelSerializer):
    class Meta:
        model = RescanSchedule
        fields = [
            "id", "model_version", "project", "interval_minutes", "enabled",
            "next_run_at", "last_run_at", "created_at", "updated_at",
        ]
        read_only_fields = ["project", "last_run_at"]

    def validate_interval_minutes(self, value):
        from django.conf import settings

        minimum = max(1, settings.MG_RESCAN_MIN_INTERVAL_MINUTES)
        if value < minimum:
            raise serializers.ValidationError(f"Interval must be at least {minimum} minutes.")
        return value


class DeploymentPolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = DeploymentPolicy
        fields = [
            "id", "project", "name", "max_risk_score", "blocked_severities",
            "require_report", "enabled", "created_by", "created_at", "updated_at",
        ]
        read_only_fields = ["created_by"]


class PolicyEvaluationSerializer(serializers.ModelSerializer):
    class Meta:
        model = PolicyEvaluation
        fields = ["id", "policy", "assessment", "result", "reasons", "evaluated_by", "created_at"]
        read_only_fields = ["result", "reasons", "evaluated_by"]


class ReferenceDatasetSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReferenceDataset
        fields = ["id", "project", "name", "file", "feature_names", "rows", "uploaded_by", "created_at"]
        read_only_fields = ["feature_names", "rows", "uploaded_by"]


class DataDriftResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = DataDriftResult
        fields = [
            "id", "assessment", "feature", "psi", "threshold", "status",
            "reference_source", "limitations", "created_at",
        ]


class WebhookEndpointSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebhookEndpoint
        fields = ["id", "name", "url", "secret", "events", "active", "created_by", "created_at"]
        read_only_fields = ["created_by"]
        extra_kwargs = {"secret": {"write_only": True}}


class WebhookDeliverySerializer(serializers.ModelSerializer):
    class Meta:
        model = WebhookDelivery
        fields = ["id", "endpoint", "event", "status", "response_code", "error", "payload", "created_at"]
        read_only_fields = ["status", "response_code", "error"]
