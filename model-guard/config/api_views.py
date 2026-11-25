from django.core.exceptions import PermissionDenied
from django.db import transaction
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from analysis.tasks import dispatch_assessment
from assessments.models import SecurityAssessment
from audit.models import log_action
from config.serializers import SecurityAssessmentSerializer
from modelregistry.models import ModelVersion, UploadedModel
from modelregistry.services import validate_and_store
from projects.models import Project
from projects.permissions import project_access


class DashboardSummaryAPIView(APIView):
    def get(self, request):
        from django.db.models import Count, Q

        from assessments.models import VulnerabilityFinding
        from modelregistry.models import UploadedModel

        project_ids = Project.objects.filter(Q(owner=request.user) | Q(members__user=request.user)).distinct().values_list("id", flat=True)
        assessments = SecurityAssessment.objects.filter(project_id__in=project_ids)
        return Response({
            "models": UploadedModel.objects.filter(project_id__in=project_ids).count(),
            "assessments": assessments.count(),
            "completed": assessments.filter(status=SecurityAssessment.Status.COMPLETED).count(),
            "critical_findings": VulnerabilityFinding.objects.filter(assessment__project_id__in=project_ids, severity="CRITICAL").count(),
            "high_findings": VulnerabilityFinding.objects.filter(assessment__project_id__in=project_ids, severity="HIGH").count(),
            "recent": SecurityAssessmentSerializer(assessments.order_by("-created_at")[:5], many=True, context={"request": request}).data,
        })


class ModelUploadAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        project_id = request.data.get("project_id")
        model_name = request.data.get("model_name")
        version_label = request.data.get("version_label") or "v1"
        description = request.data.get("description", "")
        uploaded = request.FILES.get("file")
        if not project_id or not model_name or not uploaded:
            return Response({"detail": "project_id, model_name and file are required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            project = Project.objects.get(pk=project_id)
            project_access(request.user, project, write=True)
            with transaction.atomic():
                model, created = UploadedModel.objects.get_or_create(
                    project=project,
                    name=model_name,
                    defaults={"description": description, "created_by": request.user},
                )
                result = validate_and_store(uploaded, uploaded.name, model.pk, version_label)
                version = ModelVersion.objects.create(
                    model=model,
                    version_label=version_label,
                    file=result["stored_name"],
                    original_name=result["original_name"],
                    sha256=result["sha256"],
                    size_bytes=result["size_bytes"],
                    file_format=result["file_format"],
                    is_descriptor=result["is_descriptor"],
                    metadata=result["metadata"],
                    uploaded_by=request.user,
                )
                assessment = SecurityAssessment.objects.create(
                    model_version=version,
                    project=project,
                    triggered_by=request.user,
                )
                log_action(request.user, "model.uploaded", "ModelVersion", version.pk, {"sha256": version.sha256})
            dispatch_assessment(assessment.pk)
            return Response(
                {
                    "model": model.pk,
                    "version": version.pk,
                    "assessment": assessment.pk,
                    "sha256": version.sha256,
                    "status": assessment.status,
                },
                status=status.HTTP_201_CREATED,
            )
        except Project.DoesNotExist:
            return Response({"detail": "Project not found."}, status=status.HTTP_404_NOT_FOUND)
        except PermissionDenied as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_403_FORBIDDEN)
        except Exception as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
