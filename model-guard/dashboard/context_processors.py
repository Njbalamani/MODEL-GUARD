from assessments.models import SecurityAssessment
from audit.models import AuditLog
from modelregistry.models import UploadedModel
from projects.models import Project
from reports.models import GeneratedReport


def platform_context(request):
    if not request.user.is_authenticated:
        return {"mg_models": 0, "mg_assessments": 0, "mg_critical": 0, "mg_high": 0, "mg_reports": 0, "mg_recent": []}
    return {
        "mg_models": UploadedModel.objects.count(),
        "mg_assessments": SecurityAssessment.objects.count(),
        "mg_critical": SecurityAssessment.objects.filter(findings__severity="CRITICAL").distinct().count(),
        "mg_high": SecurityAssessment.objects.filter(findings__severity="HIGH").distinct().count(),
        "mg_reports": GeneratedReport.objects.count(),
        "mg_recent": AuditLog.objects.select_related("user")[:8],
        "mg_projects": Project.objects.count(),
    }
