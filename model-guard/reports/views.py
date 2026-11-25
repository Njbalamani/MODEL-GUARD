from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render

from audit.models import log_action
from projects.permissions import accessible_project_ids, project_access
from reports.models import GeneratedReport
from reports.services import generate_report
from reports.signing import verify_report


@login_required
def report_list(request):
    reports = GeneratedReport.objects.filter(
        assessment__project_id__in=accessible_project_ids(request.user)
    ).select_related("assessment__project").order_by("-created_at")
    return render(request, "reports/list.html", {"reports": reports})


@login_required
def generate(request, assessment_id):
    from assessments.models import SecurityAssessment

    assessment = get_object_or_404(SecurityAssessment, pk=assessment_id)
    project_access(request.user, assessment.project, write=True)
    report = generate_report(assessment, request.user)
    log_action(request.user, "report.generated", "GeneratedReport", report.pk, {"assessment": assessment_id})
    return redirect("reports:detail", pk=report.pk)


@login_required
def detail(request, pk):
    report = get_object_or_404(
        GeneratedReport.objects.select_related("assessment__project"),
        pk=pk,
    )
    project_access(request.user, report.assessment.project)
    return render(request, "reports/detail.html", {"report": report})


@login_required
def download(request, pk):
    report = get_object_or_404(
        GeneratedReport.objects.select_related("assessment__project"),
        pk=pk,
    )
    project_access(request.user, report.assessment.project)
    if not report.file:
        raise Http404("Report file is missing.")
    return FileResponse(report.file.open("rb"), as_attachment=True, filename=report.file.name.split("/")[-1])


@login_required
def verify_signature(request, pk):
    report = get_object_or_404(
        GeneratedReport.objects.select_related("assessment__project"),
        pk=pk,
    )
    project_access(request.user, report.assessment.project)
    return render(request, "reports/verify.html", {
        "report": report,
        "verification": verify_report(report),
    })
