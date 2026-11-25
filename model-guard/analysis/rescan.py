from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from analysis.tasks import dispatch_assessment
from assessments.models import RescanSchedule, SecurityAssessment
from audit.models import log_action
from audit.notifications import notify


def run_due_rescans(now=None):
    now = now or timezone.now()
    minimum = max(1, settings.MG_RESCAN_MIN_INTERVAL_MINUTES)
    processed = 0
    schedules = (
        RescanSchedule.objects
        .filter(enabled=True, next_run_at__lte=now)
        .select_related("model_version", "project", "created_by")
    )
    for schedule in schedules:
        with transaction.atomic():
            schedule.refresh_from_db()
            if not schedule.enabled or schedule.next_run_at > now:
                continue
            existing = SecurityAssessment.objects.filter(
                model_version=schedule.model_version,
                status__in=[SecurityAssessment.Status.PENDING, SecurityAssessment.Status.RUNNING],
            ).exists()
            if existing:
                schedule.next_run_at = now + timedelta(minutes=max(schedule.interval_minutes, minimum))
                schedule.save(update_fields=["next_run_at", "updated_at"])
                continue
            assessment = SecurityAssessment.objects.create(
                model_version=schedule.model_version,
                project=schedule.project,
                triggered_by=schedule.created_by,
            )
            log_action(schedule.created_by, "rescan.queued", "SecurityAssessment", assessment.pk, {"schedule": schedule.pk})
            schedule.last_run_at = now
            schedule.next_run_at = now + timedelta(minutes=max(schedule.interval_minutes, minimum))
            schedule.save(update_fields=["last_run_at", "next_run_at", "updated_at"])
            dispatch_assessment(assessment.pk)
            notify("rescan.due", {
                "assessment_id": assessment.pk,
                "schedule_id": schedule.pk,
                "model_version_id": schedule.model_version_id,
            })
            processed += 1
    return processed
