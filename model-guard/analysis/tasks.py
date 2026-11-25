import logging
import threading

from django.conf import settings

from .pipeline import run_assessment

logger = logging.getLogger("modelguard")


def dispatch_assessment(assessment_id):
    try:
        from .tasks import run_assessment_task

        run_assessment_task.delay(assessment_id)
        return "celery"
    except Exception as exc:
        logger.warning("Celery dispatch failed, using thread fallback: %s", exc)
        worker = threading.Thread(target=_safe_run, args=(assessment_id,), daemon=True)
        worker.start()
        return "thread"


def _safe_run(assessment_id):
    from django.db import close_old_connections

    close_old_connections()
    try:
        run_assessment(assessment_id)
    finally:
        close_old_connections()


try:
    from celery import shared_task

    @shared_task(bind=True, name="modelguard.run_assessment")
    def run_assessment_task(self, assessment_id):
        return run_assessment(assessment_id)

    @shared_task(bind=True, name="modelguard.run_due_rescans")
    def run_due_rescans_task(self):
        from .rescan import run_due_rescans
        return run_due_rescans()

except ImportError:
    run_assessment_task = None
    run_due_rescans_task = None
