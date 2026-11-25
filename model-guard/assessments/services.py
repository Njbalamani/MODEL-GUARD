from django.db.models import Q
from django.utils import timezone

from assessments.models import FindingSuppression

SEVERITY_WEIGHTS = {"CRITICAL": 30, "HIGH": 18, "MEDIUM": 9, "LOW": 3, "INFO": 0}


def suppression_is_active(suppression):
    if suppression.status != FindingSuppression.Status.ACTIVE:
        return False
    return suppression.expires_at is None or suppression.expires_at > timezone.now()


def finding_is_suppressed(finding):
    return any(
        suppression_is_active(item)
        for item in finding.suppressions.all()
    )


def visible_findings(assessment):
    return [item for item in assessment.findings.all() if not finding_is_suppressed(item)]


def activate_suppression(suppression, user):
    FindingSuppression.objects.filter(
        finding=suppression.finding,
        status=FindingSuppression.Status.ACTIVE,
    ).exclude(pk=suppression.pk).update(
        status=FindingSuppression.Status.REVOKED,
        updated_at=timezone.now(),
    )
    suppression.status = FindingSuppression.Status.ACTIVE
    suppression.approved_by = user
    suppression.save(update_fields=["status", "approved_by", "updated_at"])
    return suppression


def revoke_suppression(suppression):
    suppression.status = FindingSuppression.Status.REVOKED
    suppression.save(update_fields=["status", "updated_at"])
    return suppression


def recalculate_assessment(assessment):
    findings = visible_findings(assessment)
    counts = {level: 0 for level in SEVERITY_WEIGHTS}
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1
    risk_score = min(100, sum(SEVERITY_WEIGHTS[item.severity] for item in findings if item.severity in SEVERITY_WEIGHTS))
    summary = {
        "findings": counts,
        "suppressed": assessment.findings.count() - len(findings),
        "robustness": list(assessment.robustness_tests.values("attack", "status", "accuracy_drop")),
        "explainability": assessment.explainability.method if hasattr(assessment, "explainability") else None,
        "privacy_indicator": assessment.privacy.indicator if hasattr(assessment, "privacy") else None,
        "reports": assessment.reports.count(),
    }
    assessment.risk_score = risk_score
    assessment.summary = summary
    assessment.save(update_fields=["risk_score", "summary"])
    return assessment
