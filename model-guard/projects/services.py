from assessments.models import SecurityAssessment
from assessments.services import visible_findings
from projects.models import PolicyEvaluation

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def evaluate_policy(policy, assessment, user=None, persist=True):
    reasons = []
    if assessment.status != SecurityAssessment.Status.COMPLETED:
        reasons.append("Assessment is not completed.")
    if assessment.risk_score > policy.max_risk_score:
        reasons.append(
            f"Risk score {assessment.risk_score} exceeds the maximum {policy.max_risk_score}."
        )
    blocked = {
        item for item in policy.blocked_severities
        if item in VALID_SEVERITIES
    }
    present = {item.severity for item in visible_findings(assessment)}
    overlap = sorted(blocked & present)
    if overlap:
        reasons.append(f"Blocked severities present: {', '.join(overlap)}.")
    if policy.require_report and not assessment.reports.exists():
        reasons.append("A generated report is required by this policy.")
    result = PolicyEvaluation.Result.FAIL if reasons else PolicyEvaluation.Result.PASS
    evaluation = None
    if persist:
        evaluation = PolicyEvaluation.objects.create(
            policy=policy,
            assessment=assessment,
            result=result,
            reasons=reasons,
            evaluated_by=user,
        )
    return {
        "result": result,
        "passed": result == PolicyEvaluation.Result.PASS,
        "reasons": reasons,
        "evaluation": evaluation,
    }
