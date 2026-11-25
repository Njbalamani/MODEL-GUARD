def _finding_keys(assessment):
    return {
        (item.severity, item.title): item
        for item in assessment.findings.all()
    }


def compare_assessments(previous, current):
    previous_findings = _finding_keys(previous)
    current_findings = _finding_keys(current)
    added = [key for key in current_findings if key not in previous_findings]
    removed = [key for key in previous_findings if key not in current_findings]
    previous_attacks = {item.attack: item for item in previous.robustness_tests.all()}
    current_attacks = {item.attack: item for item in current.robustness_tests.all()}
    robustness = []
    for attack in sorted(set(previous_attacks) | set(current_attacks)):
        before = previous_attacks.get(attack)
        after = current_attacks.get(attack)
        before_drop = float(before.accuracy_drop or 0.0) if before else None
        after_drop = float(after.accuracy_drop or 0.0) if after else None
        robustness.append({
            "attack": attack,
            "previous_drop": before_drop,
            "current_drop": after_drop,
            "delta": None if before_drop is None or after_drop is None else round(after_drop - before_drop, 6),
        })
    return {
        "previous": previous,
        "current": current,
        "risk_delta": current.risk_score - previous.risk_score,
        "added": [current_findings[key] for key in added],
        "removed": [previous_findings[key] for key in removed],
        "robustness": robustness,
        "finding_delta": len(added) - len(removed),
    }
