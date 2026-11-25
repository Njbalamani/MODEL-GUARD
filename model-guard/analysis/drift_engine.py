import numpy as np
from django.conf import settings

DRIFT_LIMITATIONS = [
    "Population stability index is computed on synthetic or uploaded tabular inputs, not on raw production traffic.",
    "Quantile bins are derived from the baseline distribution and may be unstable for sparse numeric features.",
]


def _psi(baseline, current, bins=10):
    baseline = np.asarray(baseline, dtype=float)
    current = np.asarray(current, dtype=float)
    if len(baseline) < 2 or len(current) < 2:
        return 0.0
    quantiles = np.linspace(0, 100, bins + 1)
    edges = np.unique(np.percentile(baseline, quantiles))
    if len(edges) < 3:
        low = float(np.min(np.concatenate([baseline, current])))
        high = float(np.max(np.concatenate([baseline, current])))
        if high <= low:
            return 0.0
        edges = np.linspace(low, high, bins + 1)
    edges[0] = -np.inf
    edges[-1] = np.inf
    base_counts = np.histogram(baseline, bins=edges)[0].astype(float)
    current_counts = np.histogram(current, bins=edges)[0].astype(float)
    base_ratio = (base_counts + 1e-6) / (base_counts.sum() + 1e-6 * len(base_counts))
    current_ratio = (current_counts + 1e-6) / (current_counts.sum() + 1e-6 * len(current_counts))
    return float(np.sum((current_ratio - base_ratio) * np.log(current_ratio / base_ratio)))


def run_drift_checks(features, current_X, baseline_X=None, reference_source="synthetic-baseline"):
    if current_X is None or baseline_X is None:
        return []
    current_X = np.asarray(current_X, dtype=float)
    baseline_X = np.asarray(baseline_X, dtype=float)
    results = []
    for index, feature in enumerate(features):
        if index >= current_X.shape[1] or index >= baseline_X.shape[1]:
            continue
        psi = _psi(baseline_X[:, index], current_X[:, index])
        if psi >= settings.MG_DRIFT_PSI_THRESHOLD:
            status = "DRIFT"
        elif psi >= settings.MG_DRIFT_WATCH_THRESHOLD:
            status = "WATCH"
        else:
            status = "STABLE"
        results.append({
            "feature": feature,
            "psi": round(psi, 6),
            "threshold": settings.MG_DRIFT_PSI_THRESHOLD,
            "status": status,
            "reference_source": reference_source,
            "limitations": DRIFT_LIMITATIONS,
        })
    return results
