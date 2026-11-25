from django.conf import settings
from sklearn.linear_model import LogisticRegression

from .descriptor import MODEL_TYPES, build_estimator

PRIVACY_LIMITATIONS = [
    "This is an experimental membership-inference indicator, not a confirmed privacy vulnerability.",
    "The test uses a synthetic descriptor dataset and a freshly trained surrogate model.",
    "High training confidence may also result from ordinary overfitting or dataset simplicity.",
]


def run_privacy_assessment(descriptor, X, y):
    if descriptor is None:
        return {
            "status": "UNSUPPORTED",
            "method": "none",
            "train_confidence": None,
            "holdout_confidence": None,
            "confidence_gap": None,
            "indicator": False,
            "limitations": PRIVACY_LIMITATIONS + ["No executable descriptor model was available."],
        }
    split = max(1, int(len(X) * 0.7))
    if descriptor["model_type"] in MODEL_TYPES:
        surrogate = build_estimator(descriptor, X[:split], y[:split])
    else:
        surrogate = LogisticRegression(max_iter=500, random_state=0).fit(X[:split], y[:split])
    train_confidence = float(surrogate.predict_proba(X[:split]).max(axis=1).mean())
    holdout_confidence = float(surrogate.predict_proba(X[split:]).max(axis=1).mean())
    gap = train_confidence - holdout_confidence
    return {
        "status": "COMPLETED",
        "method": "train-vs-holdout-confidence-gap",
        "train_confidence": round(train_confidence, 6),
        "holdout_confidence": round(holdout_confidence, 6),
        "confidence_gap": round(float(gap), 6),
        "indicator": bool(gap > settings.MG_PRIVACY_GAP_THRESHOLD),
        "limitations": PRIVACY_LIMITATIONS,
    }
