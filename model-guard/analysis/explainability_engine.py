import numpy as np
from django.conf import settings
from sklearn.metrics import accuracy_score

SHAP_LIMITATIONS = [
    "SHAP values are computed on synthetic descriptor data, not on uploaded binary model files.",
    "Feature importance explains the reconstructed demonstration model only.",
]


def _permutation_importance(estimator, X, y, features):
    rng = np.random.default_rng(0)
    baseline = accuracy_score(y, estimator.predict(X))
    values = []
    for index, name in enumerate(features):
        perturbed = X.copy()
        rng.shuffle(perturbed[:, index])
        drop = baseline - accuracy_score(y, estimator.predict(perturbed))
        values.append({"feature": name, "value": round(float(max(drop, 0.0)), 6)})
    return sorted(values, key=lambda item: item["value"], reverse=True)


def run_explainability(estimator, X, y, features):
    if estimator is None:
        return {
            "status": "UNSUPPORTED",
            "method": "none",
            "feature_importances": [],
            "base_value": None,
            "sample_prediction": None,
            "limitations": SHAP_LIMITATIONS + ["No executable descriptor model was available."],
        }

    limitations = list(SHAP_LIMITATIONS)
    if settings.MG_ENABLE_SHAP:
        try:
            import shap

            X_sample = X[: min(200, len(X))]
            name = type(estimator).__name__
            if name in {"RandomForestClassifier", "DecisionTreeClassifier", "GradientBoostingClassifier"}:
                explainer = shap.TreeExplainer(estimator)
                method = "shap.TreeExplainer"
            elif name == "LogisticRegression":
                explainer = shap.LinearExplainer(estimator, X[: min(100, len(X))])
                method = "shap.LinearExplainer"
            else:
                raise ValueError(f"Unsupported estimator for SHAP: {name}")
            values = explainer.shap_values(X_sample)
            if isinstance(values, list):
                values = values[1] if len(values) > 1 else values[0]
            values = np.asarray(values)
            if values.ndim == 3:
                values = values[:, :, 1] if values.shape[2] > 1 else values[:, :, 0]
            importances = np.mean(np.abs(values), axis=0)
            base = getattr(explainer, "expected_value", None)
            if isinstance(base, (list, tuple, np.ndarray)):
                base = float(np.asarray(base).flat[-1])
            elif base is None:
                base = None
            else:
                base = float(base)
            probabilities = estimator.predict_proba(X[:1])
            return {
                "status": "COMPLETED",
                "method": method,
                "feature_importances": [
                    {"feature": feature, "value": round(float(value), 6)}
                    for feature, value in zip(features, importances)
                ],
                "base_value": base,
                "sample_prediction": float(probabilities[0, 1]) if probabilities.shape[1] > 1 else float(probabilities[0, 0]),
                "limitations": limitations,
            }
        except Exception as exc:
            limitations.append(f"SHAP was unavailable for this estimator: {type(exc).__name__}: {exc}")

    limitations.append("Permutation importance fallback was used; it measures accuracy drop, not attribution.")
    return {
        "status": "FALLBACK",
        "method": "permutation-importance",
        "feature_importances": _permutation_importance(estimator, X, y, features),
        "base_value": None,
        "sample_prediction": None,
        "limitations": limitations,
    }
