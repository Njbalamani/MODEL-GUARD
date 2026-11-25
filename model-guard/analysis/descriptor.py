import json
from pathlib import Path

from django.conf import settings

from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

import numpy as np

MODEL_TYPES = {
    "logistic_regression": LogisticRegression,
    "decision_tree": DecisionTreeClassifier,
    "random_forest": RandomForestClassifier,
    "gradient_boosting": GradientBoostingClassifier,
}

PARAMETER_RULES = {
    "logistic_regression": {"C": (0.01, 100.0, float), "max_iter": (50, 2000, int)},
    "decision_tree": {"max_depth": (1, 20, int), "min_samples_leaf": (1, 50, int)},
    "random_forest": {"n_estimators": (5, 200, int), "max_depth": (1, 30, int), "min_samples_leaf": (1, 50, int)},
    "gradient_boosting": {"n_estimators": (5, 200, int), "max_depth": (1, 10, int), "learning_rate": (0.01, 1.0, float)},
}


def parse_descriptor(path):
    path = Path(path)
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Descriptor exceeds the 2 MB descriptor limit.")
    with path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict):
        raise ValueError("Descriptor root must be a JSON object.")
    allowed_root = {"schema", "model_type", "features", "parameters", "seed"}
    unknown = set(raw) - allowed_root
    if unknown:
        raise ValueError(f"Unknown descriptor keys: {sorted(unknown)}")
    if raw.get("schema") != "modelguard.descriptor.v1":
        raise ValueError("Unsupported descriptor schema.")
    model_type = raw.get("model_type")
    if model_type not in MODEL_TYPES:
        raise ValueError(f"Unsupported model_type: {model_type}")
    features = raw.get("features")
    if not isinstance(features, list) or not 2 <= len(features) <= 64:
        raise ValueError("features must contain between 2 and 64 names.")
    if not all(isinstance(item, str) and 1 <= len(item) <= 128 for item in features):
        raise ValueError("Each feature name must be a non-empty string up to 128 characters.")
    if len(set(features)) != len(features):
        raise ValueError("Feature names must be unique.")
    parameters = raw.get("parameters", {})
    if not isinstance(parameters, dict):
        raise ValueError("parameters must be an object.")
    rules = PARAMETER_RULES[model_type]
    unknown_params = set(parameters) - set(rules)
    if unknown_params:
        raise ValueError(f"Unknown parameters for {model_type}: {sorted(unknown_params)}")
    clean_params = {"random_state": 0}
    for key, value in parameters.items():
        low, high, kind = rules[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"Parameter {key} must be numeric.")
        value = kind(value)
        if not low <= value <= high:
            raise ValueError(f"Parameter {key} must be between {low} and {high}.")
        clean_params[key] = value
    seed = raw.get("seed", 42)
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 2**31 - 1:
        raise ValueError("seed must be an integer between 0 and 2147483647.")
    return {
        "schema": raw["schema"],
        "model_type": model_type,
        "features": features,
        "parameters": clean_params,
        "seed": seed,
    }


def build_synthetic_dataset(descriptor, rows=None):
    rows = rows or settings.MG_SAMPLE_ROWS
    rows = max(100, min(rows, 5000))
    rng = np.random.default_rng(descriptor["seed"])
    features = descriptor["features"]
    X = rng.normal(0.0, 1.0, size=(rows, len(features)))
    weights = rng.normal(0.0, 1.0, size=len(features))
    logits = X @ weights + rng.normal(0.0, 0.25, size=rows)
    probabilities = 1.0 / (1.0 + np.exp(-logits))
    y = (probabilities >= 0.5).astype(int)
    if y.min() == y.max():
        y[: rows // 2] = 0
        y[rows // 2 :] = 1
    return X, y


def build_estimator(descriptor, X=None, y=None):
    cls = MODEL_TYPES[descriptor["model_type"]]
    params = dict(descriptor["parameters"])
    if descriptor["model_type"] == "logistic_regression":
        params["solver"] = "lbfgs"
    estimator = cls(**params)
    if X is not None and y is not None:
        estimator.fit(X, y)
    return estimator
