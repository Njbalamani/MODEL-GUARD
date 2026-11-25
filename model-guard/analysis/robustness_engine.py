import numpy as np
from django.conf import settings

FGSM_LIMITATIONS = [
    "Finite-difference gradient approximation is used instead of framework-level autograd.",
    "Tests run on a synthetic dataset derived from the validated descriptor, not on uploaded binary model files.",
    "Results are controlled demonstrations and do not certify production robustness.",
]

PGD_LIMITATIONS = FGSM_LIMITATIONS + [
    "Projections are applied in L-infinity space with feature bounds clipped to the synthetic data range.",
]

L2_PGD_LIMITATIONS = FGSM_LIMITATIONS + [
    "Projections are applied in L2 space with a bounded epsilon norm.",
]

RANDOM_LIMITATIONS = [
    "Random Gaussian noise is a baseline stress test without gradient information.",
    "Tests run on synthetic inputs and do not certify production robustness.",
]

PATCH_LIMITATIONS = [
    "Feature patch attacks perturb a small deterministic subset of input features.",
    "Tests run on synthetic inputs and do not certify production robustness.",
]

ATTACK_LIMITATIONS = {
    "FGSM": FGSM_LIMITATIONS,
    "PGD": PGD_LIMITATIONS,
    "L2_PGD": L2_PGD_LIMITATIONS,
    "GAUSSIAN": RANDOM_LIMITATIONS,
    "PATCH": PATCH_LIMITATIONS,
}

ATTACKS = tuple(ATTACK_LIMITATIONS)


def _probabilities(estimator, X):
    if hasattr(estimator, "predict_proba"):
        return np.asarray(estimator.predict_proba(X), dtype=float)
    predictions = np.asarray(estimator.predict(X)).astype(int)
    out = np.zeros((len(predictions), 2), dtype=float)
    out[np.arange(len(predictions)), predictions] = 1.0
    return out


def _accuracy(estimator, X, y):
    return float(np.mean(np.asarray(estimator.predict(X)) == y))


def _gradient(estimator, X, y, perturbation=1e-4):
    row_index = np.arange(len(y))
    gradient = np.zeros_like(X, dtype=float)
    for feature in range(X.shape[1]):
        plus = X.copy()
        minus = X.copy()
        plus[:, feature] += perturbation
        minus[:, feature] -= perturbation
        positive = _probabilities(estimator, plus)[row_index, y]
        negative = _probabilities(estimator, minus)[row_index, y]
        gradient[:, feature] = (positive - negative) / (2 * perturbation)
    return gradient


def _l2_project(delta, epsilon):
    norms = np.linalg.norm(delta, axis=1, keepdims=True)
    scale = np.minimum(1.0, epsilon / np.maximum(norms, 1e-12))
    return delta * scale


def _perturb(estimator, X, y, epsilon, steps, step_size, attack):
    delta = np.zeros_like(X, dtype=float)
    if attack == "GAUSSIAN":
        rng = np.random.default_rng(11)
        delta = rng.normal(0.0, settings.MG_GAUSSIAN_SIGMA, size=X.shape)
        return np.clip(X + np.clip(delta, -epsilon, epsilon), -5.0, 5.0)

    if attack == "PATCH":
        rng = np.random.default_rng(17)
        gradient = _gradient(estimator, X, y)
        patch_size = min(settings.MG_PATCH_FEATURES, X.shape[1])
        for row in range(len(X)):
            columns = rng.choice(X.shape[1], size=patch_size, replace=False)
            delta[row, columns] = np.sign(-gradient[row, columns]) * epsilon
        return np.clip(X + delta, -5.0, 5.0)

    for _ in range(steps):
        gradient = _gradient(estimator, X + delta, y)
        delta += step_size * np.sign(-gradient)
        if attack == "L2_PGD":
            delta = _l2_project(delta, epsilon)
        else:
            delta = np.clip(delta, -epsilon, epsilon)
    return np.clip(X + delta, -5.0, 5.0)


def run_attack(estimator, X, y, attack, epsilon=None, steps=None, step_size=None):
    if attack not in ATTACKS:
        raise ValueError(f"Unsupported attack: {attack}")
    limitations = ATTACK_LIMITATIONS[attack]
    if estimator is None:
        return {
            "status": "UNSUPPORTED",
            "attack": attack,
            "limitations": limitations,
            "reason": "No executable descriptor or validated ONNX model was available for this artifact.",
        }

    if attack == "FGSM":
        epsilon = settings.MG_FGSM_EPSILON if epsilon is None else epsilon
        steps = 1
        step_size = epsilon
    elif attack in {"PGD", "L2_PGD"}:
        epsilon = settings.MG_PGD_EPSILON if epsilon is None else epsilon
        steps = settings.MG_PGD_STEPS if steps is None else steps
        step_size = settings.MG_PGD_STEP_SIZE if step_size is None else step_size
    else:
        epsilon = settings.MG_FGSM_EPSILON if epsilon is None else epsilon
        steps = 1
        step_size = epsilon

    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=int)
    original_accuracy = _accuracy(estimator, X, y)
    original_proba = _probabilities(estimator, X)
    original_confidence = float(np.mean(original_proba[np.arange(len(y)), y]))
    perturbed = _perturb(estimator, X, y, epsilon, steps, step_size, attack)
    perturbed_accuracy = _accuracy(estimator, perturbed, y)
    perturbed_proba = _probabilities(estimator, perturbed)
    perturbed_confidence = float(np.mean(perturbed_proba[np.arange(len(y)), y]))
    delta = perturbed - X
    return {
        "status": "COMPLETED",
        "attack": attack,
        "epsilon": float(epsilon),
        "steps": int(steps),
        "step_size": float(step_size),
        "samples": int(len(y)),
        "original_accuracy": original_accuracy,
        "perturbed_accuracy": perturbed_accuracy,
        "accuracy_drop": float(original_accuracy - perturbed_accuracy),
        "mean_confidence_drop": float(original_confidence - perturbed_confidence),
        "mean_l2_perturbation": float(np.mean(np.linalg.norm(delta, axis=1))),
        "limitations": limitations,
    }
