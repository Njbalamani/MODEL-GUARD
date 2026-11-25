import logging
from pathlib import Path

from django.conf import settings
from django.core.files.base import ContentFile
from django.db import transaction
from django.utils import timezone

from analysis.models import DataDriftResult
from analysis.onnx_adapter import validate_onnx_file
from analysis.plotting import render_importance_plot
from analysis.reference import load_reference_dataset
from audit.models import log_action
from audit.notifications import notify
from assessments.models import SecurityAssessment, VulnerabilityFinding
from assessments.services import recalculate_assessment
from explainability.models import ExplainabilityResult
from privacy.models import PrivacyAssessment
from projects.models import DeploymentPolicy, ReferenceDataset
from projects.services import evaluate_policy
from reports.models import GeneratedReport
from robustness.models import RobustnessTest

from .descriptor import build_estimator, build_synthetic_dataset, parse_descriptor
from .drift_engine import run_drift_checks
from .explainability_engine import run_explainability
from .privacy_engine import run_privacy_assessment
from .robustness_engine import ATTACKS, run_attack
from .static_inspection import inspect_file

logger = logging.getLogger("modelguard")


def _create_findings(assessment, findings):
    for item in findings:
        VulnerabilityFinding.objects.create(assessment=assessment, **item)


def _onnx_descriptor(feature_names):
    return {
        "schema": "modelguard.descriptor.v1",
        "model_type": "onnx",
        "features": feature_names,
        "parameters": {},
        "seed": 42,
    }


def _clear_previous_results(assessment):
    VulnerabilityFinding.objects.filter(assessment=assessment).delete()
    RobustnessTest.objects.filter(assessment=assessment).delete()
    ExplainabilityResult.objects.filter(assessment=assessment).delete()
    PrivacyAssessment.objects.filter(assessment=assessment).delete()
    DataDriftResult.objects.filter(assessment=assessment).delete()
    assessment.policy_evaluations.all().delete()
    assessment.risk_score = 0
    assessment.summary = {}


def run_assessment(assessment_id):
    with transaction.atomic():
        assessment = SecurityAssessment.objects.select_related(
            "model_version", "model_version__model", "project", "triggered_by"
        ).get(pk=assessment_id)
        if assessment.status in {SecurityAssessment.Status.COMPLETED, SecurityAssessment.Status.RUNNING}:
            return assessment
        assessment.status = SecurityAssessment.Status.RUNNING
        assessment.started_at = timezone.now()
        assessment.error = ""
        _clear_previous_results(assessment)
        assessment.save(update_fields=["status", "started_at", "error", "risk_score", "summary"])
        version = assessment.model_version
        version.status = "ANALYZING"
        version.save(update_fields=["status"])
        log_action(
            assessment.triggered_by,
            "assessment.started",
            "SecurityAssessment",
            assessment.pk,
            {"model_version": version.pk, "sha256": version.sha256},
        )

    descriptor = None
    all_findings = []
    estimator = None
    X = y = None

    try:
        if version.is_descriptor:
            descriptor = parse_descriptor(Path(version.file.path))

        metadata, static_findings = inspect_file(version.file.path, version.file_format, descriptor)
        all_findings.extend(static_findings)

        if version.file_format == ".onnx" and settings.MG_ENABLE_ONNX:
            try:
                adapter, feature_names = validate_onnx_file(version.file.path, version.original_name)
                estimator = adapter
                descriptor = _onnx_descriptor(feature_names)
                metadata["onnx_features"] = feature_names
                metadata["onnx_runtime"] = "enabled"
                all_findings.append({
                    "severity": "INFO",
                    "category": "Safe format",
                    "title": "Validated ONNX runtime adapter",
                    "description": "The ONNX graph passed structural validation and runs in a CPU-only hardened InferenceSession with external data disabled.",
                    "evidence": {"features": len(feature_names), "nodes": metadata.get("archive_entries", 0)},
                    "recommendation": "Prefer validated ONNX graphs for reproducible executable assessments.",
                    "confidence": "HIGH",
                    "source": "onnx-adapter",
                })
            except Exception as exc:
                all_findings.append({
                    "severity": "HIGH",
                    "category": "Analysis limitation",
                    "title": "Validated ONNX execution unavailable",
                    "description": "The ONNX artifact could not be safely validated and was not executed.",
                    "evidence": {"error": f"{type(exc).__name__}: {exc}"},
                    "recommendation": "Re-export the graph with standard operators, no external data and fixed input dimensions.",
                    "confidence": "HIGH",
                    "source": "onnx-adapter",
                })
                metadata["onnx_runtime"] = "unavailable"

        if metadata != version.metadata:
            version.metadata = metadata
            version.save(update_fields=["metadata"])

        if descriptor:
            X, y = build_synthetic_dataset(descriptor)
            if not hasattr(estimator, "predict_proba"):
                estimator = build_estimator(descriptor, X, y)
        else:
            all_findings.append({
                "severity": "INFO",
                "category": "Analysis limitation",
                "title": "Executable analysis unavailable for this artifact",
                "description": "Static inspection completed. Robustness, explainability and privacy tests require a validated JSON descriptor or validated ONNX graph and were not run on this binary artifact.",
                "evidence": {"file_format": version.file_format, "static_only": True},
                "recommendation": "Upload a validated modelguard.descriptor.v1 JSON descriptor or standard ONNX graph to enable executable demonstrations.",
                "confidence": "HIGH",
                "source": "pipeline",
            })

        with transaction.atomic():
            _create_findings(assessment, all_findings)

            attack_samples = 120
            X_test = X[:attack_samples] if X is not None else None
            y_test = y[:attack_samples] if y is not None else None
            for attack in ATTACKS:
                result = run_attack(estimator, X_test, y_test, attack)
                RobustnessTest.objects.create(
                    assessment=assessment,
                    attack=attack,
                    status=result["status"],
                    epsilon=result.get("epsilon", 0.0),
                    steps=result.get("steps", 1),
                    step_size=result.get("step_size", 0.0),
                    samples=result.get("samples", 0),
                    original_accuracy=result.get("original_accuracy"),
                    perturbed_accuracy=result.get("perturbed_accuracy"),
                    accuracy_drop=result.get("accuracy_drop"),
                    mean_confidence_drop=result.get("mean_confidence_drop"),
                    mean_l2_perturbation=result.get("mean_l2_perturbation"),
                    limitations=result.get("limitations", []),
                )
                if result["status"] == "COMPLETED" and result["accuracy_drop"] > 0.25:
                    VulnerabilityFinding.objects.create(
                        assessment=assessment,
                        severity="HIGH",
                        category="Robustness",
                        title=f"High accuracy degradation under {attack}",
                        description=f"Accuracy dropped by {result['accuracy_drop']:.1%} under a controlled {attack} demonstration.",
                        evidence={"attack": attack, "epsilon": result["epsilon"], "steps": result["steps"]},
                        recommendation="Evaluate adversarial training, input preprocessing and confidence thresholds before deployment.",
                        confidence="MEDIUM",
                        source="robustness-engine",
                    )

            explanation = run_explainability(estimator, X, y, descriptor["features"] if descriptor else [])
            plot_bytes = render_importance_plot(
                explanation["feature_importances"], explanation["method"]
            )
            explanation_record = ExplainabilityResult.objects.create(
                assessment=assessment,
                method=explanation["method"],
                status=explanation["status"],
                feature_importances=explanation["feature_importances"],
                base_value=explanation["base_value"],
                sample_prediction=explanation["sample_prediction"],
                limitations=explanation["limitations"],
            )
            if plot_bytes:
                explanation_record.plot_image.save(
                    f"assessment-{assessment.pk}-importance.png",
                    ContentFile(plot_bytes),
                    save=True,
                )

            privacy = run_privacy_assessment(descriptor, X, y)
            PrivacyAssessment.objects.create(
                assessment=assessment,
                status=privacy["status"],
                method=privacy["method"],
                train_confidence=privacy["train_confidence"],
                holdout_confidence=privacy["holdout_confidence"],
                confidence_gap=privacy["confidence_gap"],
                indicator=privacy["indicator"],
                limitations=privacy["limitations"],
            )
            if privacy["indicator"]:
                VulnerabilityFinding.objects.create(
                    assessment=assessment,
                    severity="MEDIUM",
                    category="Privacy",
                    title="Experimental membership-inference indicator",
                    description=f"Training-confidence gap of {privacy['confidence_gap']:.3f} exceeded the configured threshold. This is an indicator, not a confirmed vulnerability.",
                    evidence={"gap": privacy["confidence_gap"], "threshold": settings.MG_PRIVACY_GAP_THRESHOLD},
                    recommendation="Validate with a formal membership-inference attack on the real training distribution before treating this as confirmed leakage.",
                    confidence="LOW",
                    source="privacy-engine",
                )

            baseline_X = None
            reference_source = "synthetic-baseline"
            features = descriptor["features"] if descriptor else []
            for reference in ReferenceDataset.objects.filter(project=assessment.project):
                if features and all(feature in (reference.feature_names or []) for feature in features):
                    try:
                        baseline_X = load_reference_dataset(reference, features)
                        reference_source = reference.name
                        break
                    except Exception as exc:
                        logger.warning("Reference dataset %s could not be used: %s", reference.pk, exc)
            if baseline_X is None and descriptor and X is not None:
                baseline_descriptor = dict(descriptor)
                baseline_descriptor["seed"] = (descriptor["seed"] + 1) % (2**31 - 1)
                baseline_X, _ = build_synthetic_dataset(baseline_descriptor, rows=len(X))
            for item in run_drift_checks(features, X, baseline_X, reference_source):
                DataDriftResult.objects.create(assessment=assessment, **item)
                if item["status"] == "DRIFT":
                    VulnerabilityFinding.objects.create(
                        assessment=assessment,
                        severity="MEDIUM",
                        category="Data drift",
                        title=f"Population shift detected for {item['feature']}",
                        description=f"Population stability index {item['psi']} exceeded the configured threshold against {reference_source}.",
                        evidence={"feature": item["feature"], "psi": item["psi"], "threshold": item["threshold"]},
                        recommendation="Compare the reference and current feature distributions before trusting model results.",
                        confidence="MEDIUM",
                        source="drift-engine",
                    )

            assessment.refresh_from_db()
            recalculate_assessment(assessment)
            assessment.status = SecurityAssessment.Status.COMPLETED
            assessment.completed_at = timezone.now()
            assessment.save(update_fields=["status", "completed_at"])
            version.status = "READY"
            version.save(update_fields=["status"])
            log_action(
                assessment.triggered_by,
                "assessment.completed",
                "SecurityAssessment",
                assessment.pk,
                {"risk_score": assessment.risk_score, "findings": assessment.findings.count()},
            )
            for policy in DeploymentPolicy.objects.filter(project=assessment.project, enabled=True):
                evaluate_policy(policy, assessment, user=assessment.triggered_by)

        notify("assessment.completed", {
            "assessment_id": assessment.pk,
            "risk_score": assessment.risk_score,
            "status": assessment.status,
            "project_id": assessment.project_id,
        })
        logger.info("Assessment %s completed: %s findings", assessment_id, assessment.findings.count())
        return assessment
    except Exception as exc:
        logger.exception("Assessment %s failed", assessment_id)
        with transaction.atomic():
            assessment.refresh_from_db()
            assessment.status = SecurityAssessment.Status.FAILED
            assessment.error = f"{type(exc).__name__}: {exc}"
            assessment.completed_at = timezone.now()
            assessment.save(update_fields=["status", "error", "completed_at"])
            version.status = "UPLOADED"
            version.save(update_fields=["status"])
            log_action(
                assessment.triggered_by,
                "assessment.failed",
                "SecurityAssessment",
                assessment.pk,
                {"error": assessment.error},
            )
        notify("assessment.failed", {
            "assessment_id": assessment.pk,
            "error": assessment.error,
            "project_id": assessment.project_id,
        })
        raise
