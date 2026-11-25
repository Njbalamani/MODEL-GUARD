import hashlib
import json
import shutil
import tempfile
from pathlib import Path

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase, override_settings

from accounts.models import User
from analysis.descriptor import MODEL_TYPES, build_estimator, build_synthetic_dataset, parse_descriptor
from analysis.pipeline import run_assessment
from analysis.static_inspection import inspect_file
from assessments.models import SecurityAssessment
from audit.models import AuditLog
from modelregistry.models import ModelVersion, UploadedModel
from projects.models import Project

DESCRIPTOR = {
    "schema": "modelguard.descriptor.v1",
    "model_type": "logistic_regression",
    "features": ["latency_ms", "packet_size", "error_rate", "request_volume"],
    "parameters": {"C": 1.0, "max_iter": 300},
    "seed": 42,
}

TEST_MEDIA_ROOT = tempfile.mkdtemp(prefix="modelguard-analysis-tests-")


class DescriptorTests(SimpleTestCase):
    def test_valid_descriptor_and_estimator(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "model.json"
            path.write_text(json.dumps(DESCRIPTOR), encoding="utf-8")
            descriptor = parse_descriptor(path)
        self.assertEqual(descriptor["model_type"], "logistic_regression")
        self.assertEqual(len(descriptor["features"]), 4)
        X, y = build_synthetic_dataset(descriptor, rows=120)
        estimator = build_estimator(descriptor, X, y)
        self.assertIn("LogisticRegression", type(estimator).__name__)
        self.assertEqual(len(set(y)), 2)
        self.assertEqual(set(MODEL_TYPES), {
            "logistic_regression", "decision_tree", "random_forest", "gradient_boosting"
        })

    def test_unknown_descriptor_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.json"
            payload = dict(DESCRIPTOR)
            payload["arbitrary_code"] = "print(1)"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ValueError):
                parse_descriptor(path)

    def test_unsupported_model_type_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.json"
            payload = dict(DESCRIPTOR)
            payload["model_type"] = "arbitrary_executable"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ValueError):
                parse_descriptor(path)


class StaticInspectionTests(SimpleTestCase):
    def test_unsafe_token_is_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "malicious.pkl"
            path.write_bytes(b"cos\nsystem\n(S'id'\ntR.__reduce__pickle.loads")
            _, findings = inspect_file(path, ".pkl")
        severities = {item["severity"] for item in findings}
        self.assertIn("CRITICAL", severities)
        self.assertIn("HIGH", severities)

    def test_descriptor_finding_is_informational(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "model.json"
            path.write_text(json.dumps(DESCRIPTOR), encoding="utf-8")
            descriptor = parse_descriptor(path)
            _, findings = inspect_file(path, ".json", descriptor)
        self.assertTrue(any(item["severity"] == "INFO" for item in findings))


@override_settings(MEDIA_ROOT=TEST_MEDIA_ROOT, MG_ENABLE_SHAP=False)
class AssessmentPipelineTests(TestCase):
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(TEST_MEDIA_ROOT, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        self.user = User.objects.create_user(
            username="analyst", password="Passphrase123!", role=User.Role.ANALYST
        )
        self.project = Project.objects.create(owner=self.user, name="Security Research")
        self.model = UploadedModel.objects.create(
            project=self.project, name="fraud-detector", created_by=self.user
        )

    def _create_version(self, name, content, extension, is_descriptor):
        checksum = hashlib.sha256(content).hexdigest()
        upload = SimpleUploadedFile(name, content, content_type="application/octet-stream")
        version = ModelVersion.objects.create(
            model=self.model,
            version_label="v1",
            file=upload,
            original_name=name,
            sha256=checksum,
            size_bytes=len(content),
            file_format=extension,
            is_descriptor=is_descriptor,
            metadata={},
            uploaded_by=self.user,
        )
        assessment = SecurityAssessment.objects.create(
            model_version=version, project=self.project, triggered_by=self.user
        )
        return version, assessment

    def test_descriptor_assessment_completes(self):
        payload = json.dumps(DESCRIPTOR).encode()
        _, assessment = self._create_version("synthetic_model.json", payload, ".json", True)
        run_assessment(assessment.pk)
        assessment.refresh_from_db()
        self.assertEqual(assessment.status, SecurityAssessment.Status.COMPLETED)
        self.assertEqual(assessment.robustness_tests.count(), 5)
        self.assertEqual(
            set(assessment.robustness_tests.values_list("attack", flat=True)),
            {"FGSM", "PGD", "L2_PGD", "GAUSSIAN", "PATCH"},
        )
        self.assertEqual(assessment.explainability.status, "FALLBACK")
        self.assertEqual(assessment.privacy.status, "COMPLETED")
        self.assertGreaterEqual(assessment.findings.count(), 1)
        self.assertGreaterEqual(assessment.risk_score, 0)
        self.assertLessEqual(assessment.risk_score, 100)
        self.assertTrue(AuditLog.objects.filter(action="assessment.completed").exists())

    def test_binary_artifact_is_static_only(self):
        payload = b"cos\nsystem\n(S'id'\ntR.__reduce__pickle.loads"
        _, assessment = self._create_version("legacy.pkl", payload, ".pkl", False)
        run_assessment(assessment.pk)
        assessment.refresh_from_db()
        self.assertEqual(assessment.status, SecurityAssessment.Status.COMPLETED)
        self.assertEqual(assessment.privacy.method, "none")
        self.assertEqual(assessment.robustness_tests.count(), 5)
        self.assertTrue(all(
            test.status == "UNSUPPORTED" for test in assessment.robustness_tests.all()
        ))
        self.assertTrue(assessment.findings.filter(
            title="Executable analysis unavailable for this artifact"
        ).exists())
