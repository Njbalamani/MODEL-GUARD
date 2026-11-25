import hashlib
import hmac
import shutil
import tempfile
from datetime import timedelta
from unittest.mock import patch

import numpy as np
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from accounts.models import User
from analysis.diff_engine import compare_assessments
from analysis.drift_engine import run_drift_checks
from analysis.onnx_adapter import validate_onnx_file
from analysis.pipeline import run_assessment
from analysis.rescan import run_due_rescans
from assessments.models import (
    FindingSuppression, RescanSchedule, SecurityAssessment, VulnerabilityFinding,
)
from assessments.services import (
    activate_suppression, recalculate_assessment, revoke_suppression, visible_findings,
)
from audit.models import WebhookDelivery, WebhookEndpoint, log_action
from audit.notifications import notify
from modelregistry.models import ModelVersion, UploadedModel
from projects.models import DeploymentPolicy, Project, ReferenceDataset
from projects.services import evaluate_policy
from reports.models import GeneratedReport
from reports.services import generate_report
from reports.signing import verify_report
from robustness.models import RobustnessTest

TEST_MEDIA_ROOT = tempfile.mkdtemp(prefix="modelguard-features-tests-")


def _make_onnx_bytes():
    import onnx
    from onnx import TensorProto, helper

    node = helper.make_node("Relu", ["X"], ["Y"])
    graph = helper.make_graph(
        [node],
        "validated-graph",
        [helper.make_tensor_value_info("X", TensorProto.FLOAT, [None, 4])],
        [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [None, 4])],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)])
    model.ir_version = 10
    onnx.checker.check_model(model, full_check=True)
    return model.SerializeToString()


class DriftTests(SimpleTestCase):
    @override_settings(MG_DRIFT_PSI_THRESHOLD=0.2, MG_DRIFT_WATCH_THRESHOLD=0.1)
    def test_psi_statuses(self):
        rng = np.random.default_rng(4)
        baseline = rng.normal(0, 1, size=(240, 2))
        stable = baseline.copy()
        shifted = rng.normal(4, 1, size=(240, 2))
        stable_results = run_drift_checks(["a", "b"], stable, baseline)
        shifted_results = run_drift_checks(["a", "b"], shifted, baseline)
        self.assertTrue(all(item["status"] == "STABLE" for item in stable_results))
        self.assertTrue(all(item["status"] == "DRIFT" for item in shifted_results))


class OnnxTests(SimpleTestCase):
    @override_settings(MG_ENABLE_ONNX=True, MG_ONNX_MAX_NODES=100)
    def test_valid_onnx_model_is_accepted(self):
        with tempfile.TemporaryDirectory() as folder:
            path = f"{folder}/valid.onnx"
            with open(path, "wb") as handle:
                handle.write(_make_onnx_bytes())
            adapter, features = validate_onnx_file(path, "valid.onnx")
        self.assertEqual(features, ["onnx_feature_1", "onnx_feature_2", "onnx_feature_3", "onnx_feature_4"])
        probabilities = adapter.predict_proba(np.zeros((3, 4), dtype=np.float32))
        self.assertEqual(probabilities.shape, (3, 4))


@override_settings(MEDIA_ROOT=TEST_MEDIA_ROOT, MG_ENABLE_SHAP=False)
class FeatureWorkflowTests(TestCase):
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(TEST_MEDIA_ROOT, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        self.user = User.objects.create_user(
            username="owner", password="StrongPassphrase123!", role=User.Role.RESEARCHER
        )
        self.admin = User.objects.create_user(
            username="admin", password="StrongPassphrase123!", role=User.Role.ADMIN
        )
        self.project = Project.objects.create(owner=self.user, name="Feature Project")
        self.model = UploadedModel.objects.create(
            project=self.project, name="feature-model", created_by=self.user
        )

    def _version(self, label, content, extension, descriptor=False):
        checksum = hashlib.sha256(content).hexdigest()
        version = ModelVersion.objects.create(
            model=self.model,
            version_label=label,
            file=SimpleUploadedFile(f"{label}{extension}", content),
            original_name=f"{label}{extension}",
            sha256=checksum,
            size_bytes=len(content),
            file_format=extension,
            is_descriptor=descriptor,
            uploaded_by=self.user,
        )
        return version

    def _assessment(self, version, risk_score=0, completed=True):
        return SecurityAssessment.objects.create(
            model_version=version,
            project=self.project,
            triggered_by=self.user,
            status=SecurityAssessment.Status.COMPLETED if completed else SecurityAssessment.Status.PENDING,
            risk_score=risk_score,
        )

    def test_onnx_pipeline_uses_validated_runtime(self):
        version = self._version("onnx-v1", _make_onnx_bytes(), ".onnx")
        assessment = self._assessment(version, completed=False)
        with override_settings(MG_ENABLE_ONNX=True):
            run_assessment(assessment.pk)
        assessment.refresh_from_db()
        self.assertEqual(assessment.status, SecurityAssessment.Status.COMPLETED)
        self.assertTrue(assessment.findings.filter(title="Validated ONNX runtime adapter").exists())
        self.assertEqual(assessment.robustness_tests.count(), 5)
        self.assertEqual(assessment.privacy.status, "COMPLETED")

    def test_suppression_policy_report_and_revoke(self):
        version = self._version("suppress-v1", b"descriptor", ".json", True)
        assessment = self._assessment(version, risk_score=30)
        finding = VulnerabilityFinding.objects.create(
            assessment=assessment,
            severity="CRITICAL",
            category="Static",
            title="Critical issue",
            description="Description",
            evidence={},
            recommendation="Fix",
        )
        recalculate_assessment(assessment)
        policy = DeploymentPolicy.objects.create(
            project=self.project,
            name="Release gate",
            max_risk_score=0,
            blocked_severities=["CRITICAL"],
            created_by=self.user,
        )
        before = evaluate_policy(policy, assessment, user=self.user)
        self.assertFalse(before["passed"])

        suppression = FindingSuppression.objects.create(
            finding=finding, reason="Accepted risk", requested_by=self.user
        )
        activate_suppression(suppression, self.admin)
        recalculate_assessment(assessment)
        assessment.refresh_from_db()
        self.assertEqual(assessment.risk_score, 0)
        self.assertEqual(visible_findings(assessment), [])
        after = evaluate_policy(policy, assessment, user=self.user)
        self.assertTrue(after["passed"])

        report = generate_report(assessment, self.user)
        self.assertTrue(verify_report(report)["valid"])
        with report.file.open("wb") as handle:
            handle.write(b"tampered")
        self.assertFalse(verify_report(report)["valid"])

        revoke_suppression(suppression)
        recalculate_assessment(assessment)
        assessment.refresh_from_db()
        self.assertEqual(assessment.risk_score, 30)

    def test_rescan_command_queues_due_schedule(self):
        version = self._version("rescan-v1", b"descriptor", ".json", True)
        schedule = RescanSchedule.objects.create(
            model_version=version,
            project=self.project,
            created_by=self.user,
            interval_minutes=60,
            next_run_at=timezone.now() - timedelta(minutes=1),
        )
        with patch("analysis.rescan.dispatch_assessment") as dispatch:
            count = run_due_rescans()
        self.assertEqual(count, 1)
        self.assertEqual(SecurityAssessment.objects.count(), 1)
        self.assertEqual(dispatch.call_count, 1)
        schedule.refresh_from_db()
        self.assertGreater(schedule.next_run_at, timezone.now())

        SecurityAssessment.objects.update(status=SecurityAssessment.Status.COMPLETED)
        schedule.next_run_at = timezone.now() - timedelta(minutes=1)
        schedule.save(update_fields=["next_run_at"])
        with patch("analysis.rescan.dispatch_assessment") as dispatch:
            call_command("run_due_rescans")
        self.assertEqual(dispatch.call_count, 1)

    def test_reference_download_diff_and_comments_via_api(self):
        csv = b"latency_ms,packet_size\n1,10\n2,20\n3,30\n4,40\n5,50\n6,60\n7,70\n8,80\n9,90\n10,100\n"
        dataset = ReferenceDataset.objects.create(
            project=self.project,
            name="baseline",
            file=SimpleUploadedFile("baseline.csv", csv, content_type="text/csv"),
            uploaded_by=self.user,
            feature_names=["latency_ms", "packet_size"],
            rows=10,
        )
        self.assertEqual(dataset.rows, 10)
        self.client.login(username="owner", password="StrongPassphrase123!")
        response = self.client.get(reverse("projects:reference-list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "baseline")

        version_a = self._version("diff-a", b"a", ".json", True)
        version_b = self._version("diff-b", b"b", ".json", True)
        first = self._assessment(version_a, risk_score=10)
        second = self._assessment(version_b, risk_score=40)
        VulnerabilityFinding.objects.create(
            assessment=first, severity="LOW", category="Static", title="Only before",
            description="d", evidence={}, recommendation="r",
        )
        VulnerabilityFinding.objects.create(
            assessment=second, severity="HIGH", category="Static", title="Only after",
            description="d", evidence={}, recommendation="r",
        )
        RobustnessTest.objects.create(assessment=first, attack="FGSM", accuracy_drop=0.1)
        RobustnessTest.objects.create(assessment=second, attack="FGSM", accuracy_drop=0.4)
        comparison = compare_assessments(first, second)
        self.assertEqual(comparison["risk_delta"], 30)
        self.assertEqual([item.title for item in comparison["added"]], ["Only after"])
        self.assertEqual([item.title for item in comparison["removed"]], ["Only before"])
        self.assertEqual(comparison["robustness"][0]["delta"], 0.3)

        token = Token.objects.create(user=self.user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        comment = client.post("/api/comments/", {
            "assessment": first.pk, "body": "Reviewed and accepted."
        }, format="json")
        self.assertEqual(comment.status_code, 201)
        self.assertEqual(comment.data["user"], self.user.pk)
        for url in [
            "/api/suppressions/", "/api/comments/", "/api/schedules/", "/api/policies/",
            "/api/policy-evaluations/", "/api/reference-datasets/", "/api/drift/",
            "/api/webhooks/", "/api/webhook-deliveries/",
        ]:
            with self.subTest(url=url):
                self.assertEqual(client.get(url).status_code, 200)

    def test_admin_api_suppression_approval_policy_and_webhooks(self):
        from unittest.mock import patch

        version = self._version("api-v1", b"descriptor", ".json", True)
        assessment = self._assessment(version, risk_score=18)
        finding = VulnerabilityFinding.objects.create(
            assessment=assessment, severity="HIGH", category="Static", title="High issue",
            description="d", evidence={}, recommendation="r",
        )
        recalculate_assessment(assessment)
        policy = DeploymentPolicy.objects.create(
            project=self.project, name="API gate", max_risk_score=0,
            blocked_severities=["HIGH"], created_by=self.user,
        )
        suppression = FindingSuppression.objects.create(
            finding=finding, reason="API request", requested_by=self.user
        )
        token = Token.objects.create(user=self.admin)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

        approved = client.post(f"/api/suppressions/{suppression.pk}/approve/")
        self.assertEqual(approved.status_code, 200)
        suppression.refresh_from_db()
        self.assertEqual(suppression.status, FindingSuppression.Status.ACTIVE)
        assessment.refresh_from_db()
        self.assertEqual(assessment.risk_score, 0)

        evaluated = client.post(
            f"/api/policies/{policy.pk}/evaluate/", {"assessment_id": assessment.pk}, format="json"
        )
        self.assertEqual(evaluated.status_code, 200)
        self.assertTrue(evaluated.data["passed"])

        with patch("config.viewsets.validate_webhook_url", return_value="https://example.com/hook"):
            created = client.post("/api/webhooks/", {
                "name": "SIEM", "url": "https://example.com/hook", "secret": "top-secret",
                "events": ["assessment.completed"], "active": True,
            }, format="json")
        self.assertEqual(created.status_code, 201)
        self.assertNotIn("secret", created.data)
        self.assertEqual(WebhookEndpoint.objects.count(), 1)

        revoked = client.post(f"/api/suppressions/{suppression.pk}/revoke/")
        self.assertEqual(revoked.status_code, 200)
        assessment.refresh_from_db()
        self.assertEqual(assessment.risk_score, 18)

    @override_settings(MG_ALLOW_PRIVATE_WEBHOOKS=True, MG_WEBHOOK_TIMEOUT=1)
    def test_signed_webhook_delivery(self):
        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        endpoint = WebhookEndpoint.objects.create(
            name="Local SIEM",
            url="http://127.0.0.1:9/hook",
            secret="webhook-secret",
            events=["assessment.completed"],
            created_by=self.user,
        )
        captured = {}

        def fake_urlopen(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return FakeResponse()

        with patch("audit.notifications.urllib.request.urlopen", side_effect=fake_urlopen):
            deliveries = notify("assessment.completed", {"assessment_id": 1})
        self.assertEqual(len(deliveries), 1)
        delivery = WebhookDelivery.objects.get()
        self.assertEqual(delivery.status, "DELIVERED")
        self.assertEqual(captured["timeout"], 1)
        headers = {name.lower(): value for name, value in captured["request"].header_items()}
        expected = hmac.new(b"webhook-secret", captured["request"].data, hashlib.sha256).hexdigest()
        self.assertEqual(headers["x-modelguard-signature"], expected)

    def test_new_pages_render(self):
        version = self._version("pages-v1", b"descriptor", ".json", True)
        self._assessment(version)
        self.client.login(username="owner", password="StrongPassphrase123!")
        urls = [
            reverse("assessments:schedules"),
            reverse("assessments:schedule-create", kwargs={"version_id": version.pk}),
            reverse("projects:policy-list"),
            reverse("projects:policy-create", kwargs={"project_id": self.project.pk}),
            reverse("projects:reference-list"),
            reverse("projects:reference-upload", kwargs={"project_id": self.project.pk}),
            reverse("audit:export-page"),
            reverse("models:compare", kwargs={"pk": self.model.pk}),
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)
        self.assertEqual(self.client.get(reverse("audit:webhook-list")).status_code, 302)
        self.client.login(username="admin", password="StrongPassphrase123!")
        self.assertEqual(self.client.get(reverse("audit:webhook-list")).status_code, 200)
