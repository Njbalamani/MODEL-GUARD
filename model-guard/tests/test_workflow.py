import hashlib
import json
import shutil
import tempfile
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from analysis.pipeline import run_assessment
from assessments.models import SecurityAssessment
from modelregistry.models import ModelVersion
from projects.models import Project
from reports.models import GeneratedReport

User = get_user_model()
DESCRIPTOR = {
    "schema": "modelguard.descriptor.v1",
    "model_type": "decision_tree",
    "features": ["latency_ms", "packet_size", "error_rate", "request_volume"],
    "parameters": {"max_depth": 4, "min_samples_leaf": 2},
    "seed": 7,
}
TEST_MEDIA_ROOT = tempfile.mkdtemp(prefix="modelguard-workflow-tests-")


@override_settings(MEDIA_ROOT=TEST_MEDIA_ROOT, MG_ENABLE_SHAP=False)
class WorkflowTests(TestCase):
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(TEST_MEDIA_ROOT, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        self.password = "StrongPassphrase123!"
        self.user = User.objects.create_user(
            username="owner", password=self.password, role=User.Role.RESEARCHER
        )
        self.project = Project.objects.create(owner=self.user, name="Fraud Models")
        self.client.login(username="owner", password=self.password)

    def _descriptor_upload(self):
        payload = json.dumps(DESCRIPTOR).encode()
        return SimpleUploadedFile("synthetic_model.json", payload, content_type="application/json")

    def test_web_upload_creates_version_assessment_and_report(self):
        with patch("modelregistry.views.dispatch_assessment") as dispatch:
            response = self.client.post(reverse("models:upload"), {
                "project": self.project.pk,
                "model_name": "tree-model",
                "version_label": "v1",
                "description": "Synthetic descriptor",
                "file": self._descriptor_upload(),
            })
        self.assertEqual(response.status_code, 302)
        dispatch.assert_called_once()
        version = ModelVersion.objects.get()
        self.assertTrue(version.is_descriptor)
        self.assertEqual(version.sha256, hashlib.sha256(json.dumps(DESCRIPTOR).encode()).hexdigest())
        assessment = SecurityAssessment.objects.get()
        self.assertTrue(response.url.endswith(f"/assessments/{assessment.pk}/"))

        run_assessment(assessment.pk)
        detail = self.client.get(reverse("assessments:detail", kwargs={"pk": assessment.pk}))
        self.assertEqual(detail.status_code, 200)
        self.assertContains(detail, "Risk score")
        self.assertContains(detail, "Explainability")

        generate = self.client.get(reverse("reports:generate", kwargs={"assessment_id": assessment.pk}))
        report = GeneratedReport.objects.get()
        self.assertEqual(generate.status_code, 302)
        self.assertTrue(report.file.name.endswith(".pdf"))
        self.assertEqual(len(report.sha256), 64)

    def test_core_pages_render(self):
        urls = [
            reverse("dashboard:home"),
            reverse("projects:list"),
            reverse("projects:create"),
            reverse("models:list"),
            reverse("models:upload"),
            reverse("assessments:list"),
            reverse("reports:list"),
            reverse("docs:home"),
            reverse("docs:architecture"),
            reverse("docs:er"),
            reverse("docs:api"),
            reverse("schema"),
        ]
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)

    def test_project_isolation_on_assessment_detail(self):
        assessment = SecurityAssessment.objects.create(
            model_version=ModelVersion.objects.create(
                model=self.user.uploaded_models.create(
                    project=self.project, name="isolated", created_by=self.user
                ),
                version_label="v1",
                file=self._descriptor_upload(),
                original_name="synthetic_model.json",
                sha256="0" * 64,
                size_bytes=100,
                file_format=".json",
                is_descriptor=True,
                uploaded_by=self.user,
            ),
            project=self.project,
            triggered_by=self.user,
        )
        other = User.objects.create_user(username="outsider", password=self.password)
        self.client.login(username="outsider", password=self.password)
        response = self.client.get(reverse("assessments:detail", kwargs={"pk": assessment.pk}))
        self.assertEqual(response.status_code, 404)

    def test_api_upload_and_authentication(self):
        token = Token.objects.create(user=self.user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        with patch("config.api_views.dispatch_assessment") as dispatch:
            response = client.post("/api/upload/", {
                "project_id": self.project.pk,
                "model_name": "api-model",
                "version_label": "v1",
                "file": self._descriptor_upload(),
            }, format="multipart")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data["model"], self.project.models.get(name="api-model").pk)
        dispatch.assert_called_once()

        summary = client.get("/api/dashboard/summary/")
        self.assertEqual(summary.status_code, 200)
        self.assertEqual(summary.data["models"], 1)

    def test_signup_cannot_escalate_role(self):
        self.client.logout()
        response = self.client.post(reverse("accounts:signup"), {
            "username": "newuser",
            "email": "newuser@example.com",
            "organization": "Example",
            "role": "ADMIN",
            "password1": "AnotherStrongPassphrase123!",
            "password2": "AnotherStrongPassphrase123!",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(User.objects.get(username="newuser").role, User.Role.RESEARCHER)
