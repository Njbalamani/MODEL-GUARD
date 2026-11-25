# Database design

## Entities

- `accounts.User`: platform identity with role and organization.
- `projects.Project`: owner-scoped container for models and assessments.
- `projects.ProjectMember`: membership role for collaborative access.
- `projects.DeploymentPolicy`: project release gate with maximum risk score, blocked severities and report requirement.
- `projects.PolicyEvaluation`: PASS/FAIL result and reasons for a policy against an assessment.
- `projects.ReferenceDataset`: uploaded CSV baseline with detected feature names and row count.
- `modelregistry.UploadedModel`: logical model inside a project.
- `modelregistry.ModelVersion`: uploaded artifact with SHA-256, format, size and metadata.
- `assessments.SecurityAssessment`: one assessment run for one model version.
- `assessments.VulnerabilityFinding`: evidence-backed finding attached to an assessment.
- `assessments.FindingSuppression`: reason, status, approver and optional expiry for hiding a finding.
- `assessments.AssessmentComment`: attributed user note on an assessment.
- `assessments.RescanSchedule`: enabled interval with next and last run times for a model version.
- `robustness.RobustnessTest`: FGSM, PGD, L2_PGD, GAUSSIAN or PATCH result with accuracy and confidence deltas.
- `explainability.ExplainabilityResult`: method, feature importances, limitations and PNG plot image.
- `privacy.PrivacyAssessment`: experimental confidence-gap indicator and limitations.
- `analysis.DataDriftResult`: per-feature PSI, status, threshold and reference source.
- `reports.GeneratedReport`: PDF artifact with SHA-256 and HMAC signature metadata.
- `audit.AuditLog`: user action trail with object references and detail JSON.
- `audit.WebhookEndpoint`: signed webhook URL, shared secret and event subscriptions.
- `audit.WebhookDelivery`: webhook event, payload, delivery status and response metadata.

## Relationships

```text
User ──< Project ──< UploadedModel ──< ModelVersion ──< RescanSchedule
  │          │                              │
  │          ├──< DeploymentPolicy ──< PolicyEvaluation
  │          ├──< ReferenceDataset          │
  │          └──< SecurityAssessment ───────┘
  │                         │
  │                         ├──< VulnerabilityFinding ──< FindingSuppression
  │                         ├──< AssessmentComment
  │                         ├──< RobustnessTest
  │                         ├─── ExplainabilityResult
  │                         ├─── PrivacyAssessment
  │                         ├──< DataDriftResult
  │                         └──< GeneratedReport
  └──< AuditLog

WebhookEndpoint ──< WebhookDelivery
```

## Constraints and indexes

- Project names are unique per owner.
- Model names are unique per project.
- Version labels are unique per model.
- Robustness attack is unique per assessment.
- Drift result is unique per assessment and feature.
- Only one `ACTIVE` suppression is allowed per finding; suppressions are indexed by status and expiry.
- Deployment policy names and reference dataset names are unique per project.
- Findings are indexed by assessment, severity and category.
- Assessments are indexed by project, status, model version and creation time.
- Model versions are indexed by model, creation time, format and SHA-256.
- Rescan schedules are indexed by enabled state and next run time.
- Webhook deliveries are indexed by endpoint and creation time.

## Integrity

Every upload is hashed with SHA-256 before storage. The hash is persisted with the `ModelVersion` and included in PDF reports. Generated report files are also hashed and carry an HMAC-SHA256 signature plus signing timestamp. Approval, revocation or expiry of a suppression recalculates the assessment risk score and summary. Drift results retain the reference dataset name and thresholds used. Webhook deliveries retain the signed payload and response or error metadata for audit.
