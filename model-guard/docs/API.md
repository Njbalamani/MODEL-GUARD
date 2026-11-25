# API reference

## Authentication

```bash
curl -X POST http://localhost:8000/api/auth/token/ \
  -d "username=admin&password=your-password"
```

Send the returned token in subsequent requests:

```text
Authorization: Token <token>
```

Session authentication is also available for browser clients.

## Upload

```bash
curl -X POST http://localhost:8000/api/upload/ \
  -H "Authorization: Token <token>" \
  -F "project_id=1" \
  -F "model_name=fraud-detector" \
  -F "version_label=v1" \
  -F "file=@samples/synthetic_model.json"
```

The response contains `model`, `version`, `assessment`, `sha256` and `status`.

## Reference datasets

Uploaded CSV baselines are used for drift checks when their columns cover the assessment features.

```bash
curl -X POST http://localhost:8000/api/reference-datasets/ \
  -H "Authorization: Token <token>" \
  -F "project=1" \
  -F "name=baseline" \
  -F "file=@baseline.csv"
```

`feature_names` and `rows` are populated from the CSV and are read-only. Invalid or oversized files are rejected.

## Review actions

Suppressions are created with `POST /api/suppressions/`; only administrators can change their state:

```bash
curl -X POST http://localhost:8000/api/suppressions/1/approve/ -H "Authorization: Token <token>"
curl -X POST http://localhost:8000/api/suppressions/1/revoke/ -H "Authorization: Token <token>"
```

Policies are evaluated against a completed assessment in the same project:

```bash
curl -X POST http://localhost:8000/api/policies/1/evaluate/ \
  -H "Authorization: Token <token>" \
  -H "Content-Type: application/json" \
  -d '{"assessment_id": 12}'
```

The response contains `result`, `passed` and `reasons`; a `PolicyEvaluation` is stored.

## Resources

| Endpoint | Purpose |
| --- | --- |
| `/api/me/` | Current user |
| `/api/projects/` | Projects |
| `/api/models/` | Uploaded models |
| `/api/versions/` | Model versions and hashes |
| `/api/assessments/` | Assessments |
| `/api/assessments/{id}/queue/` | Re-queue an assessment |
| `/api/findings/` | Vulnerability findings |
| `/api/suppressions/` | Finding suppressions (`approve` and `revoke` actions) |
| `/api/comments/` | Assessment comments |
| `/api/schedules/` | Rescan schedules |
| `/api/robustness/` | FGSM, PGD, L2_PGD, GAUSSIAN and PATCH results |
| `/api/explainability/` | SHAP or fallback importance with plot image |
| `/api/privacy/` | Experimental privacy indicators |
| `/api/reference-datasets/` | Uploaded CSV reference datasets |
| `/api/drift/` | Per-feature PSI drift results |
| `/api/policies/` | Deployment policies (`evaluate` action) |
| `/api/policy-evaluations/` | Recorded policy evaluations |
| `/api/reports/` | Signed PDF metadata and signatures |
| `/api/audit/` | Audit events |
| `/api/webhooks/` | Webhook endpoints (administrator only) |
| `/api/webhook-deliveries/` | Webhook delivery log (administrator only) |
| `/api/dashboard/summary/` | Aggregate posture |
| `/api/schema/` | OpenAPI schema |

## Authorization

All querysets are scoped to projects owned by or shared with the authenticated user. Administrative roles can access broader sets. Write operations require a non-viewer membership role. Suppression approval/revocation and webhook resources are administrator-only; policy evaluation requires write access to the policy project. Rescan intervals must be at least `MG_RESCAN_MIN_INTERVAL_MINUTES`.

## Error responses

- `400`: invalid upload, descriptor, reference CSV, suppression, schedule or request data.
- `403`: insufficient project permission or administrator-only action.
- `404`: resource not found or outside the accessible project set.
- `409`: assessment is already queued or running.
