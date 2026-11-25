# Security model

## Uploaded artifacts

ModelGuard does not trust model files. Upload validation applies:

- extension allow-list and executable extension rejection;
- 200 MB default size limit;
- magic-byte checks for JSON, safetensors, NPY, NPZ, PyTorch and ZIP-like formats;
- SHA-256 hashing before storage;
- static byte scanning for suspicious execution and deserialization tokens;
- ZIP entry inspection without extraction;
- ONNX signature mismatch detection;
- structured validation before any ONNX graph is executed.

Uploaded files are never passed to `pickle.load`, `joblib.load`, `torch.load`, `keras.models.load_model` or arbitrary user-provided code. ONNX Runtime is reached only through the validated adapter below.

## Validated ONNX execution

`MG_ENABLE_ONNX` is enabled by default. A graph is executed only if it:

- is non-empty, at most 100 MB and within `MG_MAX_UPLOAD_BYTES`, with a valid protobuf signature;
- passes `onnx.checker.check_model(..., full_check=True)` and contains no external tensor data;
- has at most `MG_ONNX_MAX_NODES` nodes (default 1000);
- uses only domains in `MG_ONNX_ALLOWED_DOMAINS` (default `""` and `ai.onnx`, configurable as a comma-separated environment variable; an empty entry represents the default ONNX domain) and no control-flow, custom or `Trilu` operators;
- has exactly one float `[batch, features]` input with a fixed 2-64 feature dimension and exactly one tensor output.

Inference uses the CPU execution provider with graph optimizations and memory patterns disabled. Validation failures create a high-severity finding and no inference. ONNX results remain demonstrations on synthetic inputs and are not certification.

## Descriptor execution

Descriptor-based executable tests require `modelguard.descriptor.v1`; validated ONNX graphs use an internal descriptor for feature names. Validation enforces:

- exact root keys;
- supported model type;
- two to 64 unique string feature names;
- allow-listed numeric parameters with bounds;
- bounded integer seed.

Reconstruction uses only `LogisticRegression`, `DecisionTreeClassifier`, `RandomForestClassifier` and `GradientBoostingClassifier` with solver fixed where needed. Synthetic data is generated locally and bounded by `MG_SAMPLE_ROWS`. Explanation importance plots are rendered to PNG with Matplotlib and stored as media artifacts.

## Robustness and data drift

- FGSM uses `MG_FGSM_EPSILON`; PGD and L2_PGD use `MG_PGD_EPSILON`, `MG_PGD_STEPS` and `MG_PGD_STEP_SIZE`; GAUSSIAN uses `MG_GAUSSIAN_SIGMA`; PATCH perturbs `MG_PATCH_FEATURES` features.
- A completed attack with accuracy drop above 0.25 creates a high-severity finding and every attack result records its limitations.
- Uploaded CSV reference datasets are checked for size, at least ten rows, required feature columns and mostly numeric values; missing values are median-filled.
- PSI at or above `MG_DRIFT_PSI_THRESHOLD` (default 0.2) marks `DRIFT` and creates a medium-severity finding; PSI at or above `MG_DRIFT_WATCH_THRESHOLD` (default 0.1) marks `WATCH`. Without an eligible reference dataset a seeded synthetic baseline is used.

## Review workflow

- Findings can be suppressed with a reason. Only administrators can approve or revoke a suppression; active, unexpired suppressions are excluded from PDF reports and policy checks and from risk recalculation. Approval and revocation are audited and recalculate the assessment risk; expiry is evaluated dynamically when findings are read.
- Assessment comments are project-scoped and attributed to their author.
- Scheduled rescans respect `MG_RESCAN_MIN_INTERVAL_MINUTES` (default 15) and are driven by Celery beat or `python manage.py run_due_rescans`.
- Deployment policies evaluate completed assessments against maximum risk score, blocked severities and the report requirement; PASS/FAIL results with reasons are stored.
- Version diffs compare risk, findings and per-attack accuracy drops between completed assessments.

## Signed reports and webhooks

- Generated PDFs store a SHA-256 digest plus an HMAC-SHA256 signature keyed by `MG_REPORT_SIGNING_KEY` (defaults to `MG_SECRET_KEY`); verification recomputes both. Set a distinct signing key in production.
- Webhook endpoints are administrator-only, carry a shared secret and subscribe to `assessment.completed`, `assessment.failed`, `report.generated`, `suppression.approved` and `rescan.due`.
- Requests carry `X-ModelGuard-Event` and `X-ModelGuard-Signature` (HMAC-SHA256). Body size is bounded by `MG_WEBHOOK_MAX_BYTES` (default 1 MiB) and delivery timeout by `MG_WEBHOOK_TIMEOUT` (default 3 seconds); each attempt is recorded as a `WebhookDelivery`.
- URLs must be HTTPS and must not resolve to private, loopback, link-local or reserved addresses unless `MG_ALLOW_PRIVATE_WEBHOOKS` is explicitly enabled. Keep it disabled in production.

## Web hardening

- CSRF protection on all state-changing web routes.
- Security headers middleware with CSP, `X-Content-Type-Options`, `X-Frame-Options`, referrer policy, permissions policy and COOP.
- Password validation with a ten-character minimum.
- Project-scoped authorization for web views, API viewsets and uploads.
- Audit CSV export is limited to the requester unless the user is an administrator.
- Optional HTTPS redirect, secure cookies and HSTS via environment settings.

## Operational guidance

- Replace `MG_SECRET_KEY` in every deployed environment.
- Run behind HTTPS.
- Use a dedicated PostgreSQL role with least privilege.
- Keep media and report storage access-controlled.
- Run Celery workers and beat with the same hardened image as the web service.
- Rotate `MG_REPORT_SIGNING_KEY` and webhook secrets according to policy; rotating the signing key invalidates verification of older reports.
- Keep `MG_ALLOW_PRIVATE_WEBHOOKS` disabled unless a trusted internal receiver requires it.
- Treat generated reports, reference datasets and audit exports as sensitive artifacts.
