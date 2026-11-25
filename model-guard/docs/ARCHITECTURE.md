# Architecture

ModelGuard is a layered Django application. The presentation layer uses server-rendered templates plus a small JavaScript module for theme management, charts and Three.js visualizations. The domain layer is split into project access, model registry, assessment lifecycle, review workflows, reporting, policies and audit logging. The analysis layer is isolated in `analysis/`.

## Request flow

1. A user creates a project or uses an existing project.
2. A model artifact is uploaded through the web form or `/api/upload/`.
3. `modelregistry.services.validate_and_store` validates extension, size, magic bytes and, for JSON descriptors, the strict descriptor schema.
4. `ModelVersion` and `SecurityAssessment` records are created and an audit event is written.
5. `analysis.tasks.dispatch_assessment` sends a Celery task when Redis is reachable, otherwise it starts a daemon-thread fallback.
6. `analysis.pipeline.run_assessment` inspects bytes, validates ONNX graphs when `MG_ENABLE_ONNX` is set, and runs FGSM, PGD, L2_PGD, GAUSSIAN and PATCH attacks plus explainability, privacy and PSI drift checks for executable artifacts.
7. Findings, robustness results, drift status, policy evaluations, risk score and summary are persisted.
8. Reports are exported as hashed, signed PDFs and webhook notifications are dispatched for completed work.
9. Scheduled rescans are queued by Celery beat or `python manage.py run_due_rescans`; suppressions, comments and version diffs support review of results.

## Analysis isolation

The application never calls `pickle.load`, `joblib.load`, `torch.load` or arbitrary model inference APIs on uploaded artifacts. An ONNX graph is executed only after protobuf signature checks, `onnx.checker` validation, node and domain limits, no external tensor data, disallowed-operator rejection and fixed float input/output shape checks; its `InferenceSession` is CPU-only with graph optimizations disabled. Descriptor models are reconstructed from allow-listed scikit-learn classes with bounded numeric parameters. Feature matrices are generated locally with NumPy from a seeded RNG. Uploaded CSV reference datasets are parsed with pandas only after column, row-count and numeric-content checks, and never used to execute code.

## Asynchronous execution

Celery is the preferred execution path. Local development can use an in-process daemon thread. `SecurityAssessment.status` records `PENDING`, `RUNNING`, `COMPLETED` or `FAILED`; `error` records the exception type and message on failure. Re-queuing resets status and clears stale results. `CELERY_BEAT_SCHEDULE` runs `modelguard.run_due_rescans` every five minutes; the equivalent one-shot command is `python manage.py run_due_rescans`. Each due `RescanSchedule` creates a new assessment, emits `rescan.queued` and `rescan.due` events and honours `MG_RESCAN_MIN_INTERVAL_MINUTES`.

## Review and governance

- Active, unexpired suppressions hide findings from PDF reports and policy checks and are excluded from risk recalculation; approval and revocation are administrator actions and are audited.
- Assessment comments are attributed to their author and scoped to the assessment project.
- Enabled deployment policies evaluate completed assessments against maximum risk score, blocked severities and the report requirement, storing PASS/FAIL results with reasons.
- Generated PDFs are hashed with SHA-256 and HMAC-signed with `MG_REPORT_SIGNING_KEY`; verification recomputes both values.
- Webhook endpoints subscribe to a fixed event set, sign deliveries with HMAC-SHA256 and record each attempt as a `WebhookDelivery`.
- Version comparison reports risk delta, added and removed findings, and per-attack accuracy-drop deltas between completed assessments.

## Frontend

- `static/css/main.css` defines the dark/light glassmorphism theme.
- `static/js/app.js` manages theme, navigation, Chart.js charts and Three.js graphs.
- `static/vendor/` contains pinned local copies of Three.js, GSAP and Chart.js.
- Explanation importance plots are rendered server-side with Matplotlib and stored as PNG images on the `ExplainabilityResult`.
