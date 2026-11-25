# Deployment

## Local development

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

## Production with Docker Compose

1. Create `.env` from `.env.example` and set a strong `MG_SECRET_KEY` and a distinct `MG_REPORT_SIGNING_KEY`.
2. Set `MG_DEBUG=false`, allowed hosts and secure cookie/HTTPS settings.
3. Run `docker compose up --build -d`.
4. Create the first administrator with `docker compose exec web python manage.py createsuperuser`.
5. Keep `MG_ALLOW_PRIVATE_WEBHOOKS=false` unless a trusted internal receiver is required.

The compose stack provides PostgreSQL, Redis, the web service, a Celery worker and a Celery beat scheduler that queues due rescans. Static files are served by WhiteNoise; media files use a named volume.

## Production without Docker

Required services:

- Python 3.12 virtual environment
- PostgreSQL database
- Redis broker
- Gunicorn or another WSGI server
- Celery worker process
- Celery beat process, or a scheduled `python manage.py run_due_rescans` invocation

Commands:

```bash
pip install -r requirements.txt
python manage.py migrate --noinput
python manage.py collectstatic --noinput
celery -A config worker --loglevel=info
celery -A config beat --loglevel=info
gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 3 --timeout 120
```

`python manage.py run_due_rescans` queues due scans once; Celery beat runs the `modelguard.run_due_rescans` task every five minutes.

## Environment settings

All settings use the `MG_` prefix except database and Celery variables. Important values:

- `MG_SECRET_KEY`
- `MG_DEBUG`
- `MG_ALLOWED_HOSTS`
- `DB_ENGINE`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`
- `DATABASE_URL` as an alternative to individual `DB_*` values
- `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`
- `MG_MAX_UPLOAD_BYTES`, `MG_SAMPLE_ROWS`
- `MG_ENABLE_SHAP`, `MG_ENABLE_ART`, `MG_ASSESSMENT_TIMEOUT`
- `MG_ENABLE_ONNX`, `MG_ONNX_MAX_NODES`, `MG_ONNX_ALLOWED_DOMAINS` (comma-separated, default `,ai.onnx`, where the empty entry is the standard ONNX domain)
- `MG_FGSM_EPSILON`, `MG_PGD_EPSILON`, `MG_PGD_STEPS`, `MG_PGD_STEP_SIZE`, `MG_PATCH_FEATURES`, `MG_GAUSSIAN_SIGMA`
- `MG_PRIVACY_GAP_THRESHOLD`, `MG_DRIFT_PSI_THRESHOLD`, `MG_DRIFT_WATCH_THRESHOLD`
- `MG_RESCAN_MIN_INTERVAL_MINUTES`
- `MG_REPORT_SIGNING_KEY`
- `MG_WEBHOOK_TIMEOUT`, `MG_WEBHOOK_MAX_BYTES`, `MG_ALLOW_PRIVATE_WEBHOOKS`
- `MG_SECURE_SSL_REDIRECT`, `MG_SESSION_COOKIE_SECURE`, `MG_CSRF_COOKIE_SECURE`, `MG_SECURE_HSTS_SECONDS`

## Health and operations

- Monitor `SecurityAssessment.FAILED` records and `error` text.
- Monitor Celery worker and beat availability and Redis connectivity.
- Check `WebhookDelivery` records for failures and review endpoint event subscriptions.
- Review suppression expiry and rescan `next_run_at` values.
- Back up PostgreSQL and the media volume, including reference datasets and signed reports.
- Rotate `MG_REPORT_SIGNING_KEY` and webhook secrets; rotating the signing key invalidates verification of older reports.
- Rotate report and model archives according to organizational retention policy.
