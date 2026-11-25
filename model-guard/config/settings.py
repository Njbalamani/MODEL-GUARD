"""Production-oriented settings for ModelGuard.

PostgreSQL is the default database. SQLite is available only for local/offline tests.
Uploaded model files are never deserialized or executed by the application.
"""
from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).lower() in {"1", "true", "yes", "on"}


SECRET_KEY = os.environ.get("MG_SECRET_KEY", "dev-only-insecure-key-change-me-before-deployment")
DEBUG = env_bool("MG_DEBUG", True)
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("MG_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",") if h.strip()]

LOCAL_APPS = [
    "accounts",
    "projects",
    "modelregistry",
    "assessments",
    "robustness",
    "explainability",
    "privacy",
    "reports",
    "audit",
    "dashboard",
    "docs",
    "analysis",
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework.authtoken",
    *LOCAL_APPS,
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "config.middleware.SecurityHeadersMiddleware",
]

ROOT_URLCONF = "config.urls"
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "dashboard.context_processors.platform_context",
            ],
        },
    },
]
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

_database_url = os.environ.get("DATABASE_URL")
if _database_url:
    parsed = urlparse(_database_url)
    options = parse_qs(parsed.query)
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": parsed.path.lstrip("/"),
            "USER": parsed.username or "",
            "PASSWORD": parsed.password or "",
            "HOST": parsed.hostname or "localhost",
            "PORT": str(parsed.port or 5432),
            "OPTIONS": {key: value[0] for key, value in options.items()},
        }
    }
else:
    engine = os.environ.get("DB_ENGINE", "django.db.backends.postgresql")
    if engine in {"sqlite", "sqlite3"}:
        engine = "django.db.backends.sqlite3"
    DATABASES = {
        "default": {
            "ENGINE": engine,
            "NAME": os.environ.get("DB_NAME", str(BASE_DIR / "db.sqlite3")),
            "USER": os.environ.get("DB_USER", "modelguard"),
            "PASSWORD": os.environ.get("DB_PASSWORD", "modelguard"),
            "HOST": os.environ.get("DB_HOST", "localhost"),
            "PORT": os.environ.get("DB_PORT", "5432"),
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 10}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]
AUTH_USER_MODEL = "accounts.User"
LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "dashboard:home"
LOGOUT_REDIRECT_URL = "accounts:login"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"
        if not DEBUG
        else "whitenoise.storage.CompressedStaticFilesStorage"
    },
}
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"
FILE_UPLOAD_MAX_MEMORY_SIZE = 4 * 1024 * 1024
DATA_UPLOAD_MAX_MEMORY_SIZE = 256 * 1024 * 1024
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.TokenAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 25,
    "DEFAULT_THROTTLE_CLASSES": ["rest_framework.throttling.UserRateThrottle"],
    "DEFAULT_THROTTLE_RATES": {"user": os.environ.get("MG_API_RATE_LIMIT", "1000/hour")},
}

CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")
CELERY_TASK_ALWAYS_EAGER = env_bool("CELERY_TASK_ALWAYS_EAGER", False)
CELERY_TASK_EAGER_PROPAGATES = False
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1

MG_MAX_UPLOAD_BYTES = int(os.environ.get("MG_MAX_UPLOAD_BYTES", 200 * 1024 * 1024))
MG_ALLOWED_EXTENSIONS = {
    ".json", ".onnx", ".pt", ".pth", ".pkl", ".pickle", ".joblib",
    ".safetensors", ".npz", ".npy", ".h5", ".keras",
}
MG_EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".sh", ".bat", ".cmd", ".ps1",
    ".py", ".pyc", ".ipynb", ".js", ".vbs", ".msi", ".bin",
}
MG_SAMPLE_ROWS = int(os.environ.get("MG_SAMPLE_ROWS", 400))
MG_FGSM_EPSILON = float(os.environ.get("MG_FGSM_EPSILON", 0.12))
MG_PGD_EPSILON = float(os.environ.get("MG_PGD_EPSILON", 0.12))
MG_PGD_STEPS = int(os.environ.get("MG_PGD_STEPS", 8))
MG_PGD_STEP_SIZE = float(os.environ.get("MG_PGD_STEP_SIZE", 0.03))
MG_PRIVACY_GAP_THRESHOLD = float(os.environ.get("MG_PRIVACY_GAP_THRESHOLD", 0.15))
MG_ENABLE_SHAP = env_bool("MG_ENABLE_SHAP", True)
MG_ENABLE_ART = env_bool("MG_ENABLE_ART", False)
MG_ART_PATH = os.environ.get("MG_ART_PATH", "")
MG_ASSESSMENT_TIMEOUT = int(os.environ.get("MG_ASSESSMENT_TIMEOUT", 300))
MG_ENABLE_ONNX = env_bool("MG_ENABLE_ONNX", True)
MG_ONNX_MAX_NODES = int(os.environ.get("MG_ONNX_MAX_NODES", 1000))
MG_ONNX_ALLOWED_DOMAINS = {
    item.strip() for item in os.environ.get("MG_ONNX_ALLOWED_DOMAINS", ",ai.onnx").split(",")
}
MG_DRIFT_PSI_THRESHOLD = float(os.environ.get("MG_DRIFT_PSI_THRESHOLD", 0.2))
MG_DRIFT_WATCH_THRESHOLD = float(os.environ.get("MG_DRIFT_WATCH_THRESHOLD", 0.1))
MG_PATCH_FEATURES = int(os.environ.get("MG_PATCH_FEATURES", 1))
MG_GAUSSIAN_SIGMA = float(os.environ.get("MG_GAUSSIAN_SIGMA", 0.15))
MG_WEBHOOK_TIMEOUT = float(os.environ.get("MG_WEBHOOK_TIMEOUT", 3.0))
MG_WEBHOOK_MAX_BYTES = int(os.environ.get("MG_WEBHOOK_MAX_BYTES", 1024 * 1024))
MG_ALLOW_PRIVATE_WEBHOOKS = env_bool("MG_ALLOW_PRIVATE_WEBHOOKS", False)
MG_REPORT_SIGNING_KEY = os.environ.get("MG_REPORT_SIGNING_KEY", os.environ.get("MG_SECRET_KEY", "dev-only-insecure-key-change-me-before-deployment"))
MG_RESCAN_MIN_INTERVAL_MINUTES = int(os.environ.get("MG_RESCAN_MIN_INTERVAL_MINUTES", 15))

CELERY_BEAT_SCHEDULE = {
    "run-due-rescans": {
        "task": "modelguard.run_due_rescans",
        "schedule": timedelta(minutes=5),
    }
}

SECURE_SSL_REDIRECT = env_bool("MG_SECURE_SSL_REDIRECT", False)
SESSION_COOKIE_SECURE = env_bool("MG_SESSION_COOKIE_SECURE", False)
CSRF_COOKIE_SECURE = env_bool("MG_CSRF_COOKIE_SECURE", False)
SECURE_HSTS_SECONDS = int(os.environ.get("MG_SECURE_HSTS_SECONDS", 0))
SECURE_HSTS_INCLUDE_SUBDOMAINS = bool(SECURE_HSTS_SECONDS)
SECURE_HSTS_PRELOAD = bool(SECURE_HSTS_SECONDS)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"standard": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "standard"}},
    "root": {"handlers": ["console"], "level": os.environ.get("MG_LOG_LEVEL", "INFO")},
    "loggers": {
        "django.security": {"handlers": ["console"], "level": "WARNING", "propagate": False},
        "modelguard": {"handlers": ["console"], "level": os.environ.get("MG_LOG_LEVEL", "INFO"), "propagate": False},
    },
}
