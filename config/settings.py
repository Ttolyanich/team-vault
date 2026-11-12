import os
from urllib.parse import urlsplit
import dj_database_url

BASE_DIR = __import__("pathlib").Path(__file__).resolve().parent.parent
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
VAULT_MASTER_KEY = os.environ["VAULT_MASTER_KEY"]
DEBUG = False
APP_NAME = os.getenv("APP_NAME", "Рабочие доступы")
PUBLIC_URL = os.getenv("PUBLIC_URL", "http://localhost:8081").rstrip("/")
ALLOWED_HOSTS = [host.strip() for host in os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1,*").split(",") if host.strip()]
CSRF_TRUSTED_ORIGINS = list({
    origin.strip()
    for origin in (os.getenv("CSRF_TRUSTED_ORIGINS", "").split(",") + [PUBLIC_URL])
    if origin.strip()
})
SECURE_COOKIES = os.getenv("SECURE_COOKIES", "true").lower() == "true"
SESSION_COOKIE_SECURE = CSRF_COOKIE_SECURE = SECURE_COOKIES
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = CSRF_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = int(os.getenv("SESSION_TTL_SECONDS", "3600"))
SESSION_SAVE_EVERY_REQUEST = False
TRUSTED_PROXY_IPS = [value.strip() for value in os.getenv("TRUSTED_PROXY_IPS", "").split(",") if value.strip()]
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
# Only expose the backend through the configured trusted host proxy.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
INSTALLED_APPS = [
    "django.contrib.auth", "django.contrib.contenttypes", "django.contrib.sessions",
    "django.contrib.messages", "django.contrib.staticfiles", "vault",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware", "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware", "django.middleware.common.CommonMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware", "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware", "vault.middleware.SecurityHeadersMiddleware",
]
ROOT_URLCONF = "config.urls"
TEMPLATES = [{"BACKEND": "django.template.backends.django.DjangoTemplates", "DIRS": [BASE_DIR / "templates"], "APP_DIRS": True,
              "OPTIONS": {"context_processors": ["django.template.context_processors.request", "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages", "vault.context.common"]}}]
WSGI_APPLICATION = "config.wsgi.application"
DATABASES = {"default": dj_database_url.parse(os.environ["DATABASE_URL"], conn_max_age=60)}
AUTH_USER_MODEL = "vault.User"
AUTH_PASSWORD_VALIDATORS = [{"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 16}}]
LOGIN_URL = "/login/"
LANGUAGE_CODE = "ru"
TIME_ZONE = "Asia/Qyzylorda"
USE_TZ = True
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
ENTRA_TENANT_ID = os.getenv("ENTRA_TENANT_ID", "")
ENTRA_CLIENT_ID = os.getenv("ENTRA_CLIENT_ID", "")
ENTRA_CLIENT_SECRET = os.getenv("ENTRA_CLIENT_SECRET", "")
LOCAL_ADMIN_USERNAME = os.getenv("LOCAL_ADMIN_USERNAME", "admin")
LOCAL_ADMIN_PASSWORD = os.getenv("LOCAL_ADMIN_PASSWORD", "")
LOGGING = {"version": 1, "disable_existing_loggers": False,
           "handlers": {"console": {"class": "logging.StreamHandler"}},
           "root": {"handlers": ["console"], "level": "WARNING"}}
