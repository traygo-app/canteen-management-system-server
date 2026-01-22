import os
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

from environ import Env

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# typing and default env values
env = Env(
    DEBUG=(bool, False),
    SECRET_KEY=(str, ""),
    ALLOWED_HOSTS=(list, ["127.0.0.1", "localhost"]),
    SQL_ENGINE=(str, "django.db.backends.sqlite3"),
    SQL_DATABASE=(str, str(BASE_DIR / "db.sqlite3")),
    SQL_USER=(str, "user"),
    SQL_PASSWORD=(str, "password"),
    SQL_HOST=(str, "localhost"),
    SQL_PORT=(str, "5432"),
    LOG_DIR=(str, "logs"),
)
env.read_env()  # for docker env
env.read_env(f"{BASE_DIR}/.env")  # for local runserver

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env("SECRET_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env("DEBUG")

ALLOWED_HOSTS = env("ALLOWED_HOSTS")

# Maintenance mode
MAINTENANCE_MODE = env("MAINTENANCE_MODE", default=False, cast=bool)

# Application definition

UNFOLD_APPS = [
    "unfold",
    "unfold.contrib.filters",
    "unfold.contrib.forms",
    "unfold.contrib.inlines",
    "unfold.contrib.import_export",
    "unfold.contrib.guardian",
    "unfold.contrib.simple_history",
    "unfold.contrib.location_field",
    "unfold.contrib.constance",
]

STD_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

REMOTE_APPS = [
    "rest_framework",
    "drf_spectacular",
    "django_filters",
    "rest_framework_simplejwt.token_blacklist",
    "imagekit",
    "corsheaders",
    "sendgrid_backend",
]

LOCAL_APPS = [
    "apps.authentication",
    "apps.common",
    "apps.menus",
    "apps.orders",
    "apps.wallets",
    "apps.users",
    "apps.webhooks",
]

INSTALLED_APPS = [*UNFOLD_APPS, *STD_APPS, *REMOTE_APPS, *LOCAL_APPS]

AUTH_USER_MODEL = "users.User"

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "TOKEN_OBTAIN_SERIALIZER": "authentication.serializers.TokenWithRoleObtainPairSerializer",
}

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "apps.common.middleware.MaintenanceModeMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

CORS_ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://localhost:8080",
    "https://localhost",
    "https://api.traygo.app",
    "https://traygo.app",
]
CORS_ALLOW_CREDENTIALS = True

# CSRF protection settings
CSRF_COOKIE_SECURE = not DEBUG  # Only send CSRF cookie over HTTPS in production
CSRF_COOKIE_SAMESITE = "Lax"  # Prevents CSRF attacks from external sites
CSRF_COOKIE_HTTPONLY = False  # Allow JavaScript to read cookie for API usage

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:8000",
    "http://localhost:8080",
    "https://api.traygo.app",
    "https://traygo.app",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

REST_FRAMEWORK = {
    "DATETIME_FORMAT": "%Y-%m-%dT%H:%M:%SZ",
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_RENDERER_CLASSES": ("rest_framework.renderers.JSONRenderer",),
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_FILTER_BACKENDS": ("django_filters.rest_framework.DjangoFilterBackend",),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 20,
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "apps.common.throttling.UnverifiedUserThrottle",
        "apps.common.throttling.VerifiedUserThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "5/minute",
        "unverified": "20/minute",
        "verified": "100/minute",
        "sensitive": "1/minute",
    },
    "NUM_PROXIES": 1,
}

SPECTACULAR_SETTINGS = {
    "TITLE": "Traygo API",
    "DESCRIPTION": "Buy grechka, borsch and kompot easily.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "SCHEMA_PATH_PREFIX": r"/api/v1",
    "SERVERS": [
        {"url": "https://api.traygo.app", "description": "Deployed server"},
        {"url": "http://localhost:8000", "description": "Local Development server"},
    ],
}
UNFOLD = {
    "SITE_TITLE": "TrayGo administration",
    "SITE_HEADER": "TrayGo administration",
    "SITE_BRAND": "TrayGo",
    "COLORS": {
        "primary": {
            "50": "#edf2fe",
            "100": "#d9e3fd",
            "200": "#b3c7fb",
            "300": "#8daaf9",
            "400": "#678ef7",
            "500": "#4874e4",
            "600": "#3a5ec4",
            "700": "#2c49a3",
            "800": "#1f3482",
            "900": "#132062",
            "950": "#0a143d",
        },
    },
    "SIDEBAR": {
        "show_search": True,
        "show_all_applications": True,
        "navigation": [
            {
                "title": "Sessions",
                "icon": "devices",
                "items": [
                    {
                        "title": "Active Sessions",
                        "icon": "devices",
                        "link": "/admin/authentication/sessions/",
                    },
                ],
            },
            {
                "title": "Users",
                "icon": "people",
                "items": [
                    {
                        "title": "Users",
                        "icon": "person",
                        "link": "/admin/users/user/",
                    },
                ],
            },
            {
                "title": "Menus",
                "icon": "restaurant_menu",
                "items": [
                    {
                        "title": "Categories",
                        "icon": "category",
                        "link": "/admin/menus/category/",
                    },
                    {
                        "title": "Items",
                        "icon": "lunch_dining",
                        "link": "/admin/menus/item/",
                    },
                    {
                        "title": "Menus",
                        "icon": "menu_book",
                        "link": "/admin/menus/menu/",
                    },
                    {
                        "title": "Menu Items",
                        "icon": "list",
                        "link": "/admin/menus/menuitem/",
                    },
                ],
            },
            {
                "title": "Orders",
                "icon": "shopping_cart",
                "items": [
                    {
                        "title": "Orders",
                        "icon": "receipt_long",
                        "link": "/admin/orders/order/",
                    },
                    {
                        "title": "Order Items",
                        "icon": "list_alt",
                        "link": "/admin/orders/orderitem/",
                    },
                ],
            },
            {
                "title": "Wallets",
                "icon": "account_balance_wallet",
                "items": [
                    {
                        "title": "Balances",
                        "icon": "payments",
                        "link": "/admin/wallets/balance/",
                    },
                    {
                        "title": "Transactions",
                        "icon": "swap_horiz",
                        "link": "/admin/wallets/transaction/",
                    },
                ],
            },
        ],
    },
}

# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": env("SQL_ENGINE"),
        "NAME": env("SQL_DATABASE"),
        "USER": env("SQL_USER"),
        "PASSWORD": env("SQL_PASSWORD"),
        "HOST": env("SQL_HOST"),
        "PORT": env("SQL_PORT"),
    }
}

# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "Europe/Chisinau"

USE_I18N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"


# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

RBAC_FORCE_UPDATE_PERMISSIONS = False

# Email backend
SMTP_HOST = env("SMTP_HOST", default="")
SENDGRID_API_KEY = env("SENDGRID_API_KEY", default="")

if SENDGRID_API_KEY:
    EMAIL_BACKEND = "sendgrid_backend.SendgridBackend"
    SENDGRID_API_KEY = SENDGRID_API_KEY
    SENDGRID_SANDBOX_MODE_IN_DEBUG = env("SENDGRID_SANDBOX_MODE_IN_DEBUG", default=True, cast=bool)
elif SMTP_HOST:
    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
    EMAIL_HOST = SMTP_HOST
    EMAIL_PORT = env("SMTP_PORT", default=587, cast=int)
    EMAIL_HOST_USER = env("SMTP_USER", default="")
    EMAIL_HOST_PASSWORD = env("SMTP_PASS", default="")
    EMAIL_USE_TLS = env("EMAIL_USE_TLS", default=True, cast=bool)
    EMAIL_USE_SSL = env("EMAIL_USE_SSL", default=False, cast=bool)
else:
    # Use console backend for development when email is not configured
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default="noreply@traygo.app")

# Redis
REDIS_HOST = env("REDIS_HOST", default="localhost")
REDIS_PORT = env("REDIS_PORT", default=6379, cast=int)
REDIS_PASSWORD = env("REDIS_PASSWORD", default="")

# MFA
MFA_FERNET_KEY = env("MFA_FERNET_KEY", default="")

# Microsoft OAuth Settings
MICROSOFT_CLIENT_ID = env("MICROSOFT_CLIENT_ID", default="")
MICROSOFT_CLIENT_SECRET = env("MICROSOFT_CLIENT_SECRET", default="")
MICROSOFT_TENANT_ID = env("MICROSOFT_TENANT_ID", default="common")
MICROSOFT_REDIRECT_URI = env("MICROSOFT_REDIRECT_URI", default="http://localhost:8000/auth/microsoft/callback")

# Frontend URL for redirects after OAuth
FRONTEND_URL = env("FRONTEND_URL", default="http://localhost:8080")

# Stripe Settings
STRIPE_SECRET_KEY = env("STRIPE_SECRET_KEY", default="")
STRIPE_PUBLISHABLE_KEY = env("STRIPE_PUBLISHABLE_KEY", default="")
STRIPE_WEBHOOK_SECRET = env("STRIPE_WEBHOOK_SECRET", default="")
STRIPE_RETURN_URL = env("STRIPE_RETURN_URL", default=f"{FRONTEND_URL}/wallet/top-up/return")

# Stripe Top-up Limits
STRIPE_MIN_TOP_UP = Decimal(env("STRIPE_MIN_TOP_UP", default="5.00"))

# Logging Configuration
LOG_DIR = BASE_DIR / env("LOG_DIR")

# Auto-create logs directory if it doesn't exist
os.makedirs(LOG_DIR, exist_ok=True)  # noqa: PTH103

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{asctime} [{levelname}] {name} {module} - {message}",
            "datefmt": "%Y-%m-%d %H:%M:%S",
            "style": "{",
        },
        "simple": {
            "format": "[{levelname}] {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
            "level": "DEBUG" if DEBUG else "INFO",
        },
        "debug_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": LOG_DIR / "debug.log",
            "maxBytes": 10 * 1024 * 1024,  # 10MB
            "backupCount": 10,
            "formatter": "verbose",
            "level": "DEBUG",
        },
        "info_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": LOG_DIR / "info.log",
            "maxBytes": 10 * 1024 * 1024,  # 10MB
            "backupCount": 10,
            "formatter": "verbose",
            "level": "INFO",
        },
        "warning_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": LOG_DIR / "warning.log",
            "maxBytes": 10 * 1024 * 1024,  # 10MB
            "backupCount": 10,
            "formatter": "verbose",
            "level": "WARNING",
        },
        "error_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": LOG_DIR / "error.log",
            "maxBytes": 10 * 1024 * 1024,  # 10MB
            "backupCount": 10,
            "formatter": "verbose",
            "level": "ERROR",
        },
    },
    "loggers": {
        # Django loggers
        "django": {
            "handlers": ["console", "info_file", "warning_file", "error_file"],
            "level": "INFO",
            "propagate": False,
        },
        "django.request": {
            "handlers": ["console", "error_file"],
            "level": "ERROR",
            "propagate": False,
        },
        "django.db.backends": {
            "handlers": ["debug_file"] if DEBUG else [],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": False,
        },
        # Application loggers
        "apps.authentication": {
            "handlers": ["console", "debug_file", "info_file", "warning_file", "error_file"],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": False,
        },
        "apps.wallets": {
            "handlers": ["console", "debug_file", "info_file", "warning_file", "error_file"],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": False,
        },
        "apps.orders": {
            "handlers": ["console", "debug_file", "info_file", "warning_file", "error_file"],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": False,
        },
        "apps.users": {
            "handlers": ["console", "debug_file", "info_file", "warning_file", "error_file"],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": False,
        },
        "apps.webhooks": {
            "handlers": ["console", "debug_file", "info_file", "warning_file", "error_file"],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": False,
        },
        "apps.common": {
            "handlers": ["console", "debug_file", "info_file", "warning_file", "error_file"],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": False,
        },
    },
    "root": {
        "handlers": ["console", "debug_file", "info_file", "warning_file", "error_file"],
        "level": "DEBUG" if DEBUG else "INFO",
    },
}
STRIPE_MAX_TOP_UP = Decimal(env("STRIPE_MAX_TOP_UP", default="500.00"))
