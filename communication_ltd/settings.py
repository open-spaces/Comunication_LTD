"""
Django settings for Communication_LTD project.

CRITICAL: VULNERABLE_MODE controls whether the app uses vulnerable code paths
(raw SQL string concatenation, unescaped HTML output) or secure ones
(parameterized queries, auto-escaping). Toggle for the two required submissions.
"""
import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# VULNERABILITY TOGGLE
# ---------------------------------------------------------------------------
# True  => Part B vulnerable submission (Stored XSS + SQL injection demos work)
# False => Part B secure submission     (mitigations active)
# Override with env var: VULNERABLE_MODE=0/1
# ---------------------------------------------------------------------------
VULNERABLE_MODE = os.environ.get('VULNERABLE_MODE', '1') == '1'

# ---------------------------------------------------------------------------
# Load password policy from config file
# ---------------------------------------------------------------------------
CONFIG_PATH = BASE_DIR / 'config.json'
with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
    APP_CONFIG = json.load(f)

PASSWORD_POLICY = APP_CONFIG['password_policy']
RESET_TOKEN_CONFIG = APP_CONFIG['reset_token']
HMAC_CONFIG = APP_CONFIG['hmac']

# ---------------------------------------------------------------------------
# Standard Django settings
# ---------------------------------------------------------------------------
SECRET_KEY = 'django-insecure-CHANGE-ME-FOR-PRODUCTION-beta-key-9f7a2b1c3d4e'
DEBUG = True
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'accounts',
    'customers',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'communication_ltd.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'accounts.context_processors.vulnerable_mode',
            ],
        },
    },
]

WSGI_APPLICATION = 'communication_ltd.wsgi.application'

# ---------------------------------------------------------------------------
# Database - PostgreSQL by default (per spec). Set USE_SQLITE=1 for fast local.
# ---------------------------------------------------------------------------
USE_SQLITE = os.environ.get('USE_SQLITE', '0') == '1'

if USE_SQLITE:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.environ.get('DB_NAME', 'communication_ltd'),
            'USER': os.environ.get('DB_USER', 'postgres'),
            'PASSWORD': os.environ.get('DB_PASSWORD', 'postgres'),
            'HOST': os.environ.get('DB_HOST', 'localhost'),
            'PORT': os.environ.get('DB_PORT', '5432'),
        }
    }

# Default Django password validators are NOT used - we implement our own
# per the assignment's config-file-driven policy.
AUTH_PASSWORD_VALIDATORS = []

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ---------------------------------------------------------------------------
# Email - console backend for development. The reset token will print to stdout.
# Swap to SMTP for real email delivery.
# ---------------------------------------------------------------------------
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
DEFAULT_FROM_EMAIL = 'noreply@comunication-ltd.example'

# Login redirect
LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/customers/'
