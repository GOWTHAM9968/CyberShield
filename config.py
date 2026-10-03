import os

from pathlib import Path

from dotenv import load_dotenv


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "change-this-development-secret-key"
)


# ============================================================
# DATABASE
# ============================================================

DATABASE_PATH = BASE_DIR / "cybershield.db"


# ============================================================
# UPLOAD CONFIGURATION
# ============================================================

UPLOAD_FOLDER = BASE_DIR / "uploads"

MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB


# ============================================================
# ALLOWED FILE EXTENSIONS
# ============================================================

ALLOWED_UPLOAD_EXTENSIONS = {
    "txt",
    "pdf",
    "png",
    "jpg",
    "jpeg",
    "doc",
    "docx",
    "zip",
    "csv",
    "log"
}


# ============================================================
# MAIL CONFIGURATION
# ============================================================

MAIL_SERVER = os.getenv(
    "MAIL_SERVER",
    "smtp.gmail.com"
)

MAIL_PORT = int(
    os.getenv(
        "MAIL_PORT",
        "587"
    )
)

MAIL_USE_TLS = os.getenv(
    "MAIL_USE_TLS",
    "true"
).lower() == "true"

MAIL_USE_SSL = os.getenv(
    "MAIL_USE_SSL",
    "false"
).lower() == "true"

MAIL_USERNAME = os.getenv(
    "MAIL_USERNAME",
    ""
)

MAIL_PASSWORD = os.getenv(
    "MAIL_PASSWORD",
    ""
)

MAIL_DEFAULT_SENDER = os.getenv(
    "MAIL_DEFAULT_SENDER",
    MAIL_USERNAME
)


# ============================================================
# APPLICATION SETTINGS
# ============================================================

APP_NAME = "CyberShield"

APP_VERSION = "1.0.0"

DEBUG = os.getenv(
    "DEBUG",
    "true"
).lower() == "true"


# ============================================================
# SECURITY SETTINGS
# ============================================================

SESSION_COOKIE_HTTPONLY = True

SESSION_COOKIE_SAMESITE = "Lax"

# Keep False for local development.
# Enable only when deploying behind HTTPS.
SESSION_COOKIE_SECURE = os.getenv(
    "SESSION_COOKIE_SECURE",
    "false"
).lower() == "true"


# ============================================================
# NETWORK SCANNER
# ============================================================

NETWORK_SCAN_TIMEOUT = float(
    os.getenv(
        "NETWORK_SCAN_TIMEOUT",
        "1.0"
    )
)

DEFAULT_SCAN_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    3306,
    3389,
    8080
]


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY",
    ""
)

ABUSEIPDB_API_KEY = os.getenv(
    "ABUSEIPDB_API_KEY",
    ""
)


# ============================================================
# DEVELOPMENT INFORMATION
# ============================================================

print(f"{APP_NAME} v{APP_VERSION}")

if DEBUG:
    print("Debug mode: ENABLED")