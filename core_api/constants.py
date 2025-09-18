from typing import Set
import os

# Current version of the REST API (.e.g:  https://www.myserver.com/api/v1/{proxy+})
API_VERSION = "v1"
API_PREFIX = f"/api/{API_VERSION}"

# API Gateway event fields
QUERY_STRING_PARAMETERS = "queryStringParameters"
PATH_PARAMETERS = "pathParameters"
BODY_PARAMETER = "body"

PRN = "prn"
ITEM_TYPE = "item_type"
EVENT_TYPE = "event_type"

# Attributes of Portfolio Facts
APPROVERS = "Approvers"
CONTACTS = "Contacts"
OWNER = "Owner"
REGION = "Region"
ENVIRONMENT = "Environment"

# Registry Model Hash Keys (yes, client and portfoio are lowercase)
CLIENT_KEY = "client"
PORTFOLIO_KEY = "portfolio"
CLIENT_PORTFOLIO_KEY = "ClientPortfolio"

# Registry Range Keys
APP_KEY = "AppRegex"
ZONE_KEY = "Zone"

# These are fields in the items table "core-automation-items"
PRN = "prn"
PARENT_PRN = "parent_prn"
NAME = "name"
ITEM_TYPE = "item_type"
CONTACT_EMAIL = "contact_email"

# MapAttribute fields
APP_PRN = "app_prn"
PORTFOLIO_PRN = "portfolio_prn"
BUILD_PRN = "build_prn"
BRANCH_PRN = "branch_prn"
COMPONENT_PRN = "component_prn"
SHORT_NAME = "short_name"

# Fields For build and component releases
STATUS = "status"
RELEASED_BUILD_PRN = "released_build_prn"
RELEASED_BUILD = "released_build"

# Date fields
UPDATED_AT = "updated_at"
CREATED_AT = "created_at"

# Query tags (for pagenation)
EARLIEST_TIME = "earliest_time"
LATEST_TIME = "latest_time"
DATA_PAGINATOR = "data_paginator"
SORT = "sort"
LIMIT = "limit"
ASCENDING = "ascending"

API_ID = "coreApiv1"
DOMAIN_PREFIX = "core"  # e.g. core.execute-api.us-east-1.amazonaws.com

API_LAMBDA_NAME = "core-automation-api-master"

# Standard HTTP headers used in AWS API Gateway
HDR_X_CORRELATION_ID = "X-Correlation-Id"
HDR_X_FORWARDED_FOR = "X-Forwarded-For"
HDR_X_FORWARDED_PROTO = "X-Forwarded-Proto"
HDR_AUTHORIZATION = "Authorization"
HDR_CONTENT_TYPE = "Content-Type"
HDR_ACCEPT = "Accept"
HDR_USER_AGENT = "User-Agent"


# JWT Configuration
SCK_TOKEN_COOKIE_NAME = "sck_token"
SCK_MFA_COOKIE_NAME = "sck_mfa_token"
SCK_TOKEN_REFRESH_SECONDS = 120  # 2 minutes
SCK_TOKEN_SESSION_MINUTES = os.getenv("SCK_TOKEN_SESSION_MINUTES", "30")

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
# Validate algorithm is supported
SUPPORTED_ALGORITHMS = ["HS256", "HS384", "HS512"]
if JWT_ALGORITHM not in SUPPORTED_ALGORITHMS:
    JWT_ALGORITHM = "HS256"

# Safe integer conversion with better error handling
try:
    JWT_ACCESS_HOURS = int(os.getenv("JWT_ACCESS_HOURS", "24"))
    if JWT_ACCESS_HOURS < 1 or JWT_ACCESS_HOURS > 168:  # 1 hour to 1 week
        JWT_ACCESS_HOURS = 24
except (ValueError, TypeError):
    JWT_ACCESS_HOURS = 24

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI", "http://localhost:8090/auth/github/callback")

ALLOWED_SCOPES: Set[str] = {
    "read",
    "write",
    "read:profile",
    "write:profile",
}

# Encryption key for credentials (32-byte base64url)
CRED_ENC_KEY_B64 = os.getenv("CRED_ENC_KEY", "")


# Abuse/cost controls (stateless; configurable via env)
REFRESH_MIN_INTERVAL_SECONDS = int(os.getenv("REFRESH_MIN_INTERVAL_SECONDS", "300"))  # 5 minutes

# Absolute session max age: after this many minutes from initial auth_time, refresh is denied
# and the client must re-authenticate. Defaults to 8 hours.
SCK_SESSION_ABSOLUTE_MAX_MINUTES = int(os.getenv("SCK_SESSION_ABSOLUTE_MAX_MINUTES", "480"))

ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
API_HOST = os.getenv("API_HOST", "http://localhost:8090")
CLIENT_HOST = os.getenv("CLIENT_HOST", "http://localhost:8080")


SMTP_ENABLE = os.getenv("SMTP_ENABLE", "false").lower() == "true"
SMTP_ADDRESS = os.getenv("SMTP_ADDRESS", "email-smtp.us-east-1.amazonaws.com")
SMTP_PORT = os.getenv("SMTP_PORT", 587)
SMTP_USER_NAME = os.getenv("SMTP_USER_NAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_DOMAIN = os.getenv("SMTP_DOMAIN", "jvj28.com")
SMTP_AUTHENTICATION = os.getenv("SMTP_AUTHENTICATION", "login")
SMTP_ENABLE_STARTTLS_AUTO = os.getenv("SMTP_ENABLE_STARTTLS_AUTO", "true").lower() == "true"

# none, peer, client_once,  fail_if_no_peer_cert
SMTP_OPENSSL_VERIFY_MODE = os.getenv("SMTP_OPENSSL_VERIFY_MODE", "none")
SMTP_CA_PATH = os.getenv("SMTP_CA_PATH", "/etc/ssl/certs")
SMTP_CA_FILE = os.getenv("SMTP_CA_FILE", "/etc/ssl/certs/ca-certificates.crt")

# SMTP Email User Settings
SMTP_EMAIL_FROM = os.getenv("SMTP_EMAIL_FROM", "no-reply@nodomain.com")
SMTP_EMAIL_DISPLAY_NAME = os.getenv("SMTP_EMAIL_DISPLAY_NAME", "Admin")
SMTP_EMAIL_REPLY_TO = os.getenv("SMTP_EMAIL_REPLY_TO", "noreply@nodomain.com")
SMTP_EMAIL_SUBJECT_PREFIX = os.getenv("SMTP_EMAIL_SUBJECT_PREFIX", "[core automation lab]")
