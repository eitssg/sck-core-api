import os
from typing import Set


# JWT Configuration
SCK_TOKEN_COOKIE_NAME = "sck_token"

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")
JWT_SESSION_MINUTES = os.getenv("JWT_SESSION_MINUTES", "30")
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
}

# Encryption key for credentials (32-byte base64url)
CRED_ENC_KEY_B64 = os.getenv("CRED_ENC_KEY", "")


# Abuse/cost controls (stateless; configurable via env)
REFRESH_MIN_INTERVAL_SECONDS = int(os.getenv("REFRESH_MIN_INTERVAL_SECONDS", "300"))  # 5 minutes

ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
API_HOST = os.getenv("API_HOST", "localhost")
API_PORT = int(os.getenv("API_PORT", "8090"))
