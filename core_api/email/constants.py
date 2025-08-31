import os

### Email Services

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
