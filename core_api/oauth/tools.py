from typing import Optional, Dict, Tuple
import time
import base64
import os
import json
import uuid
import bcrypt
from datetime import datetime, timedelta, timezone

from fastapi import Request

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from jwcrypto import jwe
from pydantic import BaseModel, Field, model_validator

import jwt
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK

import core_logging as log

from core_db.response import SuccessResponse
from core_db.profile.model import UserProfile
from core_db.profile.actions import ProfileActions
from core_db.oauth.actions import RateLimitActions

from .constants import CRED_ENC_KEY_B64, JWT_SECRET_KEY, JWT_ALGORITHM, SESSION_JWT_MINUTES, JWT_EXPIRATION_HOURS


def validate_token(token: str) -> dict:
    """
    Validate and decode a JWT token.

    Args:
        token (str): JWT token string to validate

    Returns:
        dict: Decoded JWT payload if valid

    Raises:
        jwt.InvalidTokenError: If token is invalid, expired, or malformed
        jwt.ExpiredSignatureError: If token has expired
        jwt.InvalidSignatureError: If token signature is invalid
    """
    return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])


class JwtPayload(BaseModel):
    sub: str = Field(...)
    iat: int | None = Field(None, description="Issued at time as UNIX timestamp")
    exp: int | None = Field(None, description="Expiration time as UNIX timestamp")
    typ: str | None = Field(None, description="Token type")
    iss: str | None = Field(None, description="Issuer")
    jti: str | None = Field(None, description="Unique token identifier")
    ttl: int | None = Field(None, description="Token time-to-live in minutes")
    cid: str | None = Field(None, description="Client ID")
    cnm: str | None = Field(None, description="Client Name")
    scp: str | None = Field(None, description="Scope of the Access token")
    enc: str | None = Field(None, description="Encrypted AWS STS temporary credentials (JWE)")

    @model_validator(mode="before")
    def validate_fields(cls, values: dict) -> dict:
        if "typ" not in values:
            values["typ"] = "access"
        if "iss" not in values:
            values["iss"] = "sck-core-api"

        ttl = int(values.get("ttl", 1440))
        if ttl > 1440:  # 24 hours max
            ttl = 1440
        elif ttl < 5:  # 5 minutes min
            ttl = 5
        values["ttl"] = ttl

        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=ttl)

        if "iat" not in values:
            values["iat"] = int(now.timestamp())
        if "exp" not in values:
            values["exp"] = int(exp.timestamp())
        if "jti" not in values:
            values["jti"] = uuid.uuid4().hex

        if "scp" not in values:
            values["scp"] = "read"

        return values

    def model_dump(self, **kwargs) -> dict:
        kwargs.setdefault("exclude_none", True)
        return super().model_dump(**kwargs)


def is_password_compliant(password: str) -> bool:
    """
    Check if the provided password meets complexity requirements.

    Args:
        password (str): Password string to check.

    Returns:
        bool: True if password is compliant, False otherwise.
    """
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char in "!@#$%^&*()-+" for char in password):
        return False
    return True


def encrypt_credentials(aws_access_key: str | None = None, aws_secret_key: str | None = None, password: str | None = None) -> dict:
    """
    Encrypt AWS credentials with server key using JWE.

    Creates an envelope that can store password hash and/or AWS credentials.
    Both are optional - allows creating users without AWS credentials initially.

    Args:
        aws_access_key (str, optional): AWS access key ID
        aws_secret_key (str, optional): AWS secret access key
        password (str, optional): User password for verification hash

    Returns:
        dict: Encrypted credential envelope containing:
              - password (str, optional): bcrypt hash if password provided
              - aws_credentials (str, optional): JWE-encrypted credentials if provided
              - encryption (str): Always "jwe" if aws_credentials present
              - created_at (str): ISO timestamp of creation

    Examples:
        >>> # User signup with password only (no AWS creds yet)
        >>> envelope = encrypt_credentials(password="user_password")
        >>>
        >>> # User signup with both password and AWS creds
        >>> envelope = encrypt_credentials("AKIA...", "secret...", "user_password")
        >>>
        >>> # SSO user with AWS creds (no password)
        >>> envelope = encrypt_credentials("AKIA...", "secret...")
    """
    envelope = {"created_at": datetime.now(timezone.utc).isoformat()}

    # If password provided, hash it for verification
    if password:
        if not is_password_compliant(password):
            raise ValueError("Password must be at least 8 characters")
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
        envelope["Password"] = password_hash.decode("utf-8")

    # If AWS credentials provided, encrypt them
    if aws_access_key and aws_secret_key:
        creds = encrypt_aws_credentials(aws_access_key, aws_secret_key)
        if creds:
            envelope.update(creds)

    return envelope


def _b64pad(v: str) -> str:
    """
    Pad a base64url string to a valid length for decoding.

    Base64url encoding may omit padding characters. This function
    adds the necessary padding to make the string decodable.

    Args:
        v (str): Base64url string without padding.

    Returns:
        str: Padded base64 string safe to decode.

    Examples:
        >>> padded = _b64pad("SGVsbG8")  # "Hello" in base64url
        >>> decoded = base64.urlsafe_b64decode(padded)
    """
    return v + "=" * (-len(v) % 4)


# Global JWK for credential encryption/decryption
def get_encryption_key() -> JWK | None:

    if not CRED_ENC_KEY_B64:
        log.warning("CRED_ENC_KEY not configured - cannot encrypt/decrypt credentials")
        return None

    key_bytes = base64.urlsafe_b64decode(_b64pad(CRED_ENC_KEY_B64))
    l = len(key_bytes)
    if l != 32:
        log.error(f"CRED_ENC_KEY must be 32 bytes (base64url-decoded), got {l} bytes")
        return None

    try:
        return JWK(kty="oct", k=base64.urlsafe_b64encode(key_bytes).decode())
    except Exception as e:
        log.error(f"Failed to create JWK from CRED_ENC_KEY: {e}")
        return None


def encrypt_aws_credentials(aws_access_key: str, aws_secret_key: str) -> None | Dict[str, str]:
    """
    Encrypt AWS credentials using JWE.

    The return is a "partial" profiles dict containing the encrypted AWS credentials.

    Example:
        {
            "AwsCredentials": "jwe-encrypted-credentials",
            "Encryption": "jwe"
        }

        You can use this value to insert into the user profile "Credentials" field.

    Example:

        This is a full example of a user profile with encrypted credentials:
        {
            "Credentials": {
                "Password": "bcrypt-hash",
                "AwsCredentials": "jwe-encrypted-credentials",
                "Encryption": "jwe"
            }
        }

    Args:
        aws_access_key (str): AWS access key ID
        aws_secret_key (str): AWS secret access key

    Returns:
        dict: Encrypted AWS credentials in a partial Profiles dict or None if encryption fails

    """
    if not aws_access_key or not aws_secret_key:
        return None

    credentials = {
        "AccessKeyId": aws_access_key,
        "SecretAccessKey": aws_secret_key,
    }

    # We may be saving the password only
    return {"AwsCredentials": encrypt_creds(credentials), "Encryption": "jwe"}


def encrypt_creds(credentials: dict) -> str:
    """
    Encrypt credentials dictionary using JWE (JSON Web Encryption).

    Args:
        credentials (dict): Dictionary containing sensitive credential data

    Returns:
        str: JWE-encrypted string of the credentials

    Raises:
        ValueError: If credentials cannot be serialized or encrypted
        Exception: If encryption key is invalid or missing
    """
    enc_key = get_encryption_key()

    if not enc_key:
        raise RuntimeError("Encryption key not available")

    cred_json = json.dumps(credentials)
    jwe_creds = JWE(cred_json.encode("utf-8"), alg="dir", enc="A256GCM")
    jwe_creds.add_recipient(enc_key)

    return jwe_creds.serialize(compact=True)


def decrypt_creds(encrypted_credentials: str) -> dict:
    """
    Decrypt JWE-encrypted credentials back to dictionary.

    Args:
        encrypted_credentials (str): JWE-encrypted credential string

    Returns:
        dict: Decrypted credentials dictionary

    Raises:
        ValueError: If encrypted string is malformed or cannot be decrypted
        Exception: If decryption key is invalid
    """
    enc_key = get_encryption_key()

    if not enc_key:
        raise RuntimeError("Decryption key not available")

    try:
        jwe_creds = JWE()
        jwe_creds.deserialize(encrypted_credentials)
        jwe_creds.decrypt(enc_key)
        return json.loads(jwe_creds.payload.decode("utf-8"))
    except Exception as e:
        log.error(f"Failed to decrypt credentials: {e}")
        raise ValueError("Failed to decrypt credentials")


def get_user_access_key(user_id: str, password: Optional[str] = None) -> dict:
    """
    Load and decrypt user's AWS credentials from database profile.

    Retrieves user profile, validates password if provided, and extracts
    AWS access key and secret key from encrypted credentials envelope.

    Args:
        user_id (str): User identifier to lookup credentials for
        password (str, optional): User password for validation. If None, skips password check.

    Returns:
        dict: Dictionary containing AWS access key and secret key

    Raises:
        ValueError: If password validation fails or credentials are malformed
        Exception: If profile lookup fails or decryption fails
    """
    try:
        if not user_id:
            raise ValueError("User ID is required for validation.")

        response: SuccessResponse = ProfileActions.get(client="core", user_id=user_id, profile_name="default")
        profile = UserProfile(**response.data)

        if not profile.credentials:
            raise ValueError("No credentials envelope found")

        credentials = profile.credentials

        if password:
            stored_hash = credentials.get("Password") or credentials.get("password")
            if not stored_hash or not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
                raise ValueError("Password validation failed. Bad password.")

        jwe_creds = credentials.get("AwsCredentials") or credentials.get("aws_credentials")
        if not jwe_creds:
            raise ValueError("No credentials found in envelope")

        return decrypt_creds(jwe_creds)

    except Exception as e:
        log.debug(f"Error retrieving credentials for user {user_id}: {e}")
        raise


def create_basic_session_jwt(client_id: str, client_name: str, user_id: str, minutes: int = SESSION_JWT_MINUTES) -> str:
    """
    Create a basic session JWT token for user authentication with client context.

    This token contains only user identity and client context - NO AWS credentials.
    Used for session management and OAuth flows before final token issuance.

    Args:
        client_id (str): OAuth client ID
        client_name (str): Client name/slug for data operations
        user_id (str): User identifier (subject claim)
        minutes (int): Token validity in minutes. Defaults to SESSION_JWT_MINUTES.

    Returns:
        str: JWT session token with client context

    JWT Claims:
        - sub: User ID
        - typ: "session"
        - iss: "sck-core-api"
        - iat: Issued at timestamp
        - exp: Expiration timestamp
        - jti: Unique token ID
        - NO AWS credentials of any kind

    Examples:
        >>> session_token = create_basic_session_jwt("user@example.com", 30)
        >>> # Token contains only user identity for OAuth flows
    """
    payload = JwtPayload(
        sub=user_id,
        cid=client_id,
        cnm=client_name,
        ttl=minutes,
    ).model_dump()

    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_access_token_with_sts(aws_credentials: dict, user_id: str, scope: str, client_id: str, client_name: str) -> str:
    """
    Create OAuth access token with embedded STS temporary credentials and client context.

    Takes user's long-term AWS credentials, exchanges them for temporary STS credentials,
    then embeds the encrypted STS credentials and client context in a JWT access token.

    Args:
        aws_credentials (dict): User's long-term AWS credentials
        user_id (str): User identifier (subject claim)
        scope (str): OAuth scope string
        client_id (str): OAuth client ID for context
        client_name (str): Client name/slug for data operations

    Returns:
        str: JWT access token with encrypted STS credentials and client context

    Raises:
        ValueError: If user has no AWS credentials configured
        RuntimeError: If STS token generation fails
        BotoCoreError: If AWS STS service call fails
        ClientError: If AWS credentials are invalid

    JWT Claims:
        - sub: User ID, typ: "access_token", iss: "sck-core-api"
        - iat/exp: Timestamps, jti: Unique token ID, scope: OAuth scope
        - client_id: OAuth client identifier, client_name: Client slug for data operations
        - aws_credentials: Encrypted STS credentials (JWE)

    Example:
        >>> aws_creds = {"AccessKeyId": "AKIA...", "SecretAccessKey": "secret..."}
        >>> token = create_access_token_with_sts(
        ...     aws_creds, "user@example.com", "read write", "myapp", "core"
        ... )
        >>> # Token contains encrypted STS credentials for API access
    """

    # Use provided duration or default
    duration_seconds = 3600 * JWT_EXPIRATION_HOURS

    sts_credentials = {
        "AccessKeyId": "",
        "SecretAccessKey": "",
        "SessionToken": "",
        "Expiration": "",
    }

    mfa_device_id = None
    mfa_token_code = None

    try:
        # Get the AWS credentials (stored on your user profile)
        access_key = aws_credentials.get("AccessKeyId")
        secret_key = aws_credentials.get("SecretAccessKey")

        # Create STS client and get temporary credentials for the API
        sts_client = boto3.client("sts", aws_access_key_id=access_key, aws_secret_access_key=secret_key)
        result = sts_client.get_session_token(
            DurationSeconds=duration_seconds, SerialNumber=mfa_device_id, TokenCode=mfa_token_code
        )

        if "Credentials" in result:
            sts_credentials = result["Credentials"]

    except (BotoCoreError, ClientError) as e:
        log.warn(f"Error retrieving STS credentials for user {user_id}: {e}")

    creds_enc = encrypt_creds(sts_credentials)

    minutes = 60 * JWT_EXPIRATION_HOURS

    payload = JwtPayload(
        sub=user_id,
        cid=client_id,
        cnm=client_name,
        enc=creds_enc,
        ttl=minutes,
        scp=scope,
    ).model_dump()

    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def get_client_ip(request: Request) -> str:
    """
    Extract client IP address from request, considering possible proxies.

    This function attempts to determine the real client IP address by
    checking proxy headers and falling back to the direct connection IP.
    Used for rate limiting and security logging.

    Args:
        request (Request): FastAPI request object.

    Returns:
        str: Client IP address or "unknown" if cannot be determined.

    Security:
        - Checks X-Forwarded-For header for proxy scenarios
        - Falls back to direct connection IP
        - Returns "unknown" rather than raising errors
        - Truncates forwarded header to prevent log injection

    Examples:
        >>> ip = get_client_ip(request)
        >>> # Use for rate limiting or logging
    """
    ip = request.client.host if request.client else "unknown"

    # Check forwarded IP if behind proxy (take first IP only)
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if forwarded and forwarded != ip:
        # Basic validation of forwarded IP
        try:
            import ipaddress

            ipaddress.ip_address(forwarded)
            return forwarded
        except ValueError:
            pass  # Invalid IP, use original

    return ip


def get_client_identifier(request: Request) -> str:
    """
    Generate a client identifier for rate limiting and tracking.

    Creates a stable identifier combining IP address and user agent
    for rate limiting purposes. This allows tracking of clients across
    requests without relying on cookies or authentication.

    Args:
        request (Request): FastAPI request object.

    Returns:
        str: Client identifier string in format "ip#user_agent".

    Security:
        - Combines IP and user agent for better uniqueness
        - Truncates user agent to prevent header injection
        - Stable across requests from same client
        - Safe for logging and database keys

    Examples:
        >>> identifier = get_client_identifier(request)
        >>> # Use for rate limiting or abuse detection
    """
    real_ip = get_client_ip(request)

    # Include user agent for fingerprinting (truncated for safety)
    ua = request.headers.get("user-agent", "unknown")[:50]

    return f"{real_ip}#{ua}"


def _get_rate_limit_key(identifier: str, endpoint: str) -> str:
    """
    Generate DynamoDB key for rate limiting storage.

    Creates a consistent key format for storing rate limit data in DynamoDB.
    Keys are prefixed with "rate#" for easy identification and cleanup.

    Args:
        identifier (str): Client identifier from get_client_identifier().
        endpoint (str): API endpoint name being rate limited.

    Returns:
        str: DynamoDB key for rate limit record.

    Examples:
        >>> key = _get_rate_limit_key("192.168.1.1#Chrome", "signup")
        >>> # "rate#signup#192.168.1.1#Chrome"
    """
    return f"rate#{endpoint}#{identifier}"


def check_rate_limit(request: Request, endpoint: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
    """
    Check if client is rate limited for specific endpoint.

    Implements sliding window rate limiting using DynamoDB for storage.
    Tracks attempts per client per endpoint and enforces configurable limits.
    Auto-expires old records to prevent storage bloat.

    Args:
        request (Request): FastAPI request object.
        endpoint (str): API endpoint name (e.g., "signup", "login").
        max_attempts (int, optional): Maximum attempts allowed in window. Defaults to 5.
        window_minutes (int, optional): Time window in minutes. Defaults to 15.

    Returns:
        bool: True if request should be allowed, False if rate limited.

    Security:
        - Sliding window prevents burst attacks
        - Per-endpoint limits for granular control
        - Auto-expiring records prevent storage growth
        - Fails open on database errors (availability over security)
        - Client identification via IP + user agent

    Rate Limit Algorithm:
        1. Get client identifier (IP + user agent)
        2. Retrieve attempt history from DynamoDB
        3. Filter attempts to current time window
        4. Check if under limit, add current attempt
        5. Update DynamoDB with new attempt list
        6. Set TTL for automatic cleanup

    Examples:
        >>> # Check signup rate limit (5 attempts per 15 minutes)
        >>> if not check_rate_limit(request, "signup", 5, 15):
        ...     return JSONResponse({"error": "Rate limited"}, status_code=429)
        >>>
        >>> # Check login rate limit (10 attempts per 5 minutes)
        >>> if not check_rate_limit(request, "login", 10, 5):
        ...     return JSONResponse({"error": "Too many login attempts"}, status_code=429)
    """
    identifier = get_client_identifier(request)
    key = _get_rate_limit_key(identifier, endpoint)
    now = int(time.time())
    window_start = now - (window_minutes * 60)

    try:
        # Get current attempts
        sr: SuccessResponse = RateLimitActions.get(**{"code": key})
        response = sr.data

    except Exception:
        # No record exists (probably) - create initial record
        try:
            data = {
                "client": "core",
                "code": key,
                "attempts": [now],
                "ttl": now + (window_minutes * 60 * 2),  # TTL = 2x window for safety
            }
            log.debug(f"Creating new rate limit record: ", details=data)
            RateLimitActions.create(**data)

            return True  # First attempt allowed
        except Exception as e:
            log.warning(f"Failed to create rate limit record: {e}")
            return True  # Fail open

    try:
        # Filter recent attempts within the time window
        attempts = [ts for ts in response.get("attempts", []) if ts > window_start]

        if len(attempts) >= max_attempts:
            log.info(f"Rate limit exceeded for {identifier} on {endpoint}: {len(attempts)}/{max_attempts}")
            return False  # Rate limited

        # Add current attempt
        attempts.append(now)
        RateLimitActions.update(
            **{
                "client": "core",
                "code": key,
                "attempts": attempts,
                "ttl": now + (window_minutes * 60 * 2),  # TTL = 2x window
            }
        )
        return True

    except Exception as e:
        log.warning(f"Rate limit check failed: {e}")
        return True  # Fail open to avoid blocking legitimate users


def cookie_opts() -> dict:
    """
    Generate secure cookie options for production use.

    Creates a dictionary of cookie attributes for secure session management.
    Configurable via environment variables for different deployment environments.

    Returns:
        dict: Cookie options dictionary with security attributes.

    Environment Variables:
        - SECURE_COOKIES: Set to "true" for HTTPS-only cookies (default: false)
        - COOKIE_SAMESITE: SameSite attribute (default: "lax")
        - COOKIE_DOMAIN: Cookie domain scope (optional)

    Security Features:
        - httponly: Prevents JavaScript access (XSS protection)
        - secure: HTTPS-only transmission (when enabled)
        - samesite: CSRF protection
        - path: Restricts cookie scope

    Cookie Attributes:
        - httponly: True (prevents XSS)
        - secure: Based on SECURE_COOKIES env var
        - samesite: "Lax" (configurable, CSRF protection)
        - path: "/" (site-wide)
        - domain: Optional domain restriction

    Examples:
        >>> opts = cookie_opts()
        >>> response.set_cookie("session", token, **opts)
        >>>
        >>> # Production environment
        >>> # SECURE_COOKIES=true, COOKIE_SAMESITE=Strict
        >>> opts = cookie_opts()
        >>> # {'httponly': True, 'secure': True, 'samesite': 'Strict', 'path': '/'}
    """
    secure = os.getenv("SECURE_COOKIES", "false").lower() in ("1", "true", "yes")
    same_site = os.getenv("COOKIE_SAMESITE", "lax").capitalize()  # Lax, None, Strict
    domain = os.getenv("COOKIE_DOMAIN")  # optional

    opts = {"httponly": True, "secure": secure, "samesite": same_site, "path": "/"}

    if domain:
        opts["domain"] = domain

    return opts


def get_authenticated_user(request: Request) -> Tuple[str | None, str | None, str | None]:
    """
    Extract the authenticated user and client context from JWT token.

    Checks Authorization header or sck_token cookie for valid JWT,
    then extracts user identity and client information.

    Auth sources (in order):
        - Authorization: Bearer <JWT>
        - sck_token cookie

    Args:
        request (Request): FastAPI request object

    Returns:
        Tuple[str | None, str | None, str | None]: (user_id, client_id, client_name)
                                                   Returns (None, None, None) if no valid token found

    Example:
        >>> user_id, client_id, client_name = get_authenticated_user(request)
        >>> if user_id:
        ...     # User is authenticated, use client_name for data operations
        ...     ProfileActions.get(client=client_name or "core", user_id=user_id, profile_name="default")
    """
    # Get the token from either the "authorization" header or the "sck_token" cookie
    authz = (request.headers.get("authorization") or "").strip()
    token = None
    if authz.lower().startswith("bearer "):
        token = authz.split(" ", 1)[1].strip()
    elif "sck_token" in request.cookies:
        token = request.cookies["sck_token"]

    if not token:
        return None, None, None

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
            },
        )

        user_id = payload.get("sub")
        client_id = payload.get("cid")
        client_name = payload.get("cnm")

        return user_id, client_id, client_name

    except jwt.InvalidTokenError:
        log.warning("Invalid JWT token in request")

    return None, None, None
