from typing import Optional, Tuple, Dict
import time
import base64
import os
import json
import uuid
import bcrypt
from datetime import datetime, timedelta, timezone

from fastapi import Request

import jwt
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK

import core_logging as log

from core_db.response import SuccessResponse
from core_db.profile.model import UserProfile
from core_db.profile.actions import ProfileActions
from core_db.oauth.actions import RateLimitActions

from .constants import CRED_ENC_KEY_B64, JWT_SECRET_KEY, JWT_ALGORITHM


def validate_token(token: str) -> dict:
    """
    Validate a JWT token and return the decoded payload.

    This function verifies the JWT signature, expiration, and format.
    It uses HS256 algorithm by default but respects the JWT_ALGORITHM setting.

    Args:
        token (str): JWT token to validate. Must be a valid JWT format.

    Returns:
        dict: Decoded JWT payload if valid, containing standard JWT claims
              (sub, iat, exp, etc.) plus any custom claims. Returns error
              dict with 'error' key if validation fails.

    Examples:
        >>> payload = validate_token("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...")
        >>> if "error" not in payload:
        ...     user_id = payload["sub"]
    """
    try:
        decoded = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return decoded
    except jwt.ExpiredSignatureError:
        log.warning("JWT token has expired")
        return {"error": "Token has expired"}
    except jwt.InvalidTokenError:
        log.warning("Invalid JWT token")
        return {"error": "Invalid token"}


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
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
        envelope["password"] = password_hash.decode("utf-8")

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
_CRED_JWK = None

if CRED_ENC_KEY_B64:
    try:
        key_bytes = base64.urlsafe_b64decode(_b64pad(CRED_ENC_KEY_B64))
        l = len(key_bytes)
        if l != 32:
            raise ValueError(f"CRED_ENC_KEY must be 32 bytes (base64url-decoded), got {l} bytes")
        _CRED_JWK = JWK(kty="oct", k=base64.urlsafe_b64encode(key_bytes).decode())
    except Exception as e:
        raise RuntimeError(f"Failed to initialize credential encryption key: {e}")


def encrypt_aws_credentials(aws_access_key: str, aws_access_secret) -> None | Dict[str, str]:

    if not aws_access_key or not aws_access_secret:
        return None

    credentials = {
        "AccessKeyId": aws_access_key,
        "SecretAccessKey": aws_access_secret,
    }

    # We may be saving the password only
    return {"aws_credentials": encrypt_creds(credentials), "encryption": "jwe"}


def encrypt_creds(creds: Dict) -> str:
    """
    Encrypt AWS STS credentials using JWE with AES-256-GCM.

    This function encrypts AWS credentials (typically temporary STS tokens)
    for secure transmission in JWT tokens. Uses JWE with direct key agreement
    and AES-256-GCM authenticated encryption.

    Args:
        creds (dict): AWS STS credential fields to encrypt. Should contain:
                     - AccessKeyId (str): Temporary access key
                     - SecretAccessKey (str): Temporary secret key
                     - SessionToken (str): STS session token
                     - Expiration (str, optional): Token expiration time

    Returns:
        str: Compact JWE string containing the encrypted credentials.
             Format: header.encrypted_key.iv.ciphertext.tag

    Raises:
        RuntimeError: If CRED_ENC_KEY not properly configured
        Exception: If JWE encryption fails

    Security:
        - AES-256-GCM provides confidentiality and authenticity
        - Direct key agreement (no key wrapping overhead)
        - Compact serialization for efficient transmission
        - Server-controlled encryption key

    Examples:
        >>> sts_creds = {
        ...     "AccessKeyId": "ASIA...",
        ...     "SecretAccessKey": "temp_secret...",
        ...     "SessionToken": "token...",
        ...     "Expiration": "2023-01-01T12:00:00Z"
        ... }
        >>> jwe_string = encrypt_creds(sts_creds)
        >>> # Include jwe_string in JWT token
    """
    if not _CRED_JWK:
        raise RuntimeError("CRED_ENC_KEY not configured - cannot encrypt credentials")

    if not creds or not isinstance(creds, dict):
        raise ValueError("Credentials must be a non-empty dictionary")

    try:
        jwe = JWE(
            plaintext=json.dumps(creds, separators=(",", ":")).encode("utf-8"),
            protected={"alg": "dir", "enc": "A256GCM"},
        )
        jwe.add_recipient(_CRED_JWK)
        return jwe.serialize(compact=True)
    except Exception as e:
        log.error(f"JWE encryption failed: {e}")
        raise RuntimeError(f"Failed to encrypt credentials: {e}")


def decrypt_creds(enc: str) -> dict:
    """
    Decrypt a compact JWE string and return the AWS STS credential dict.

    This function decrypts JWE-encrypted AWS credentials using the server's
    encryption key. Typically used to extract temporary STS credentials
    from JWT tokens.

    Args:
        enc (str): Compact JWE string produced by encrypt_creds().
                  Must be in format: header.encrypted_key.iv.ciphertext.tag

    Returns:
        dict: Decrypted AWS STS credential fields containing:
              - AccessKeyId (str): Temporary access key
              - SecretAccessKey (str): Temporary secret key
              - SessionToken (str): STS session token
              - Expiration (str, optional): Token expiration time

    Raises:
        RuntimeError: If CRED_ENC_KEY not configured or decryption fails
        ValueError: If JWE format is invalid

    Security:
        - Verifies JWE authenticity and integrity
        - Only server with correct key can decrypt
        - Protects against tampering and forgery

    Examples:
        >>> jwe_string = "eyJhbGci..."  # From JWT token
        >>> creds = decrypt_creds(jwe_string)
        >>> access_key = creds["AccessKeyId"]
        >>> secret_key = creds["SecretAccessKey"]
        >>> session_token = creds["SessionToken"]
    """
    if not _CRED_JWK:
        raise RuntimeError("CRED_ENC_KEY not configured - cannot decrypt credentials")

    if not enc or not isinstance(enc, str):
        raise ValueError("Encrypted credentials must be a non-empty string")

    try:
        jwe = JWE()
        jwe.deserialize(enc, key=_CRED_JWK)
        return json.loads(jwe.payload.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in decrypted credentials: {e}")
    except Exception as e:
        log.error(f"JWE decryption failed: {e}")
        raise RuntimeError(f"Failed to decrypt credentials: {e}")


def decrypt_credentials(env: Dict, password: str = None) -> dict:
    """
    Decrypt AWS credentials from encrypted envelope stored in database.

    This function handles decryption of long-term AWS credentials stored
    in the database. It verifies passwords for regular users and decrypts
    the JWE-encrypted credential payload.

    Args:
        env (dict): Stored credential envelope from encrypt_credentials() containing:
                   - encryption (str): Should be "jwe"
                   - aws_credentials (str): JWE-encrypted credential string
                   - password (str, optional): bcrypt hash for verification
                   - created_at (str): Creation timestamp
        password (str, optional): User password for verification. Required if
                                 envelope contains password hash.

    Returns:
        dict: Decrypted AWS credentials containing:
              - AccessKeyId (str): AWS access key ID
              - SecretAccessKey (str): AWS secret access key
              - Region (str, optional): AWS region

    Raises:
        ValueError: If password verification fails or envelope is malformed
        RuntimeError: If credential decryption fails

    Security:
        - Verifies bcrypt password hash before decryption
        - Constant-time password comparison via bcrypt
        - JWE provides authenticated encryption of credentials
        - Prevents unauthorized access to stored credentials

    Examples:
        >>> # For regular user
        >>> envelope = {...}  # From database
        >>> creds = decrypt_credentials(envelope, "user_password")
        >>>
        >>> # For SSO user (no password)
        >>> creds = decrypt_credentials(envelope)
    """
    if not env or not isinstance(env, dict):
        raise ValueError("Credential envelope must be a non-empty dictionary")

    try:
        # If envelope has password hash, verify it
        if "password" in env and password:
            stored_hash = env["password"].encode("utf-8")
            if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
                raise ValueError("Invalid password")
        elif "password" in env and not password:
            raise ValueError("Password required for this credential")

        # Decrypt using server key (JWE)
        jwe_creds = env.get("aws_credentials")
        if not jwe_creds:
            raise ValueError("No credentials found in envelope")

        return decrypt_creds(jwe_creds)

    except ValueError:
        raise  # Re-raise ValueError as-is
    except Exception as e:
        log.error(f"Credential decryption failed for envelope: {e}")
        raise RuntimeError(f"Credential decryption failed: {e}")


def get_user_access_key(user_id: str, password: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """
    Load and decrypt user's AWS credentials from database.

    Returns (None, None) if user exists but has no AWS credentials yet.
    This is normal for newly created users who haven't added AWS keys.
    """
    try:
        response: SuccessResponse = ProfileActions.get(user_id=user_id, profile_name="default")
        profile = UserProfile(**response.data)

        if not profile.credentials:
            log.debug(f"No credentials envelope found for user {user_id}")
            return None, None

        # Handle envelope format
        if isinstance(profile.credentials, dict):
            # Check if envelope has AWS credentials
            if "aws_credentials" not in profile.credentials:
                log.debug(f"No AWS credentials in envelope for user {user_id}")
                return None, None

            # Decrypt AWS credentials
            creds = decrypt_credentials(profile.credentials, password)
            return creds.get("AccessKeyId"), creds.get("SecretAccessKey")
        else:
            log.debug(f"Unsupported credential format for user {user_id}")
            return None, None

    except Exception as e:
        log.debug(f"Error retrieving credentials for user {user_id}: {e}")
        return None, None


def create_basic_session_jwt(user_id: str, minutes: int | None = None) -> str:
    """
    Create a basic session JWT token for user identity only.

    This token contains NO AWS credentials and is only used for OAuth flows
    to identify the authenticated user during authorize/token exchanges.

    Args:
        user_id (str): User identifier (subject claim in JWT).
        minutes (int | None, optional): Token lifetime in minutes. Defaults to 30.

    Returns:
        str: JWT token string containing only user identity claims.

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
    ttl = minutes if isinstance(minutes, int) and minutes > 0 else int(os.getenv("SESSION_JWT_MINUTES", "30"))

    # Enforce reasonable session token limits
    if ttl > 1440:  # 24 hours max
        ttl = 1440
    elif ttl < 5:  # 5 minutes min
        ttl = 5

    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ttl)

    payload = {
        "sub": user_id,
        "typ": "session",
        "iss": "sck-core-api",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": uuid.uuid4().hex,
        # NO AWS credentials - this is identity-only token
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_session_jwt(user_id: str, cred_jwe: str, minutes: int | None = None) -> str:
    """
    Create a short-lived session JWT token containing encrypted AWS credentials.

    This function creates JWT tokens for user sessions, typically containing
    encrypted long-term AWS credentials that can be exchanged for temporary
    STS tokens. Used for maintaining user sessions across requests.

    Args:
        user_id (str): User identifier (subject claim in JWT).
        cred_jwe (str): JWE-encrypted AWS credentials string.
        minutes (int | None, optional): Token lifetime in minutes. Defaults to
                                       SESSION_JWT_MINUTES env var or 30 minutes.

    Returns:
        str: JWT token string containing session claims and encrypted credentials.

    Raises:
        Various JWT encoding exceptions if token creation fails.

    Security:
        - Short-lived tokens (30 minutes default)
        - Credentials double-encrypted (JWE + JWT signing)
        - Unique JTI for token tracking/revocation
        - Server-controlled token lifetime

    JWT Claims:
        - sub: User ID
        - typ: "session"
        - iss: "sck-core-api"
        - iat: Issued at timestamp
        - exp: Expiration timestamp
        - jti: Unique token ID
        - cred_jwe: Encrypted AWS credentials

    Examples:
        >>> cred_jwe = encrypt_creds(aws_credentials)
        >>> session_token = create_session_jwt("user@example.com", cred_jwe, 60)
        >>> # Return session_token to client
    """
    ttl = minutes if isinstance(minutes, int) and minutes > 0 else int(os.getenv("SESSION_JWT_MINUTES", "30"))

    # Enforce reasonable session token limits
    if ttl > 1440:  # 24 hours max
        ttl = 1440
    elif ttl < 5:  # 5 minutes min
        ttl = 5

    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ttl)

    payload = {
        "sub": user_id,
        "typ": "session",
        "iss": "sck-core-api",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": uuid.uuid4().hex,
        # JWE of long-term access keys (server-only decrypt)
        "cred_jwe": cred_jwe,
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_access_token_with_sts(user_id, scope, client_id, client_name) -> str:
    pass


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


def get_authenticated_user(request: Request) -> Tuple[bool, Optional[str]]:
    """Extract the authenticated user from Authorization or cookie.

    Auth sources (in order):
        - Authorization: Bearer <JWT>
        - sck_token cookie

    Returns:
        Tuple[bool, Optional[str]]: (True, sub) if a valid JWT is found; otherwise (False, None).
    """
    authz = (request.headers.get("authorization") or "").strip()
    token = None
    if authz.lower().startswith("bearer "):
        token = authz.split(" ", 1)[1].strip()
    elif "sck_token" in request.cookies:
        token = request.cookies["sck_token"]
    if not token:
        return False, None
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
        # Optional: enforce typ/access on Bearer usage, etc.
        return True, payload.get("sub")
    except jwt.InvalidTokenError:
        return False, None
