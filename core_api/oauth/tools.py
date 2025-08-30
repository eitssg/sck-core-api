from typing import Optional, Dict, Tuple
import time
import base64
import os
import json
import uuid
import ipaddress
import bcrypt
from datetime import datetime, timedelta, timezone

from core_db.registry import ClientFact

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from pydantic import BaseModel, Field, model_validator

import jwt
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK

import core_logging as log

from core_db.response import SuccessResponse
from core_db.profile.model import UserProfile
from core_db.profile.actions import ProfileActions
from core_db.oauth.actions import RateLimitActions
from core_db.registry.client import ClientActions

from .constants import (
    CRED_ENC_KEY_B64,
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    REFRESH_MIN_INTERVAL_SECONDS,
    SESSION_JWT_MINUTES,
    JWT_EXPIRATION_HOURS,
    SCK_TOKEN_COOKIE_NAME,
)


class JwtPayload(BaseModel):
    sub: str = Field(..., description="Subject (user identifier, e.g. email)")
    cid: str = Field(..., description="Client ID")

    iat: int | None = Field(None, description="Issued at time as UNIX timestamp")
    exp: int | None = Field(None, description="Expiration time as UNIX timestamp")
    typ: str | None = Field(None, description="Token type")
    iss: str | None = Field(None, description="Issuer")
    jti: str | None = Field(None, description="Unique token identifier")
    ttl: int | None = Field(None, description="Token time-to-live in minutes")
    cnm: str | None = Field(None, description="Client URL slug associated with Client ID")
    scp: str | None = Field(None, description="Scope of the Access token")
    enc: str | None = Field(None, description="Encrypted AWS STS temporary credentials (JWE)")
    nbf: int | None = Field(None, description="Not before time as UNIX timestamp")

    # OAuth Flow Parameters
    rty: str | None = Field(None, description="Response type (code, token)")
    rdu: str | None = Field(None, description="Redirect URI for OAuth callback")
    sid: str | None = Field(None, description="State parameter for OAuth flow")
    ccm: str | None = Field(None, description="Code challenge method (S256, plain)")
    cch: str | None = Field(None, description="Code challenge for PKCE")

    # Optional OAuth Extensions
    aud: str | None = Field(None, description="Intended audience")
    nonce: str | None = Field(None, description="OpenID Connect nonce")
    prompt: str | None = Field(None, description="Authentication prompt parameter")
    max_age: int | None = Field(None, description="Maximum authentication age")

    def is_expired(self) -> bool:
        """Check if the token is expired."""
        return self.exp is not None and self.exp < int(datetime.now(timezone.utc).timestamp())

    def is_not_before(self) -> bool:
        """Check if the token is not yet valid."""
        return self.nbf is not None and self.nbf > int(datetime.now(timezone.utc).timestamp())

    def is_valid(self) -> bool:
        """Check if the token is valid (not expired and not before)."""
        return not self.is_expired() and not self.is_not_before()

    def is_refresh(self) -> bool:
        """Check if the token is a refresh token."""
        return self.typ == "refresh"

    def is_access(self) -> bool:
        """Check if the token is an access token."""
        return self.typ == "access"

    def is_bearer(self) -> bool:
        """Check if the token is a bearer token."""
        return self.typ == "bearer"

    def is_client_credentials(self) -> bool:
        """Check if the token is a client credentials token."""
        return self.typ == "client_credentials"

    def is_system(self) -> bool:
        """Check if the token is a system token."""
        return self.typ == "system"

    def is_service_account(self) -> bool:
        """Check if the token is a service account token."""
        return self.typ == "service_account"

    def is_anonymous(self) -> bool:
        """Check if the token is an anonymous token."""
        return self.typ == "anonymous"

    def is_public(self) -> bool:
        """Check if the token is a public token."""
        return self.typ == "public"

    def is_internal(self) -> bool:
        """Check if the token is an internal token."""
        return self.typ == "internal"

    def ttl_seconds(self) -> int:
        """Get the token time-to-live in seconds."""
        return self.ttl * 60 if self.ttl else 0

    @model_validator(mode="before")
    def validate_fields(cls, values: dict) -> dict:

        if "cid" not in values:
            raise ValueError("Client ID (cid) is required")

        cnm = values.get("cnm")
        if not cnm:
            raise ValueError("Client Name (cnm) is required")
        cnm = cnm.lower()
        values["cnm"] = cnm

        typ = values.get("typ")
        if not typ:
            typ = "access"
            values["typ"] = typ
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

        if typ == "refresh" and "nbf" not in values:
            nbf = int((datetime.now(timezone.utc) + timedelta(seconds=REFRESH_MIN_INTERVAL_SECONDS)).timestamp())
            values["nbf"] = nbf

        return values

    def model_dump(self, **kwargs) -> dict:
        kwargs.setdefault("exclude_none", True)
        return super().model_dump(**kwargs)

    def encode(self) -> str:
        """Encode the JWT payload as a JWT token."""
        return jwt.encode(self.model_dump(), JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    @classmethod
    def decode(cls, token: str) -> "JwtPayload":
        """Decode a JWT token into a JwtPayload instance."""
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
        return cls(**payload)


def is_password_compliant(password: str) -> bool:
    """Check if password meets security complexity requirements

    Enforces enterprise-grade password policy for user account security.
    All requirements must be met for password to be considered compliant

    Args:
        password (str): Plain text password to validate

    Returns:
        bool: True if password meets all requirements, False otherwise

    Password Requirements:
        - Minimum 8 characters length
        - At least 1 uppercase letter (A-Z)
        - At least 1 lowercase letter (a-z)
        - At least 1 digit (0-9)
        - At least 1 special character (!@#$%^&*()-+)

    Examples:
        >>> is_password_compliant("Pass123!")      # True - meets all requirements
        >>> is_password_compliant("password")      # False - no uppercase, digit, special
        >>> is_password_compliant("PASSWORD123!")  # False - no lowercase
        >>> is_password_compliant("Pass!")         # False - too short, no digit
    """
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char in "!@#$%^&*()-+_" for char in password):
        return False
    return True


def encrypt_credentials(
    aws_access_key: str | None = None,
    aws_secret_key: str | None = None,
    password: str | None = None,
) -> dict:
    """Create encrypted credential envelope for secure storage in user profiles

    Combines password hashing (bcrypt) and AWS credential encryption (JWE) into a single
    envelope structure. Supports partial credentials - either password only, AWS only, or both.

    Creates an envelope that can store password hash and/or AWS credentials.
    Both are optional - allows creating users without AWS credentials initially.

    Args:
        aws_access_key (str, optional): AWS access key ID
        aws_secret_key (str, optional): AWS secret access key
        password (str, optional): User password for verification hash

    Returns:
        dict: Credential envelope structure:
              {
                  "Password": "bcrypt_hash",           # If password provided
                  "AwsCredentials": "jwe_encrypted",   # If AWS creds provided
                  "Encryption": "jwe",                 # If AWS creds present
                  "created_at": "2024-01-01T12:00:00Z" # Always present
              }

    Raises:
        ValueError: If password fails complexity requirements
        RuntimeError: If AWS credential encryption fails

    Security Features:
        - Passwords hashed with bcrypt (12 rounds, salted)
        - AWS credentials encrypted with JWE using server key
        - No plain text credentials ever stored
        - Envelope versioning via created_at timestamp

    Examples:
        >>> # User signup with password only (no AWS creds yet)
        >>> envelope = encrypt_credentials(password="SecurePass123!")
        >>> # {"Password": "$2b$12$...", "created_at": "2024-01-01T..."}
        >>>
        >>> # User signup with both password and AWS creds
        >>> envelope = encrypt_credentials("AKIA...", "secret...", "user_password")
        >>> # {"Password": "$2b$12$...", "AwsCredentials": "eyJ...", "Encryption": "jwe", ...}
        >>>
        >>> # SSO user with AWS creds (no password)
        >>> envelope = encrypt_credentials("AKIA...", "secret...")
        >>> # {"AwsCredentials": "eyJ...", "Encryption": "jwe", "created_at": "..."}
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
    """Add missing padding to base64url strings for safe decoding

    Base64url encoding omits padding characters (=) to make URLs safe. This utility
    function restores the required padding for proper base64 decoding.

    Args:
        v (str): Base64url string without padding.

    Returns:
        str: Padded base64 string safe to decode.

    Algorithm:
        Adds "=" characters based on string length modulo 4:
        - Length % 4 = 0: No padding needed
        - Length % 4 = 1: Invalid (should not occur)
        - Length % 4 = 2: Add "=="
        - Length % 4 = 3: Add "="

    Examples:
        >>> padded = _b64pad("SGVsbG8")  # "Hello" in base64url
        >>> # "SGVsbG8=" - now properly padded
        >>> decoded = base64.urlsafe_b64decode(padded)
        >>> # b'Hello'
    """
    return v + "=" * (-len(v) % 4)


# Global JWK for credential encryption/decryption
def get_encryption_key() -> JWK | None:
    """Create JWK encryption key from environment variable for credential security

    Converts the base64url-encoded CRED_ENC_KEY environment variable into a JSON Web Key
    suitable for JWE encryption/decryption operations. Used internally by encrypt_creds()
    and decrypt_creds() functions.

    Returns:
        JWK | None: JSON Web Key for AES-256-GCM encryption, None if key unavailable

    Environment Variables:
        CRED_ENC_KEY: Base64url-encoded 32-byte AES key for credential encryption

    Key Requirements:
        - Must be exactly 32 bytes when base64url-decoded (AES-256)
        - Should be cryptographically random
        - Must be consistent across all application instances

    Security Notes:
        - Key is loaded once and cached globally
        - Missing key disables credential encryption/decryption
        - Invalid key length prevents encryption operations
        - All errors logged but don't expose key material

    Examples:
        >>> key = get_encryption_key()
        >>> if key:
        ...     # Encryption/decryption available
        >>> else:
        ...     # CRED_ENC_KEY not configured properly
    """

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
    """Encrypt AWS access key and secret into JWE format for secure profile storage

    Creates a partial credential envelope containing only AWS credential encryption.
    This is used internally by encrypt_credentials() and can be used standalone
    when only AWS credentials need to be encrypted (e.g., credential updates).

    Args:
        aws_access_key (str): AWS access key ID (e.g., "AKIAIOSFODNN7EXAMPLE")
        aws_secret_key (str): AWS secret access key (40-character string)

    Returns:
        dict | None: Partial credential envelope or None if inputs invalid:
         {
             "AwsCredentials": "jwe-encrypted-credentials",
             "Encryption": "jwe"
         }

    Usage in User Profiles:
        The returned dict is designed to be merged into a user profile's
        "Credentials" field alongside password hashes and other data.

    Profile Integration Example:
        >>> aws_envelope = encrypt_aws_credentials("AKIA...", "secret...")
        >>> user_profile["Credentials"].update(aws_envelope)
        >>> # Results in:
         {
            "user_id": "user@example.com",
             "Credentials": {
                 "Password": "bcrypt-hash",
                 "AwsCredentials": "jwe-encrypted-credentials",
                 "Encryption": "jwe"
             }
         }

    Security Features:
        - Uses AES-256-GCM encryption via JWE
        - No plain text AWS credentials in output
        - Encryption key derived from CRED_ENC_KEY env var
        - Safe to store in database or logs

    Examples:
        >>> # Encrypt new AWS credentials
        >>> envelope = encrypt_aws_credentials("AKIA123...", "wJalrXUt...")
        >>> # {"AwsCredentials": "eyJhbGciOiJkaXIi...", "Encryption": "jwe"}
        >>>
        >>> # Handle missing credentials
        >>> envelope = encrypt_aws_credentials("", "")
        >>> # None
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

    # Create JWE with protected header and payload
    protected = {"alg": "dir", "enc": "A256GCM"}
    jwe_creds = JWE(cred_json, protected)
    jwe_creds.add_recipient(enc_key)

    return jwe_creds.serialize(compact=True)


def decrypt_creds(encrypted_credentials: str | None) -> dict:
    """
    Decrypt JWE-encrypted credentials back to dictionary.

    Args:
        encrypted_credentials (str): JWE-encrypted credential string.  JwtPayload.enc field.

    Returns:
        dict: Decrypted credentials dictionary.  Will return {} if JwtPayload.enc is Empty

    Raises:
        ValueError: If encrypted string is malformed or cannot be decrypted
        Exception: If decryption key is invalid
    """
    if not encrypted_credentials:
        return {}

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


def get_user_access_key(client: str, user_id: str, password: Optional[str] = None) -> Tuple[dict, dict]:
    """Retrieve and decrypt user's AWS credentials from database with optional password validation

    Fetches user profile from database, optionally validates password, then decrypts
    and returns AWS credentials. Used by OAuth token generation and direct API access.

    Args:
        client (str): Client name for the profile
        user_id (str): User identifier to lookup credentials for
        password (str, optional): User password for validation. If None, skips password check.

    Returns:
        tuple[dict, dict]: Decrypted AWS credentials structure:
              {
                  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
              },
              {
                  "Profiles": [
                      "read",
                      "write",
                      "admin",
                  ]
              }

    Raises:
        ValueError: Multiple specific validation failures:
                   - Missing user_id
                   - Profile not found
                   - No credentials envelope in profile
                   - Password validation failed
                   - No AWS credentials in envelope
        Exception: Database or decryption system failures

    Security Features:
        - Password validated against bcrypt hash if provided
        - AWS credentials decrypted with server key
        - All errors logged without exposing credentials
        - No credentials returned on any validation failure

    Database Operations:
        - Queries ProfileActions.get() with client="core"
        - Expects UserProfile model structure
        - Handles missing profiles gracefully

    Examples:
        >>> # OAuth flow - validate password and get credentials
        >>> creds, permissions = get_user_access_key("acme", "user@example.com", "password123")
        >>> access_key = creds["AccessKeyId"]
        >>> secret_key = creds["SecretAccessKey"]
        >>>
        >>> # API access - skip password validation
        >>> creds, permissions = get_user_access_key("acme", "user@example.com")
        >>> # Returns credentials if user has them configured
    """
    try:
        if not user_id:
            raise ValueError("User ID is required for validation.")

        response: SuccessResponse = ProfileActions.get(client=client, user_id=user_id, profile_name="default")
        profile = UserProfile(**response.data)

        if not profile.credentials:
            raise ValueError("No credentials envelope found")

        credentials = profile.credentials
        permissions = profile.permissions

        if password:
            stored_hash = credentials.get("Password")
            if not stored_hash or not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
                raise ValueError("Password validation failed. Bad password.")

        jwe_creds = credentials.get("AwsCredentials")
        if not jwe_creds:
            return {}, permissions

        return decrypt_creds(jwe_creds), permissions

    except Exception as e:
        log.debug(f"Error retrieving credentials for user {user_id}: {e}")
        raise


def create_basic_session_jwt(client_id: str, client_name: str, user_id: str, minutes: int = SESSION_JWT_MINUTES) -> str:
    """Generate session JWT for OAuth flows with user identity and client context but no AWS credentials

    Creates a lightweight authentication token used in OAuth authorization flows.
    Contains user identity and client information but deliberately excludes AWS credentials
    for security - those are added later via create_access_token_with_sts().

    Args:
        client_id (str): OAuth client ID
        client_name (str): Client name/slug for data operations
        user_id (str): User identifier (subject claim)
        minutes (int): Token validity in minutes. Defaults to SESSION_JWT_MINUTES.

    Returns:
        str: Signed JWT token for session authentication

    JWT Claims (via JwtPayload model):
        - sub (str): User identifier (email address)
        - typ (str): Token type "session"
        - iss (str): Issuer "sck-core-api"
        - iat (int): Issued at timestamp (Unix epoch)
        - exp (int): Expiration timestamp (Unix epoch)
        - jti (str): Unique token identifier (hex UUID)
        - cid (str): OAuth client identifier
        - cnm (str): Client name/slug for data operations

    Security Features:
        - Signed with JWT_SECRET_KEY (HMAC-SHA256)
        - Time-limited expiration
        - Unique per issuance (jti claim)
        - No sensitive credentials embedded

    OAuth Flow Usage:
        1. User logs in via /auth/v1/login
        2. Session JWT returned to client
        3. Client includes in Authorization header
        4. /auth/v1/authorize validates session and issues auth code
        5. /auth/v1/token exchanges code for access token with AWS creds

    Examples:
        >>> # OAuth login flow
        >>> token = create_basic_session_jwt("webapp", "core", "user@example.com", 30)
        >>> # Use in Authorization header: "Bearer <token>"
        >>>
        >>> # Custom client with extended session
        >>> token = create_basic_session_jwt("mobile-app", "tenant1", "user@example.com", 60)
    """
    payload = JwtPayload(
        sub=user_id,
        typ="session",
        cid=client_id,
        cnm=client_name,
        ttl=minutes,
    )

    return payload.encode()


def create_access_token_with_sts(aws_credentials: dict, jwt_payload: JwtPayload, permissions: dict) -> str:
    """Generate OAuth access token with encrypted AWS STS temporary credentials and client context

    Takes user's long-term AWS credentials, exchanges them for time-limited STS credentials,
    encrypts the STS credentials, and embeds them in a JWT access token. This provides
    secure, temporary AWS access without exposing long-term credentials to clients.

    Args:
        aws_credentials (dict): User's long-term AWS credentials
        jwt_payload (JwtPayload): JWT payload containing user and client information
        permissions (dict): User's permissions for the session

    Returns:
        str: Signed JWT access token containing encrypted AWS STS credentials

    Raises:
        BotoCoreError: AWS SDK connection/configuration errors
        ClientError: AWS credential validation or permission errors
        RuntimeError: Encryption system failures
        Exception: JWT signing or general processing errors

    JWT Claims (via JwtPayload model):
        - sub (str): User identifier
        - typ (str): "access_token"
        - iss (str): "sck-core-api"
        - iat (int): Issued at timestamp
        - exp (int): Expiration timestamp
        - jti (str): Unique token identifier
        - scp (str): OAuth scope (e.g., "read write")
        - cid (str): OAuth client identifier
        - cnm (str): Client name for data operations
        - enc (str): JWE-encrypted STS credentials

    STS Credential Structure (encrypted in 'enc' claim):
        {
            "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SessionToken": "AQoDYXdzEJr...",
            "Expiration": "2024-01-01T14:00:00+00:00"
        }

    Security Features:
        - STS credentials time-limited (based on JWT_EXPIRATION_HOURS)
        - All AWS credentials encrypted with server key (JWE)
        - No long-term credentials exposed to clients
        - Token signed and tamper-evident
        - Automatic credential expiration

    AWS STS Integration:
        - Calls boto3 STS get_session_token()
        - Duration limited by JWT_EXPIRATION_HOURS
        - Supports optional MFA (currently disabled)
        - Fails gracefully on AWS errors (empty credentials)

    Error Handling:
        - AWS errors logged but don't fail token generation
        - Invalid credentials result in empty STS credentials
        - Encryption failures propagate as RuntimeError
        - Token generation continues with empty credentials on AWS failure

    Example:
        >>> aws_creds = {"AccessKeyId": "AKIA...", "SecretAccessKey": "secret..."}
        >>> token = create_access_token_with_sts(
        ...     aws_creds, "user@example.com", "read write", "myapp", "core"
        ... )
        >>> # Token contains encrypted STS credentials for API access
    """

    # Convert user permissions to OAuth scope string
    user_scope = _generate_scope_from_permissions(permissions)

    # Merge with any application-level scope from session token
    session_scope = jwt_payload.scp or ""
    combined_scope = _combine_scopes(session_scope, user_scope)

    # Use provided duration or default
    duration_seconds = 3600 * JWT_EXPIRATION_HOURS

    sts_credentials = {
        "AccessKeyId": "",
        "SecretAccessKey": "",
        "SessionToken": "",
        "Expiration": "",
    }

    if len(aws_credentials) != 0:
        mfa_device_id = None
        mfa_token_code = None

        try:
            # Get the AWS credentials (stored on your user profile)
            access_key = aws_credentials.get("AccessKeyId")
            secret_key = aws_credentials.get("SecretAccessKey")

            # Create STS client and get temporary credentials for the API
            sts_client = boto3.client("sts", aws_access_key_id=access_key, aws_secret_access_key=secret_key)

            if mfa_device_id and mfa_token_code:
                result = sts_client.get_session_token(
                    DurationSeconds=duration_seconds,
                    SerialNumber=mfa_device_id,
                    TokenCode=mfa_token_code,
                )
            else:
                result = sts_client.get_session_token(DurationSeconds=duration_seconds)

            if "Credentials" in result:
                sts_credentials = result["Credentials"]
                # Convert datetime to string for JSON serialization
                if hasattr(sts_credentials.get("Expiration"), "isoformat"):
                    sts_credentials["Expiration"] = sts_credentials["Expiration"].isoformat()

        except (BotoCoreError, ClientError) as e:
            log.warn(f"Error retrieving STS credentials for user {jwt_payload.sub}: {e}")

        creds_enc = encrypt_creds(sts_credentials)
    else:
        creds_enc = None

    minutes = 60 * JWT_EXPIRATION_HOURS

    payload = JwtPayload(
        sub=jwt_payload.sub,
        cid=jwt_payload.cid,
        cnm=jwt_payload.cnm,
        scp=combined_scope,
        enc=creds_enc,
        ttl=minutes,
    )
    return payload.encode()


def _generate_scope_from_permissions(permissions: dict) -> str:
    """Convert user permissions dictionary to OAuth scope string.

    Args:
        permissions (dict): User permissions from UserProfile

    Returns:
        str: Space-separated OAuth scope string

    Examples:
        >>> permissions = {
        ...     "registry": ["read", "write"],
        ...     "aws": ["credentials:read"],
        ...     "admin": ["user:manage"]
        ... }
        >>> scope = generate_scope_from_permissions(permissions)
        >>> # "registry:read registry:write aws:credentials:read admin:user:manage"
    """
    if not permissions or not isinstance(permissions, dict):
        return ""

    scopes = []

    for category, perms in permissions.items():
        if not isinstance(perms, list):
            continue

        for perm in perms:
            if isinstance(perm, str) and perm.strip():
                if category == "*":
                    # Wildcard permission: "*" -> "*:read", "*:write"
                    scope = f"*:{perm.strip()}"
                else:
                    # Regular permission: "registry" -> "registry:read"
                    scope = f"{category}:{perm.strip()}"
                scopes.append(scope)

    return " ".join(sorted(scopes))


def _combine_scopes(app_scope: str, user_scope: str) -> str:
    """Combine application and user scopes, removing duplicates.

    Args:
        app_scope (str): Application-level scope from session token
        user_scope (str): User-level scope from permissions

    Returns:
        str: Combined scope string
    """
    app_scopes = set(app_scope.split()) if app_scope else set()
    user_scopes = set(user_scope.split()) if user_scope else set()

    # Combine and sort for consistency
    combined = app_scopes.union(user_scopes)
    return " ".join(sorted(combined))


def get_client_ip(headers: dict) -> str:
    """Extract real client IP address from request headers, handling proxy scenarios safely

    Determines the actual client IP address by checking proxy headers and falling back
    to direct connection IP. Used for rate limiting, security logging, and abuse detection.

    Args:
        request (Request): FastAPI request object.

    Returns:
        str: Client IP address or "unknown" if cannot be determined.

    IP Resolution Order:
        1. X-Forwarded-For header (first IP only)
        2. Direct connection IP (request.client.host)
        3. "unknown" if neither available

    Security:
        - Validates forwarded IP format before use
        - Takes only first IP from X-Forwarded-For chain
        - Prevents header injection attacks
        - Safe fallback for all edge cases
        - Never raises exceptions

    Proxy Support:
        - Load balancers (ALB, NLB, CloudFlare)
        - Reverse proxies (nginx, Apache)
        - CDNs (CloudFront, Fastly)
        - API gateways

    Common Scenarios:
        - Direct connection: Returns request.client.host
        - Behind proxy: Returns X-Forwarded-For value
        - Invalid proxy header: Falls back to direct IP
        - No client info: Returns "unknown"

    Examples:
        >>> ip = get_client_ip(request)
        >>> # Direct: "192.168.1.100"
        >>> # Proxied: "203.0.113.1" (from X-Forwarded-For)
        >>> # Unknown: "unknown"
        >>> # Use for rate limiting or logging
    """

    ip = headers.get("x-real-ip") or headers.get("x-client-ip") or "unknown"

    # Check forwarded IP if behind proxy (take first IP only)
    forwarded = headers.get("x-forwarded-for", "").split(",")[0].strip()
    if forwarded and forwarded != ip:
        # Basic validation of forwarded IP
        try:
            ipaddress.ip_address(forwarded)
            return forwarded
        except ValueError:
            pass  # Invalid IP, use original

    return ip


def get_client_identifier(headers: dict) -> str:
    """Generate stable client fingerprint for rate limiting and abuse detection

    Creates a composite identifier combining IP address and user agent to uniquely
    identify clients across requests. More reliable than IP alone for rate limiting.

    Args:
        request (Request): FastAPI request object.

    Returns:
        str: Client identifier string in format "ip#user_agent".

    Identifier Format:
        "{real_ip}#{truncated_user_agent}"
        Example: "192.168.1.1#Mozilla/5.0 (Windows NT 10.0; Win64; x64) Appl"

    Security:
        - User agent truncated to 50 chars (prevents injection)
        - Stable across requests from same client/browser
        - Safe for database keys and logging
        - Handles missing user agent gracefully

    Rate Limiting Benefits:
        - Distinguishes multiple users behind same NAT/proxy
        - Identifies browser vs API client patterns
        - Reduces false positives in shared environments

    Privacy Considerations:
        - User agent is publicly available header
        - No personally identifiable information stored
        - Identifier used only for security purposes

    Examples:
        >>> identifier = get_client_identifier(request)
        >>> # "203.0.113.1#Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        >>> # Use for rate limiting or abuse detection
    """
    real_ip = get_client_ip(headers)

    # Include user agent for fingerprinting (truncated for safety)
    ua = headers.get("user-agent", "unknown")[:50]

    return f"{real_ip}#{ua}"


def _get_rate_limit_key(identifier: str, endpoint: str) -> str:
    """Generate consistent DynamoDB key for rate limit record storage and retrieval

    Creates standardized key format for storing rate limit data in DynamoDB.
    Keys include endpoint and client identifier for granular rate limiting.

    Args:
        identifier (str): Client identifier from get_client_identifier().
        endpoint (str): API endpoint name being rate limited.

    Returns:
        str: DynamoDB key for rate limit record.

    Key Format:
        "rate#{endpoint}#{client_identifier}"

    Key Benefits:
        - Consistent format across all rate limit records
        - Easy to query by endpoint or client
        - Supports cleanup operations (prefix "rate#")
        - Safe for DynamoDB key constraints
        - Human-readable for debugging

    Examples:
        >>> key = _get_rate_limit_key("192.168.1.1#Mozilla/5.0", "login")
        >>> # "rate#login#192.168.1.1#Mozilla/5.0"
        >>>
        >>> key = _get_rate_limit_key("203.0.113.1#curl/7.68.0", "signup")
        >>> # "rate#signup#203.0.113.1#curl/7.68.0"
    """
    return f"rate#{endpoint}#{identifier}"


def check_rate_limit(headers: dict, endpoint: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
    """Enforce sliding window rate limiting per client per endpoint using DynamoDB storage

    Implements robust rate limiting to prevent abuse while maintaining good user experience.
    Uses sliding window algorithm with automatic cleanup and fail-open security model.

    Args:
        request (Request): FastAPI request object.
        endpoint (str): API endpoint name (e.g., "signup", "login").
        max_attempts (int, optional): Maximum attempts allowed in window. Defaults to 5.
        window_minutes (int, optional): Time window in minutes. Defaults to 15.

    Returns:
        bool: True if request should be allowed, False if rate limited.

    Rate Limiting Algorithm:
        1. Generate client identifier (IP + user agent)
        2. Create DynamoDB key for endpoint + client
        3. Retrieve existing attempt history
        4. Filter attempts to current time window
        5. Check if under limit, record current attempt
        6. Update DynamoDB with new attempt list
        7. Set TTL for automatic record cleanup

    Storage Structure (DynamoDB):
        {
            "client": "core",
            "code": "rate#login#192.168.1.1#Mozilla",
            "attempts": [1640995200, 1640995260, 1640995320],
            "ttl": 1640997000
        }

    Security:
        - Sliding window prevents sustained abuse
        - Per-endpoint granularity (different limits per API)
        - Fail-open design (allow on database errors)
        - Client fingerprinting resists simple IP changes
        - Automatic record expiration prevents storage bloat

    Performance Features:
        - Single DynamoDB read + write per check
        - TTL-based automatic cleanup
        - Minimal data storage (timestamps only)
        - Efficient sliding window calculation

    Operational Benefits:
        - Configurable per endpoint and client type
        - Observable via DynamoDB metrics
        - Self-healing (expired records auto-deleted)
        - Graceful degradation on outages

    Rate Limit Algorithm:
        1. Get client identifier (IP + user agent)
        2. Retrieve attempt history from DynamoDB
        3. Filter attempts to current time window
        4. Check if under limit, add current attempt
        5. Update DynamoDB with new attempt list
        6. Set TTL for automatic cleanup

    Examples:
        >>> # Standard login protection
        >>> if not check_rate_limit(request, "login", 5, 15):
        ...     return JSONResponse({"error": "Rate limited"}, status_code=429)
        >>>
        >>> # Stricter signup limits
        >>> if not check_rate_limit(request, "signup", 3, 60):
        ...     return JSONResponse({"error": "Too many signups"}, status_code=429)
        >>>
        >>> # API access protection
        >>> if not check_rate_limit(request, "api_call", 100, 1):
        ...     return JSONResponse({"error": "API rate limit exceeded"}, status_code=429)

    Common Rate Limit Patterns:
        - Login: 5-10 attempts per 15 minutes
        - Signup: 2-3 attempts per hour
        - Password reset: 3 attempts per hour
        - API calls: 100-1000 per minute
        - File uploads: 10 per hour

    """
    identifier = get_client_identifier(headers)
    key = _get_rate_limit_key(identifier, endpoint)
    now = int(time.time())
    window_start = now - (window_minutes * 60)

    client = "core"

    try:
        # Get current attempts
        sr: SuccessResponse = RateLimitActions.get(client=client, code=key)
        response = sr.data

    except Exception as e:
        # No record exists (probably) - create initial record
        try:
            data = {
                "client": client,
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
        data = {
            "client": client,
            "code": key,
            "attempts": attempts,
            "ttl": now + (window_minutes * 60 * 2),  # TTL = 2x window
        }

        RateLimitActions.update(**data)

        return True

    except Exception as e:
        log.warning(f"Rate limit check failed: {e}")
        return True  # Fail open to avoid blocking legitimate users


def cookie_opts() -> dict:
    """Generate secure cookie configuration for session management and CSRF protection

    Creates production-ready cookie attributes based on environment configuration.
    Balances security with compatibility across different deployment scenarios.

    Returns:
        dict: Cookie options dictionary with security attributes.

    Environment Variables:
        SECURE_COOKIES: "true"/"false" - Require HTTPS (default: false)
        COOKIE_SAMESITE: "Lax"/"Strict"/"None" - CSRF protection (default: "lax")
        COOKIE_DOMAIN: Domain restriction (optional, e.g., ".example.com")

    Security Attributes:
        httponly: True - Prevents JavaScript access (XSS protection)
        secure: From env - HTTPS-only transmission when enabled
        samesite: From env - Cross-site request protection
        path: "/" - Site-wide cookie scope
        domain: From env - Optional domain restriction

    Security Features:
        - XSS Protection: httponly prevents client-side script access
        - CSRF Protection: samesite restricts cross-site requests
        - Transport Security: secure ensures HTTPS-only (when enabled)
        - Domain Control: optional domain restriction

    Deployment Scenarios:
        Development (HTTP):
            SECURE_COOKIES=false, COOKIE_SAMESITE=Lax
            - Compatible with local development
            - Basic CSRF protection maintained

        Production (HTTPS):
            SECURE_COOKIES=true, COOKIE_SAMESITE=Strict
            - Maximum security for production
            - HTTPS required, strict CSRF protection

        API Gateway/CDN:
            SECURE_COOKIES=true, COOKIE_DOMAIN=.example.com
            - Works across subdomains
            - Maintains security in complex deployments

    SameSite Values:
        - "Lax": Balanced security, allows some cross-site requests
        - "Strict": Maximum security, blocks all cross-site requests
        - "None": Minimum restriction, requires Secure flag

    Examples:
        >>> # Development environment
        >>> opts = cookie_opts()
        >>> # {'httponly': True, 'secure': False, 'samesite': 'Lax', 'path': '/'}
         >>> response.set_cookie("session", token, **opts)
         >>>
         >>> # Production environment
         >>> # SECURE_COOKIES=true, COOKIE_SAMESITE=Strict
         >>> opts = cookie_opts()
         >>> # {'httponly': True, 'secure': True, 'samesite': 'Strict', 'path': '/'}
         >>>
         >>> # Multi-domain setup
         >>> # COOKIE_DOMAIN=.example.com
         >>> opts = cookie_opts()
         >>> # {'httponly': True, 'secure': True, 'samesite': 'Lax', 'path': '/', 'domain': '.example.com'}
    """
    secure = os.getenv("SECURE_COOKIES", "false").lower() in ("1", "true", "yes")
    same_site = os.getenv("COOKIE_SAMESITE", "lax").capitalize()  # Lax, None, Strict
    domain = os.getenv("COOKIE_DOMAIN")  # optional

    opts = {"httponly": True, "secure": secure, "samesite": same_site, "path": "/"}

    if domain:
        opts["domain"] = domain

    return opts


def get_authenticated_user(cookies: dict, headers: dict) -> Tuple[JwtPayload | None, str | None]:
    """Extract the authenticated user and client context from JWT token.

    Checks Authorization header or sck_token cookie for valid JWT,
    then extracts user identity and client information.

    Auth sources (in order):
        - Authorization: Bearer <JWT>
        - sck_token cookie

    Args:
        request (Request): FastAPI request object

    Returns:
        Tuple[JwtPayload | None, str | None]: (jwt_payload, jwt_signature)
                                              Returns (None, None) if no valid token found

    Example:
        >>> jwt_payload, jwt_signature = get_authenticated_user(request)
        >>> if jwt_payload:
        ...     # User is authenticated, use client_name for data operations
        ...     client = jwt_payload.cnm or "core"
        ...     profile = ProfileActions.get(client=client, user_id=jwt_payload.sub, profile_name="default")

    Auth Sources (in order of preference):
        1. Authorization: Bearer <JWT> header
        2. sck_token cookie

    JWT Token Types Supported:
        - Session tokens (typ="session") - from login flow
        - Access tokens (typ="access_token") - from OAuth flow
        - Refresh tokens (typ="refresh") - for token renewal

    Security:
        - Validates JWT signature and expiration
        - Supports multiple authentication methods
        - Returns (None, None) for invalid/missing tokens
        - Logs warnings for invalid tokens

    Raises:
        No exceptions raised - returns None values for any authentication failure
    """
    # Get the token from either the "authorization" header or the "sck_token" cookie
    authz = (headers.get("authorization") or "").strip()
    token = None
    if authz.lower().startswith("bearer "):
        token = authz.split(" ", 1)[1].strip()
    elif SCK_TOKEN_COOKIE_NAME in cookies:
        token = cookies[SCK_TOKEN_COOKIE_NAME]

    if not token:
        return None, None

    try:
        jwt_parts = token.split(".")
        if len(jwt_parts) == 3:
            jwt_signature = jwt_parts[2]

        jwt_payload = JwtPayload.decode(token)

        return jwt_payload, jwt_signature

    except jwt.InvalidTokenError as e:
        log.warning(f"Invalid JWT token in request: {e}")

    return None, None


def get_oauth_app_info(client_id: str) -> ClientFact | None:
    """Retrieve OAuth client application registration from database by client identifier.

    Fetches complete OAuth client configuration including redirect URIs, client name,
    and other registration details. Used throughout OAuth flow for client validation.

    Args:
        client_id (str): OAuth client identifier to lookup (e.g., "coreui", "mobile-app")

    Returns:
        ClientFact | None: Complete client registration record or None if not found:
                    {
                        "client_id": "coreui",
                        "Client": "core",
                        "redirect_uri": "http://localhost:3000/auth/callback",
                        "client_name": "Core UI Application",
                        ...
                    }

    Database Integration:
        - Queries ClientActions.get() from core_db
        - Returns raw database record structure
        - Handles missing clients gracefully (returns None)
        - All database errors logged but don't raise exceptions

    Usage in OAuth Flow:
        - /auth/v1/authorize: Validates client_id and gets redirect_uri
        - /auth/v1/token: Validates client during token exchange
        - /auth/v1/login: Validates client during authentication

    Security Features:
        - Prevents unknown clients from participating in OAuth
        - Validates redirect URI against registered values
        - Enables client-specific configuration and limits
        - Audit trail via database logging

    Examples:
        >>> # Valid client lookup
        >>> app_info = get_oauth_app_info("coreui")
        >>> if app_info:
        ...     redirect_uri = app_info["redirect_uri"]
        ...     client_name = app_info["Client"]
        >>>
        >>> # Unknown client
        >>> app_info = get_oauth_app_info("malicious_app")
        >>> # Returns None - client not registered
        >>>
        >>> # OAuth flow validation
        >>> app_info = get_oauth_app_info(request.form["client_id"])
        >>> if not app_info:
        ...     return JSONResponse({"error": "invalid_client"}, status_code=401)
    """
    try:
        response = ClientActions.get(client_id=client_id)
        log.debug(f"OAuth app info for client {client_id}:", details=response.data)
        return ClientFact(**response.data)
    except Exception as e:
        log.error(f"Failed to get OAuth app info for client {client_id}: {e}")
        return None
