from profile import Profile
from typing import Optional
from datetime import datetime, timezone, timedelta
import random
import os
import re
from urllib.parse import urlencode
import uuid
import bcrypt
from core_db import ConflictException, NotFoundException
from core_db.registry import ClientFact
import httpx
import base64
import hmac
import hashlib
import struct
import time
from urllib.parse import quote as urlquote

import jwt

import core_logging as log
import core_framework as util
from core_helper.aws import invoke_lambda

from core_invoker.handler import handler as invoker_handler
from core_execute.actionlib.actions.system.send_email import SendEmailActionResource, SendEmailActionSpec
from core_framework.models import DeploymentDetails, PackageDetails, TaskPayload
from core_framework.models import ActionMetadata

from core_db.exceptions import OperationException
from core_db.profile import ProfileActions, UserProfile
from core_db.oauth import ForgotPassword, ForgotPasswordActions
from core_db.registry.client import ClientActions

from core_api.response import RedirectResponse

from ..request import RouteEndpoint
from ..response import ErrorResponse, Response, SuccessResponse, cookie_opts

from ..constants import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    SCK_MFA_COOKIE_NAME,
    SCK_TOKEN_COOKIE_NAME,
)

from .tools import (
    JwtPayload,
    create_mfa_session_jwt,
    emit_session_cookie,
    get_client_ip,
    get_authenticated_user,
    encrypt_aws_credentials,
    check_rate_limit,
    encrypt_credentials,
    get_mfa_token_user,
    get_oauth_app_info,
    is_password_compliant,
    revoke_access_token,
)

###########################################################
#
# THIS FILE IS RUN INSIDE A LAMBDA FUNCTION IT IS NOT A
# FASTAPI ASYNC HANDLER
#
###########################################################


# ---- TOTP helpers -----------------------------------------------------------


def _b32_secret_generate(num_bytes: int = 20) -> str:
    """Generate a random base32-encoded secret without padding."""
    secret = base64.b32encode(os.urandom(num_bytes)).decode("ascii")
    return secret.rstrip("=")


def _b32_secret_decode(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    # add padding back for decoding
    pad = "=" * ((8 - (len(s) % 8)) % 8)
    return base64.b32decode(s + pad, casefold=True)


def _hotp(key: bytes, counter: int, digits: int = 6) -> str:
    hm = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = hm[-1] & 0x0F
    dbc = ((hm[offset] & 0x7F) << 24) | ((hm[offset + 1] & 0xFF) << 16) | ((hm[offset + 2] & 0xFF) << 8) | (hm[offset + 3] & 0xFF)
    code = dbc % (10**digits)
    return str(code).zfill(digits)


def _totp_verify(secret: str, code: str, *, period: int = 30, skew: int = 1, digits: int = 6, now: Optional[int] = None) -> bool:
    """Verify a TOTP code with ±skew time steps.

    Args:
        secret: base32 secret
        code: code string from user
        period: time step in seconds
        skew: window of steps before/after to accept
        digits: number of digits expected
        now: optional epoch seconds for testing
    """
    if not code or not code.isdigit() or len(code) not in (6, 7, 8):
        return False
    try:
        key = _b32_secret_decode(secret)
    except Exception:
        return False
    ts = int(now if now is not None else time.time()) // period
    for off in range(-skew, skew + 1):
        if _hotp(key, ts + off, digits=digits) == code.zfill(digits):
            return True
    return False


def _build_otpauth_uri(secret: str, *, account_name: str, issuer: str, digits: int = 6, period: int = 30) -> str:
    label = f"{issuer}:{account_name}"
    # Use urlquote for path label, urlencode for query
    query = urlencode({"secret": secret, "issuer": issuer, "digits": str(digits), "period": str(period), "algorithm": "SHA1"})
    return f"otpauth://totp/{urlquote(label)}?{query}"


def _generate_recovery_codes(n: int = 10, length: int = 8) -> list[str]:
    alphabet = "0123456789"
    return ["".join(random.choices(alphabet, k=length)) for _ in range(n)]


def _hash_codes(codes: list[str]) -> list[str]:
    hashed: list[str] = []
    for c in codes:
        hashed.append(bcrypt.hashpw(c.encode("utf-8"), bcrypt.gensalt()).decode("utf-8"))
    return hashed


def _read_identity_cookie(cookies: dict) -> Optional[dict]:
    """Read and validate the sck_identity cookie set by OAuth callbacks.

    Args:
        cookies (Mapping[str, str] | dict): Request cookies map.

    Returns:
        Optional[dict]: Decoded identity payload if valid; otherwise None.
    """
    tok = cookies.get("sck_identity")
    if not tok:
        return None
    try:
        return jwt.decode(
            tok,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"verify_signature": True, "verify_exp": True, "verify_iat": True},
        )
    except jwt.InvalidTokenError:
        return None


def _profile_exists(user_id: str, profile_name: str = "default") -> bool:
    """Return True if a profile already exists for user_id/profile_name.

    Args:
        user_id (str): Profile owner identifier (email).
        profile_name (str): Profile name (default "default").

    Returns:
        bool: True if the profile exists; otherwise False.
    """
    try:
        ProfileActions.get(client="core", user_id=user_id, profile_name=profile_name)
        return True
    except Exception:
        return False


def _verify_captcha(token: Optional[str], ip: Optional[str]) -> bool:
    """
    Verify CAPTCHA using Cloudflare Turnstile or Google reCAPTCHA v2/v3.
    Uses the first configured provider.

    Env:
        TURNSTILE_SECRET or RECAPTCHA_SECRET

    Args:
        token (Optional[str]): CAPTCHA response token from client.
        ip (Optional[str]): Client IP for remoteip.

    Returns:
        bool: True if verification succeeded or not configured; False otherwise.
    """
    ts_secret = os.getenv("TURNSTILE_SECRET")
    rc_secret = os.getenv("RECAPTCHA_SECRET")

    if not ts_secret and not rc_secret:
        log.warning("CAPTCHA not configured; skipping verification")
        return True

    if not token:
        return False

    try:
        with httpx.AsyncClient(timeout=10) as client:
            if ts_secret:
                r = client.post(
                    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                    data={"secret": ts_secret, "response": token, "remoteip": ip or ""},
                )
                data = r.json()
                return bool(data.get("success"))
            else:
                r = client.post(
                    "https://www.google.com/recaptcha/api/siteverify",
                    data={"secret": rc_secret, "response": token, "remoteip": ip or ""},
                )
                data = r.json()
                return bool(data.get("success"))
    except Exception as e:
        log.warning(f"CAPTCHA verification failed: {e}")
        return False


def user_signup(*, cookies: dict = None, headers: dict = None, body: dict = None, **kwargs) -> Response:
    """Create or update the default profile, then return a session token.

    Route:
        POST /auth/v1/signup

    Modes:
        - SSO (GitHub/Apple): requires sck_identity cookie; body: { access_key, secret_key, first_name?, last_name? }.
          Encrypts with server key (JWE), creates or updates profile for authenticated user.
        - Email/password: body: { email, password, access_key, access_secret, first_name?, last_name? }.
          Email format validated by Pydantic UserProfile model.
          Encrypts with user password; creation only (409 if user exists).

    Response:
        201 JSON:
          {
            "data": {
              "user_id": "...",
              "profile_name": "default",
              "token": "<session_jwt>",        # typ=session, carries cred_jwe (long-term keys)
              "token_type": "Bearer"
            },
            "code": 201
          }

    Notes:
        - No cookies are set here. The session token is used with Authorization: Bearer
          when calling /auth/v1/authorize → /auth/v1/token or /auth/v1/refresh.
    """

    # Rate limit key standardized to auth:signup
    if not check_rate_limit(headers, "auth:signup", max_attempts=10, window_minutes=15):
        return ErrorResponse(code=429, message="rate_limited")

    # Common input
    first_name = body.get("first_name", "")
    last_name = body.get("last_name", "")
    password = body.get("password", "")
    client_id = body.get("client_id", "")
    aws_access_key = body.get("aws_access_key", "")
    aws_secret_key = body.get("aws_secret_key", "")

    if not client_id:
        return ErrorResponse(code=400, message="client_id is required")

    app_info: ClientFact = get_oauth_app_info(client_id=client_id)
    if not app_info:
        return ErrorResponse(code=400, message="invalid_client")

    client = app_info.client

    # Determine mode (SSO Sign-In-With-Github or Sign-In-With-Email)
    ident = _read_identity_cookie(cookies)

    if ident:
        # SSO path: use identity cookie for user_id; encrypt with server key
        user_id = ident.get("sub") or ident.get("email")
        email = ident.get("email") or ident.get("sub")
        password = random.token_urlsafe(16)  # Dummy password for encryption

    else:
        # Email/password path
        user_id = body.get("user_id") or body.get("email")
        email = body.get("email") or body.get("user_id")
        password = body.get("password")

        if not user_id or not password:
            return ErrorResponse(code=400, message="Email and password are required")

        # Validate password strength
        if not is_password_compliant(password):
            return ErrorResponse(code=400, message="Password does not meet requirements")

        captcha_token = body.get("captcha_token")

        ok = _verify_captcha(captcha_token, get_client_ip(headers))
        if not ok:
            return ErrorResponse(code=400, message="Invalid captcha")

    # During sign-up, there may or may not be aws credentials.
    # If there are not credentials, we'll safe the password, and we'll add
    # AWS credentials to the user profile at a later time.
    try:
        encrypted_credentials = encrypt_credentials(aws_access_key, aws_secret_key, password)
    except Exception as e:
        log.warning(f"Failed to encrypt credentials (such as bad password validation): {e}")
        return ErrorResponse(code=500, message="Failed to encrypt credentials", exception=e)

    try:
        # Load in UserProfile for validation with Pydantic (includes email validation)

        data = UserProfile(
            user_id=user_id,
            profile_name="default",
            email=email,
            first_name=first_name,
            last_name=last_name,
            credentials=encrypted_credentials,
            email_verified=False,
        ).model_dump()
    except Exception as e:
        # Pydantic validation errors (including invalid email) are client errors
        error_msg = str(e)
        if "email" in error_msg.lower():
            error_msg = "Invalid email format"

        return ErrorResponse(code=400, message=error_msg)

    exists = _profile_exists(user_id=user_id, profile_name="default")

    try:

        if ident:

            # Authenticated via SSO: allow create-or-update
            if exists:
                ProfileActions.patch(client=client, **data)
            else:
                log.info("New user profile created", details={"user_id": user_id, "client": client, "mode": "sso_signup"})
                ProfileActions.create(client=client, **data)

        else:
            # Signup via email/password: creation only; reject if exists
            if exists:
                return ErrorResponse(code=409, message=f"User '{user_id}' already exists")

            log.info("New user profile created", details={"user_id": user_id, "client": client, "mode": "email_signup"})

            ProfileActions.create(client=client, **data)

            _send_email_verification(client, user_id, email)

    except Exception as e:
        return ErrorResponse(code=500, message="Profile update failed", exception=e)

    return SuccessResponse()


def get_user_profile(
    *, cookies: dict = None, headers: dict = None, path_params: dict = None, query_params: dict = None, body: dict = None, **kwargs
) -> Response:
    """Get the authenticated user's profile.

    Route:
        GET /auth/v1/me

    Behavior:
        - Requires valid Authorization: Bearer token
    """

    jwt_payload, _ = get_authenticated_user(cookies=cookies)
    if jwt_payload is None:
        return ErrorResponse(code=401, message="Unauthorized")

    # Rate limit key standardized to auth:login
    if not check_rate_limit(headers, "auth:login", max_attempts=100, window_minutes=15):
        log.warning(f"Rate limit exceeded for user {jwt_payload.sub} on /auth/v1/me")
        return ErrorResponse(code=429, message="rate_limited")

    profile_name = query_params.get("profile_name", "default") if query_params else "default"

    # path parameters override if supplied
    profile_name = path_params.get("profile_name", profile_name) if path_params else profile_name

    try:
        profile = ProfileActions.get(client=jwt_payload.cnm, user_id=jwt_payload.sub, profile_name=profile_name)
        data = profile.model_dump(by_alias=False, mode="json")

        if "Password" in data.get("credentials", {}):
            del data["credentials"]["Password"]

        log.debug(f"Retrieved profile for user {jwt_payload.sub}", details=data)

        return SuccessResponse(data=data)

    except Exception as e:
        log.error(f"Failed to retrieve user profile for {jwt_payload.sub}: {e}")
        return ErrorResponse(code=500, message="Failed to retrieve user profile", exception=e)


def update_user_profile(
    *, cookies: dict = None, headers: dict = None, path_params: dict | None = None, body: dict = None, **kwargs
) -> Response:
    """Update user profile fields including AWS credentials.

    Route:
        PUT /auth/v1/users/me

    Request:
        JSON: {
            aws_access_key?: string,
            aws_secret_key?: string,
            first_name?: string,
            last_name?: string,
            email?: string
        }

    Behavior:
        - Updates only provided fields (PATCH semantics)
        - AWS credentials are encrypted and merged with existing credentials
        - Requires valid Authorization: Bearer token
    """
    # Get authenticated user first
    jwt_payload, _ = get_authenticated_user(cookies=cookies)
    if jwt_payload is None:
        return ErrorResponse(code=401, message="Unauthorized")

    # Rate limit key standardized to auth:profile:update
    if not check_rate_limit(headers, "auth:profile:update", max_attempts=20, window_minutes=1):
        log.warning(f"Rate limit exceeded for user {jwt_payload.sub} on /v1/users/me")
        return ErrorResponse(code=429, message="rate_limited")

    if body is None:
        body = {}

    # Extract update fields
    aws_access_key = body.pop("aws_access_key", None)
    aws_secret_key = body.pop("aws_secret_key", None)
    profile_name = body.pop("profile_name", "default").strip()
    body.pop("user_id", None)  # Prevent user_id changes
    body.pop("profile_name", None)  # Prevent profile_name changes
    body.pop("credentials", None)  # Prevent direct credentials changes

    # path parameters override if supplied
    profile_name = path_params.get("profile_name", profile_name) if path_params else profile_name

    if not profile_name:
        return ErrorResponse(code=400, message="profile_name cannot be empty")

    # Get current profile

    # Prepare update data (only include fields that are provided)
    update_data = {}

    for k, v in body.items():
        update_data[k] = v

    if body.pop("logged_in", False):
        update_data["last_login"] = datetime.now(timezone.utc)
        update_data["increment_session"] = "true"

    # Handle AWS credentials update
    if aws_access_key and aws_secret_key:
        try:

            profile = ProfileActions.get(
                client=jwt_payload.cnm,
                user_id=jwt_payload.sub,
                profile_name=profile_name,
            )

            # Get existing credentials envelope or create new one
            existing_credentials = profile.credentials
            if existing_credentials is None:
                existing_credentials = {"created_at": datetime.now(timezone.utc).isoformat()}

            existing_credentials["updated_at"] = datetime.now(timezone.utc).isoformat()

            new_aws_creds = encrypt_aws_credentials(aws_access_key, aws_secret_key)
            existing_credentials.update(new_aws_creds)

            # Preserve password hash if it exists
            update_data["credentials"] = existing_credentials

            update_data["identity"] = _get_identity(existing_credentials)

        except OperationException as e:
            log.warn(f"Failed to retrieve user profile for {jwt_payload.sub}: {e}")
            return ErrorResponse(code=e.code, message="User profile read failure", exception=e)
        except Exception as e:
            log.warn(f"Failed to encrypt AWS credentials for {jwt_payload.sub}: {e}")
            return ErrorResponse(code=500, message="Failed to encrypt AWS credentials", exception=e)

    # Perform the update
    try:

        log.debug(f"Updating profile for user {jwt_payload.sub}, profile {profile_name}", details=update_data)
        new_response: UserProfile = ProfileActions.patch(
            client=jwt_payload.cnm, user_id=jwt_payload.sub, profile_name=profile_name, **update_data
        )
        new_data = new_response.model_dump(by_alias=False, mode="json")
        if "Password" in new_data.get("credentials", {}):
            del new_data["credentials"]["Password"]

        return SuccessResponse(data=new_data)

    except Exception as e:
        log.error(f"Failed to update user profile for {jwt_payload.sub}: {e}")
        return ErrorResponse(code=500, message="Failed to update user profile", exception=e)


def list_user_profiles(*, cookies: dict = None, headers: dict = None, body: dict = None, **kwargs) -> Response:
    """List all profiles for the authenticated user.

    Route:
        GET /auth/v1/users/me/profiles

    Behavior:
        - Requires valid Authorization
    """

    jwt_payload, _ = get_authenticated_user(cookies=cookies)
    if jwt_payload is None:
        return ErrorResponse(code=401, message="Unauthorized")

    # Rate limit key standardized to auth:profile:list
    if not check_rate_limit(headers, "auth:profile:list", max_attempts=20, window_minutes=1):
        log.warning(
            "Rate limit exceeded listing profiles",
            details={
                "user": jwt_payload.sub,
                "client": jwt_payload.cnm,
                "endpoint": "/auth/v1/users/me/profiles",
                "action": "list_user_profiles",
            },
        )
        return ErrorResponse(code=429, message="rate_limited")

    include_fields = {"user_id", "profile_name"}

    try:
        profile_list, paginator = ProfileActions.list(client=jwt_payload.cnm, user_id=jwt_payload.sub)
        # The response.data probably returned PascalCase, we need to convert to snake_case
        profiles = [item.model_dump(by_alias=False, include=include_fields) for item in profile_list]
        log.debug(f"Listed {len(profiles)} profiles for user {jwt_payload.sub}", details={"profiles": profiles})
        return SuccessResponse(data={"profiles": profiles}, metadata=paginator.get_metadata())
    except Exception as e:
        log.error(f"Failed to list user profiles for {jwt_payload.sub}: {e}")
        return ErrorResponse(code=500, message="Failed to list user profiles", exception=e)


def create_user_profile(*, cookies: dict = None, headers: dict = None, body: dict = None, **kwargs) -> Response:

    jwt_payload, _ = get_authenticated_user(cookies=cookies)
    if jwt_payload is None:
        return ErrorResponse(code=401, message="Unauthorized")

    # Rate limit key standardized to auth:profile:create
    if not check_rate_limit(headers, "auth:profile:create", max_attempts=20, window_minutes=1):
        log.warning(
            "Rate limit exceeded creating profile",
            details={
                "user": jwt_payload.sub,
                "client": jwt_payload.cnm,
                "endpoint": "/auth/v1/me",
                "action": "create_user_profile",
            },
        )
        return ErrorResponse(code=429, message="rate_limited")

    if body is None:
        body = {}

    body.pop("user_id", None)  # user_id comes from authentication session
    body.pop("client", None)  # client comes from authentication session

    # profile name is required, must be lowercase a-z and 1 to 12 characters in length
    profile_name = body.pop("profile_name", "").strip()

    if not profile_name:
        log.warning(
            "Empty profile_name on create",
            details={"user": jwt_payload.sub, "client": jwt_payload.cnm},
        )
        return ErrorResponse(code=400, message="Profile name is required")

    # Prevent user_id and client changes

    if not re.match(r"^[a-z]{1,12}$", profile_name):
        log.warning(
            "Invalid profile_name format",
            details={
                "user": jwt_payload.sub,
                "client": jwt_payload.cnm,
                "profile_name": profile_name,
                "rule": "^[a-z]{1,12}$",
            },
        )
        return ErrorResponse(code=400, message="Invalid profile_name format")

    try:

        profile = ProfileActions.create(
            client=jwt_payload.cnm,
            user_id=jwt_payload.sub,
            profile_name=profile_name,
        )
        data = profile.model_dump(by_alias=False, exclude={"credentials"}, mode="json")
        log.info(
            "User profile created",
            details={
                "user": jwt_payload.sub,
                "client": jwt_payload.cnm,
                "profile_name": profile_name,
            },
        )
        return SuccessResponse(code=201, data=data)

    except ValueError as ve:
        log.warning(
            "Profile creation validation error",
            details={
                "user": jwt_payload.sub,
                "client": jwt_payload.cnm,
                "profile_name": profile_name,
                "error": str(ve),
            },
        )
        return ErrorResponse(code=400, message=str(ve))
    except ConflictException:
        log.info(
            "Profile creation conflict",
            details={
                "user": jwt_payload.sub,
                "client": jwt_payload.cnm,
                "profile_name": profile_name,
            },
        )
        return ErrorResponse(code=409, message="User profile already exists")
    except Exception as e:
        log.error(
            f"Profile creation failed for user {jwt_payload.sub}",
            details={
                "client": jwt_payload.cnm,
                "profile_name": profile_name,
                "error": str(e),
            },
        )
        return ErrorResponse(code=500, message="Profile creation failed", exception=e)


def delete_user_profile(
    *, cookies: dict = None, headers: dict = None, path_params: dict | None = None, body: dict = None, **kwargs
) -> Response:

    jwt_payload, _ = get_authenticated_user(cookies=cookies)

    if jwt_payload is None:
        return ErrorResponse(code=401, message="Unauthorized")

    # Rate limit key standardized to auth:profile:delete
    if not check_rate_limit(headers, "auth:profile:delete", max_attempts=5, window_minutes=1):
        log.warning(
            "Rate limit exceeded deleting profile",
            details={
                "user": jwt_payload.sub,
                "client": jwt_payload.cnm,
                "endpoint": "/auth/v1/me",
                "action": "delete_user_profile",
            },
        )
        return ErrorResponse(code=429, message="rate_limited")

    if body is None:
        body = {}

    profile_name = body.get("profile_name", "").strip()

    # path parameters override if supplied
    profile_name = path_params.get("profile_name", profile_name) if path_params else profile_name

    if not profile_name:
        log.warning(
            "Empty profile_name on delete",
            details={"user": jwt_payload.sub, "client": jwt_payload.cnm},
        )
        return ErrorResponse(code=400, message="Profile name is required")

    if profile_name == "default":
        log.warning(
            "Attempt to delete default profile",
            details={"user": jwt_payload.sub, "client": jwt_payload.cnm},
        )
        return ErrorResponse(code=400, message="Cannot delete default profile")

    if not re.match(r"^[a-z]{1,12}$", profile_name):
        log.warning(
            "Invalid profile_name format on delete",
            details={
                "user": jwt_payload.sub,
                "client": jwt_payload.cnm,
                "profile_name": profile_name,
                "rule": "^[a-z]{1,12}$",
            },
        )
        return ErrorResponse(code=400, message="Invalid profile_name format")

    try:
        ProfileActions.delete(
            client=jwt_payload.cnm,
            user_id=jwt_payload.sub,
            profile_name=profile_name,
        )
        log.info(
            "User profile deleted",
            details={
                "user": jwt_payload.sub,
                "client": jwt_payload.cnm,
                "profile_name": profile_name,
            },
        )
        return SuccessResponse(code=200, message="Profile deleted")
    except NotFoundException:
        log.info(
            "Profile deletion not found",
            details={
                "user": jwt_payload.sub,
                "client": jwt_payload.cnm,
                "profile_name": profile_name,
            },
        )
        return ErrorResponse(code=404, message="User profile not found")
    except Exception as e:
        log.error(
            f"Profile deletion failed for user {jwt_payload.sub}",
            details={
                "client": jwt_payload.cnm,
                "profile_name": profile_name,
                "error": str(e),
            },
        )
        return ErrorResponse(code=500, message="Profile deletion failed", exception=e)


def _get_identity(aws_credentials: dict) -> dict:
    """Extract AWS identity information from encrypted credentials."""
    import boto3

    try:

        client = boto3.client(
            "sts",
            aws_access_key_id=aws_credentials.get("AccessKeyId"),
            aws_secret_access_key=aws_credentials.get("SecretAccessKey"),
        )

        identity = client.get_caller_identity()

        response = {
            "UserId": identity.get("UserId"),
            "Account": identity.get("Account"),
            "Arn": identity.get("Arn"),
        }

        return response
    except Exception as e:
        log.warning(f"Failed to get AWS identity: {e}")
        return {}


def user_login(*, headers: dict = None, body: dict = None, **kwargs) -> Response:
    """
    Authenticate with email/password and return a basic session JWT with client context.

    This endpoint is part of the OAuth flow for email/password authentication.
    It validates user credentials and returns a session JWT that contains user
    identity and client context but NO AWS credentials. The session JWT is used
    to continue the OAuth authorization flow.

    Route:
        POST /auth/v1/login

    Request:
        JSON: {
            "email": string,           // Required - User email address (user_id)
            "password": string,        // Required - User password
            "client_id": string,       // Required - OAuth client identifier
            "client"?: string,         // Optional - Client name/slug (defaults to client DB value or "core")
            "returnTo"?: string        // Optional - Original OAuth URL to return to after login
        }

    Behavior:
        - Validates client_id against OAuth applications database
        - Retrieves user profile from database using client context
        - Validates password against stored bcrypt hash
        - Rate limits login attempts (10 attempts per 15 minutes)
        - Creates session JWT with user identity and client context
        - Returns session token for OAuth flow continuation

    JWT Claims (session token):
        - sub: User ID (email)
        - typ: "session"
        - iss: "sck-core-api"
        - iat/exp: Timestamps
        - jti: Unique token ID
        - cid: OAuth client ID
        - cnm: Client name/slug for data operations

    Response:
        Success (200):
          {
            "data": {
                "token": "<session_jwt>",      // JWT session token
                "expires_in": 1800,            // Token lifetime in seconds (30 min)
                "token_type": "Bearer",        // Token type for Authorization header
                "returnTo"?: "string"          // Original OAuth URL (if provided)
            },
             "code": 200
           }

        Errors:
          400 - Missing required fields, invalid client_id
          401 - Invalid credentials, user not found, no password configured
          429 - Rate limit exceeded
          500 - Server processing error

    OAuth Flow Context:
        1. User visits /auth/v1/authorize?client_id=myapp&...
        2. Not authenticated → redirected to /login?client_id=myapp&returnTo=...
        3. User submits this login form with client_id preserved
        4. Returns session JWT with client context
        5. React app redirects to returnTo URL with session token
        6. /auth/v1/authorize continues with authenticated user + client

    Examples:
        >>> # Standard OAuth login request
        >>> {
        ...   "email": "user@example.com",
        ...   "password": "SecurePass123!",
        ...   "client_id": "coreui",
        ...   "returnTo": "/auth/v1/authorize?client_id=coreui&response_type=code&..."
        ... }
        >>>
        >>> # Minimal login request (defaults client to DB value)
        >>> {
        ...   "email": "user@example.com",
        ...   "password": "SecurePass123!",
        ...   "client_id": "mobile_app"
        ... }
    """

    try:
        user_id = body.get("email")
        password = body.get("password", "")
        if not user_id or not password:
            return ErrorResponse(code=400, message="Email and password are required")

        client_id = body.get("client_id")
        if not client_id:
            return ErrorResponse(code=400, message="The field client_id is required")

        # Rate limit key standardized to auth:login
        if not check_rate_limit(headers, "auth:login", max_attempts=100, window_minutes=15):
            log.warning(f"Rate limit exceeded for user {user_id} on /auth/v1/login")
            return ErrorResponse(code=429, message="rate_limited")

        app_info: ClientFact = get_oauth_app_info(client_id)
        if not app_info:
            log.warn("Invalid client attempted login: %s", client_id)
            return ErrorResponse(code=400, message="invalid_client")

        client = app_info.client

        # Get user profile and validate password
        try:
            profile_name = "default"
            profile_data = ProfileActions.get(client=client, user_id=user_id, profile_name=profile_name)
        except Exception as e:
            log.debug(f"Profile not found for user {user_id}: {e}")
            return ErrorResponse(code=401, message="Authorization Failed", exception=e)

        # Check if user has a password (some SSO users might not)
        credentials = profile_data.credentials or {}
        stored_hash = credentials.get("Password")
        if not stored_hash:
            log.warn("Login attempt for user without password: %s", user_id)
            log.debug(f"No password found for user {user_id}")
            return ErrorResponse(code=401, message="Authorization Failed")

        # Validate password against stored hash
        if not bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
            log.warn("Password validation failed for user: %s", user_id)
            log.debug(f"Password validation failed for user {user_id}")
            return ErrorResponse(code=401, message="Authorization Failed")

        if profile_data.mfa_enabled:
            session_jwt = create_mfa_session_jwt(client_id, client, user_id, 5)
            resp = SuccessResponse(code=202, message="mfa_required")
            resp.set_cookie(SCK_MFA_COOKIE_NAME, session_jwt, max_age=5 * 60, **cookie_opts())
            return resp

        return emit_session_cookie(SuccessResponse(), client_id, client, user_id)

    except Exception as e:
        log.error(f"Login error for {user_id}: {e}")
        return ErrorResponse(code=500, message="Authentication processing error", exception=e)


def forgot_password(*, headers: dict = None, body: dict = None, **kwargs):
    """Generate forgot password token and queue email via API→Invoker→Runner→StepFunction chain."""

    valid_characters = "0123456789"
    code = "".join(random.choices(valid_characters, k=8))
    key = f"forgot_password:{code}"
    email = body.get("email", None)
    client = body.get("client", "core")
    client_id = body.get("client_id", "")

    # Rate limit key standardized to auth:forgot_password
    if not check_rate_limit(headers, "auth:forgot_password", max_attempts=50, window_minutes=15):
        log.warning("Rate limit exceeded for /auth/v1/forgot-password")
        return ErrorResponse(code=429, message="rate_limited")

    if not email:
        return ErrorResponse(code=400, message="Email Address is required")

    if not client_id:
        return ErrorResponse(code=400, message="Client ID is required")

    try:

        EXPIRATION_MINUTES = 15
        token = JwtPayload(sub=email, typ="forgot_password", cid=client_id, cnm=client, ttl=EXPIRATION_MINUTES, jti=code).encode()

        forgot_password_record = ForgotPassword(
            **{
                "code": key,
                "email": email,
                "user_id": email,
                "client": client,
                "client_id": client_id,
                "reset_token": token,
                "used": False,
                "expires_at": datetime.now(timezone.utc) + timedelta(minutes=EXPIRATION_MINUTES),
            }
        )

        ForgotPasswordActions.create(**forgot_password_record.model_dump())

        log.info("Forgot password request created", details={"email": email, "client": client})

    except Exception as e:
        log.warn("Failed to create forgot password request for %s: %s", email, str(e))
        return ErrorResponse(code=500, message="Failed to create forgot password request", exception=e)

    host = os.getenv("CLIENT_HOST", "http://localhost:8080")
    server_url = host + os.getenv("CLIENT_NEW_PASSWORD", "/new-password")

    try:
        _queue_email_via_security_chain(
            client=client,
            email_type="authcode",
            to_email=email,
            template_data={
                "auth_code": code,
                "user_name": email.split("@")[0],
                "company_name": "Core",
                "reset_url": f"{server_url}?code={code}&token={token}",
            },
        )

        log.info("Forgot password email queued successfully for %s", email)

    except Exception as e:
        log.warn("Failed to queue forgot password email for %s: %s", email, str(e))
        # Continue anyway - user has the token for manual verification

    return SuccessResponse(data={"token": token})


def _queue_email_via_security_chain(client: str, email_type: str, to_email: str, template_data: dict) -> None:
    """Queue email sending via API→Invoker→Runner→StepFunction security chain."""

    try:
        # You must define which AWS Account has the permission to send emails
        # Will also need to be able to assume the role for the email sending
        # for the region that needs to send email
        spec = SendEmailActionSpec(
            account=util.get_automation_account(),
            region=util.get_automation_region(),
            to_email=to_email,
            subject=_get_email_subject(email_type),
            template_type=email_type,
            template_data=template_data,
        )

        metadata = ActionMetadata(
            name="system-send-email",
            namespace="email",
            description="Send email action",
        )

        send_email_action = SendEmailActionResource(metadata=metadata, spec=spec)

        # Load the applications to the deployment package
        package_details = PackageDetails(actions=[send_email_action])

        # Defines the applicationperforming the action
        deployment_details = DeploymentDetails(
            client=client,  # Customer: core, acme, bbr, etc.
            portfolio="core-automation",  # System: automation (email system runs in automation portfolio)
            # branch=None, build=None (not specified for portfolio scope)
        )

        # Build the task payload for the invoker.  Note, you can't put Jinja2 action payloads in this method.
        # see the "compile" task for core_deployspec for that.
        task_payload = TaskPayload(
            correlation_id=log.get_correlation_id(),
            client=client,
            task="deploy",  # "deploy" means "run the actions in this package"
            deployment_details=deployment_details,
            package=package_details,
            type="deployspec",  # "deployspec" means "here is a full package spec"
        )

        log.debug("Email task queued:", details=task_payload.model_dump())

        if util.is_local_mode():
            # Local mode: Call invoker handler directly
            response = invoker_handler(task_payload.model_dump())
            log.debug("Email task executed locally", details={"response": response})
        else:
            # Production: Invoke through security chain
            arn = util.get_invoker_lambda_arn()
            response = invoke_lambda(arn, task_payload.model_dump())
            log.debug("Email task invoked via Lambda", details={"response": response})

    except ValueError as ve:
        errors = ve.errors() if hasattr(ve, "errors") else str(ve)
        log.warn("Failed to queue email via security chain: %s", errors)
    except Exception as e:
        log.warn("Failed to queue email via security chain: %s", str(e))
        # Don't raise - email failure shouldn't break the main operation


def _get_email_subject(email_type: str) -> str:
    """Get email subject based on type."""
    subjects = {
        "authcode": "Password Reset Verification Code",
        "passupdated": "Password Updated Successfully",
        "welcome": "Welcome to Simple Cloud Kit",
    }
    return subjects.get(email_type, "Notification")


def verify_secret(*, cookies: dict = None, headers: dict = None, body: dict = None, **kwargs):
    log.info("Verify secret called")

    try:
        jwt_token, _ = get_authenticated_user(cookies=cookies, headers=headers)
    except Exception as e:
        log.debug(f"Failed to get authenticated user: {str(e)}")
        return ErrorResponse(code=401, message=f"Unauthorized: {str(e)}")

    if not jwt_token:
        return ErrorResponse(code=401, message="Unauthorized - missing or invalid token")

    try:

        code = body.get("code", None)
        email = jwt_token.sub
        client = jwt_token.cnm
        client_id = jwt_token.cid
        jti = jwt_token.jti  # The expected code from JWT
        token_type = jwt_token.typ

        # Validate this is a forgot password token
        if token_type != "forgot_password":
            return ErrorResponse(code=401, message="Invalid token type for verification")

        # Verify the code matches the one in the JWT
        if code != jti:
            log.warning(f"Code mismatch for {email}: input={code}, jwt={jti}")
            return ErrorResponse(code=404, message="Verification code not found in database")

        key = f"forgot_password:{jwt_token.jti}"
        result = ForgotPasswordActions.get(client=client, code=key)
        if not result:
            return ErrorResponse(code=404, message="Forgot password request not found")

        data = ForgotPassword(**result.data)

        if data.verified:
            return ErrorResponse(code=400, message="Secret already verified")

        data.verified = True

        ForgotPasswordActions.patch(client=jwt_token.cnm, **data.model_dump())

        return SuccessResponse(message="Token verified")

    except Exception as e:
        log.debug(f"Failed to verify secret: {str(e)}")
        return ErrorResponse(code=500, message=f"Failed to verify secret: {str(e)}", exception=e)


def set_new_password(*, cookies: dict = None, headers: dict = None, body: dict = None, **kwargs):

    log.info("Set new password called")

    try:
        jwt_token, _ = get_authenticated_user(cookies=cookies, headers=headers)
    except Exception as e:
        log.debug(f"Failed to get authenticated password token: {str(e)}")
        return ErrorResponse(code=401, message=f"Unauthorized - missing or invalid token: {str(e)}")

    if not jwt_token:
        log.debug("Authorization token is missing or expired")
        return ErrorResponse(
            code=401, message="Authorization token is missing or expired.  Please request a new authorization code."
        )

    new_password = body.get("password")

    if not new_password:
        log.debug("New password is missing from request")
        return ErrorResponse(code=400, message="Missing new password")

    email = jwt_token.sub
    client = jwt_token.cnm
    jti = jwt_token.jti
    token_type = jwt_token.typ
    client_id = jwt_token.cid

    if token_type != "forgot_password":
        log.debug(f"Invalid token type for password reset: {token_type}")
        return ErrorResponse(code=401, message="Invalid token type for password reset")

    try:
        key = f"forgot_password:{jti}"
        result = ForgotPasswordActions.get(client=client, code=key)
        forgot_password = ForgotPassword(**result.data)
    except Exception as e:
        log.debug(f"Failed to get forgot password request: {str(e)}")
        return ErrorResponse(code=400, message="Forgot password request not found")

    if not forgot_password.verified:
        return ErrorResponse(code=400, message="Forgot password request has not been verified")

    forgot_password.used = True
    try:
        ForgotPasswordActions.patch(client=client, code=key, client_id=client_id, **forgot_password.model_dump())
    except Exception as e:
        log.debug(f"Failed to update forgot password request: {str(e)}")
        return ErrorResponse(code=500, message="Failed to update forgot password request")

    try:
        profile_name = "default"
        log.info(f"Looking up user profile {client}/{profile_name}: {email} ")
        profile = ProfileActions.get(client=client, user_id=email, profile_name=profile_name)
    except Exception as e:
        log.debug(f"Failed to get user profile: {str(e)}")
        return ErrorResponse(code=404, message="User profile not found")

    try:
        credentials = profile.credentials or {}
        credentials["Password"] = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        profile.credentials = credentials
        data = profile.model_dump(by_alias=False)
        log.debug("Updating user profile with new password", details=data)

        ProfileActions.update(client=client, **data)

        log.info("Password updated successfully", details={"email": email, "client": client})

        _queue_email_via_security_chain(
            client=client,
            email_type="passupdated",
            to_email=email,
            template_data={
                "user_name": email.split("@")[0],
                "company_name": "Core",
                "ip_address": headers.get("source_ip"),
                "user_agent": headers.get("user_agent"),
            },
        )

        return SuccessResponse(message="Password updated successfully")

    except Exception as e:
        log.debug(f"Failed to set new password: {str(e)}")
        return ErrorResponse(code=500, message=f"Failed to set new password.  Please contact support.", exception=e)


def user_logout(*, cookies: dict = None, headers: dict = None, query_params: dict = None, **kwargs):
    """OAuth/OpenID Connect logout endpoint.

    Route:
        GET /auth/v1/logout
    Query:
        post_logout_redirect_uri (optional): Where to redirect after logout
        state (optional): Opaque value to maintain state

    Returns:
        Response: Logout confirmation or redirect
    """
    post_logout_redirect_uri = query_params.get("post_logout_redirect_uri")
    state = query_params.get("state")

    # Rate limiting
    # Rate limit key standardized to auth:logout
    if not check_rate_limit(headers, "auth:logout", max_attempts=10, window_minutes=1):
        log.warn("Rate limit exceeded on /auth/v1/logout")
        return ErrorResponse(code=429, message="rate_limited")

    # Get current user to validate logout
    jwt_payload, _ = get_authenticated_user(cookies=cookies)
    if jwt_payload is not None:
        revoke_access_token(jwt_payload)

    # Build logout redirect URL
    if post_logout_redirect_uri:
        # Validate redirect URI (you might want to check against registered URIs)
        params = {}
        if state:
            params["state"] = state

        redirect_url = post_logout_redirect_uri
        if params:
            separator = "&" if "?" in redirect_url else "?"
            redirect_url = f"{redirect_url}{separator}{urlencode(params)}"

        # Clear session cookies and redirect
        response = RedirectResponse(url=redirect_url)
    else:
        response = SuccessResponse(code=204)

    response.delete_cookie(SCK_TOKEN_COOKIE_NAME, path="/")
    return response


def refresh_session_cookie(*, cookies: dict = None, headers: dict = None, body: dict = None, **kwargs) -> Response:
    """Sliding-window session refresh endpoint.

    Route: POST /auth/v1/refresh

    Behavior:
      - Validates existing session token (typ=session) in cookie.
      - If token expired → 401 + cookie cleared.
      - If not yet inside refresh threshold (seconds_left > SCK_TOKEN_REFRESH_SECONDS) → 204 no-op (idempotent).
      - If inside refresh threshold → issue new session token extending window (SCK_TOKEN_SESSION_MINUTES) without exceeding
        absolute max (SCK_SESSION_ABSOLUTE_MAX_MINUTES from original auth_time).
      - Returns 204 on success (no body) for both rotate and no-op cases.

    Rate limiting: auth:session:refresh (low-cost, moderate allowance).
    """

    headers = headers or {}
    cookies = cookies or {}

    if not check_rate_limit(headers, "auth:session:refresh", max_attempts=120, window_minutes=10):
        log.warn("Rate limit exceeded on /auth/v1/refresh")
        return ErrorResponse(code=429, message="rate_limited")

    jwt_payload, _ = get_authenticated_user(cookies=cookies)
    if not jwt_payload or jwt_payload.typ != "session":
        log.debug("/auth/v1/refresh missing/invalid session", details={"has_jwt": bool(jwt_payload)})
        resp = ErrorResponse(code=401, message="invalid_session")
        resp.delete_cookie(SCK_TOKEN_COOKIE_NAME, path="/")
        return resp

    client = jwt_payload.cnm
    user_id = jwt_payload.sub
    client_id = jwt_payload.cid

    return emit_session_cookie(SuccessResponse(code=204), client_id, client, user_id)


def list_organizations(*, headers: dict = None, **kwargs) -> Response:
    """List organizations the authenticated user belongs to.

    Route:
        GET /auth/v1/organizations

    Behavior:
        - Requires valid Authorization: Bearer token
        - Returns a list of organizations associated with the user
    """

    # Rate limit key standardized to auth:organization:list
    if not check_rate_limit(headers, "auth:organization:list", max_attempts=10, window_minutes=1):
        log.warning(f"Rate limit exceeded for /auth/v1/organizations")
        return ErrorResponse(code=429, message="rate_limited")

    try:

        client_list, _ = ClientActions.list(client="core", limit=1000)

    except Exception as e:
        log.error(f"Failed to retrieve organizations: {e}")
        return SuccessResponse(code=204)

    clients: list[ClientFact] = client_list

    data = [{"client": c.client, "client_name": c.client_name} for c in clients]

    return SuccessResponse(data=data)


def verify_email_address(*, headers: dict = None, query_params: dict = None, body: dict = None, **kwargs) -> Response:
    """Verify email address using a token.

    Route:
        GET /auth/v1/verify

    Request:
        JSON: {
            "token": string,           // Required - Verification token
            "client": string           // Required - Client name/slug (defaults to "core")
        }

    Behavior:
        - Validates the provided verification token
        - Marks the user's email as verified if the token is valid
        - Returns a success message upon successful verification

    Response:
        Success (200):
          {
            "message": "Email verified successfully"
          }

        Errors:
          400 - Missing required fields
          401 - Invalid or expired token
          500 - Server processing error
    """
    token = body.get("token") or query_params.get("token")
    client = body.get("client", "core") or query_params.get("client", "core")

    if not token:
        return ErrorResponse(code=400, message="Verification token is required")

    # Rate limit key standardized to auth:email:verification
    if not check_rate_limit(headers, "auth:email:verification", max_attempts=10, window_minutes=15):
        log.warning(f"Rate limit exceeded on /auth/v1/verify")
        return ErrorResponse(code=429, message="rate_limited")

    try:
        payload = JwtPayload.decode(token)
        if payload.typ != "email_verification":
            return ErrorResponse(code=401, message="Invalid token type")

        user_id = payload.sub

        # Retrieve user profile
        profile = ProfileActions.get(client=client, user_id=user_id, profile_name="default")

        if profile.email_verified:
            return SuccessResponse(message="Email already verified")

        # Mark email as verified
        profile.email_verified = True
        profile.email_verified_at = datetime.now(timezone.utc)
        ProfileActions.patch(client=client, record=profile)

        log.info(f"Email verified successfully for user {user_id}", details={"client": client})

        return SuccessResponse(message="Email verified successfully")

    except Exception as e:
        log.error(f"Failed to verify email: {e}")
        return ErrorResponse(code=500, message="Failed to verify email", exception=e)


def _send_email_verification(client: str, user_id: str, to_email: str, *, is_resend: bool = False) -> None:
    """Send email verification email via security chain.

    Args:
        client: Client name/slug for data isolation
        user_id: The user's id/email (used for token subject)
        to_email: Destination email
        is_resend: When True, signals the template to render resend-specific copy
    """
    host = os.getenv("CLIENT_HOST", "http://localhost:8080")
    server_url = host + os.getenv("CLIENT_EMAIL_VERIFICATION", "/verify-email")

    try:
        # Token valid for 24 hours (in minutes)
        minutes = 60 * 24
        verification_token = JwtPayload(
            sub=user_id,
            typ="email_verification",
            cid="",
            cnm=client,
            ttl=minutes,
            jti=str(uuid.uuid4()),
        ).encode()

        verification_url = f"{server_url}?token={verification_token}&client={client}"

        _queue_email_via_security_chain(
            client=client,
            email_type="welcome",
            to_email=to_email,
            template_data={
                "user_name": user_id.split("@")[0],
                "company_name": "Core",
                "verification_url": verification_url,
                "verification_expires_minutes": minutes,
                "login_url": host + os.getenv("CLIENT_LOGIN", "/login"),
                "support_email": os.getenv("SUPPORT_EMAIL", "support@eits.com.sg"),
                "is_resend": is_resend,
                # Always define 'features' for STRICT template rendering
                # The welcome templates check `{% if features %}`; provide an empty list by default
                "features": [],
            },
        )

        log.info("Email verification queued successfully for %s", user_id)

    except Exception as e:
        log.warn("Failed to queue email verification for %s: %s", user_id, str(e))
        # Don't raise - email failure shouldn't break the main operation


def resend_verification_email(*, headers: dict = None, body: dict = None, **kwargs) -> Response:
    """Resend email verification to user.

    Route:
        POST /auth/v1/verification/resend

    Request:
        JSON: {
            "email": string,           // Required - User email address (user_id)
            "client": string           // Required - Client name/slug (defaults to "core")
        }

    Behavior:
        - Validates the provided email address
        - Resends the email verification if the user exists and is not already verified
        - Returns a success message upon successful queuing of the email

    Response:
        Success (200):
          {
            "message": "Verification email resent successfully"
          }

        Errors:
          400 - Missing required fields
          404 - User not found or already verified
          429 - Rate limit exceeded
          500 - Server processing error
    """
    email = body.get("email")
    client = body.get("client", "core")

    if not email:
        return ErrorResponse(code=400, message="Email Address is required")

    # Rate limit key standardized to auth:email:verification
    if not check_rate_limit(headers, "auth:email:verification", max_attempts=10, window_minutes=15):
        log.warning(f"Rate limit exceeded on /auth/v1/verification/resend")
        return ErrorResponse(code=429, message="rate_limited")

    try:
        profile_name = "default"
        profile = ProfileActions.get(client=client, user_id=email, profile_name=profile_name)
    except Exception as e:
        log.debug(f"Profile not found for user {email}: {e}")
        return ErrorResponse(code=404, message="User not found")

    if profile.email_verified:
        return ErrorResponse(code=400, message="Email is already verified")

    try:
        _send_email_verification(client, email, profile.email, is_resend=True)
        return SuccessResponse(message="Verification email resent successfully")

    except Exception as e:
        log.error(f"Failed to resend verification email to {email}: {e}")
        return ErrorResponse(code=500, message="Failed to resend verification email", exception=e)


def mfa_totp_setup(*, cookies: dict = None, headers: dict = None, body: dict = None, **kwargs) -> Response:
    """Set up TOTP MFA for the authenticated user.

    Route:
        POST /auth/v1/mfa/totp/setup

    Request:
        JSON: {
            "label": string,           // Optional - Label for the TOTP (e.g., "MyApp")
            "issuer": string           // Optional - Issuer name for the TOTP (e.g., "MyCompany")
        }

    Behavior:
        - Requires valid Authorization: Bearer token
        - Generates a TOTP secret and provisioning URI
        - Returns the TOTP secret and provisioning URI for the user to configure their authenticator app

    Response:
        Success (200):
          {
            "data": {
                "secret": "<totp_secret>",          // Base32 encoded TOTP secret
                "provisioning_uri": "<uri>"         // URI for QR code generation
            },
             "code": 200,
              }
    """
    jwt_payload, _ = get_authenticated_user(cookies=cookies)
    if not jwt_payload:
        return ErrorResponse(code=401, message="Unauthorized - missing or invalid token")

    # Rate limit key standardized to auth:mfa:setup
    if not check_rate_limit(headers, "auth:mfa:setup", max_attempts=10, window_minutes=5):
        return ErrorResponse(code=429, message="rate_limited")

    body = body or {}
    profile_name = body.get("profile_name", "default")
    label = body.get("label") or jwt_payload.sub
    issuer = body.get("issuer", "SimpleCloudKit")

    # If a secret already exists and we aren't forcing reset, reuse it (idempotent)
    try:
        existing = ProfileActions.get(client=jwt_payload.cnm, user_id=jwt_payload.sub, profile_name=profile_name)
    except Exception:
        existing = None  # treat as new

    force_reset = bool(body.get("force_reset"))
    if existing and existing.totp_secret and not force_reset:
        secret = existing.totp_secret
        provisioning_uri = _build_otpauth_uri(secret, account_name=label, issuer=issuer)
        # Do not return recovery codes again (only on first generation)
        return SuccessResponse(data={"secret": secret, "provisioning_uri": provisioning_uri, "recovery_codes": []})

    # Generate TOTP secret and otpauth URI
    secret = _b32_secret_generate()
    provisioning_uri = _build_otpauth_uri(secret, account_name=label, issuer=issuer)

    # Create recovery codes; store hashes, return plaintext once
    recovery_codes_plain = _generate_recovery_codes()
    recovery_codes_hashed = _hash_codes(recovery_codes_plain)

    data = {
        "mfa_enabled": False,
        "mfa_methods": ["totp"],
        "totp_secret": secret,
        "recovery_codes": recovery_codes_hashed,
    }
    try:
        result = ProfileActions.patch(client=jwt_payload.cnm, user_id=jwt_payload.sub, profile_name=profile_name, **data)
        log.debug("Updated user profile with MFA data", details=result.model_dump())
    except Exception as e:
        log.error(f"Failed to update user profile with MFA data: {e}")
        return ErrorResponse(code=500, message="Failed to set up MFA", exception=e)

    return SuccessResponse(data={"secret": secret, "provisioning_uri": provisioning_uri, "recovery_codes": recovery_codes_plain})


def mfa_totp_confirm(*, cookies: dict = None, headers: dict = None, body: dict = None, **kwargs) -> Response:
    """Confirm TOTP MFA setup by validating the provided TOTP code."""
    jwt_payload, _ = get_authenticated_user(cookies=cookies)
    if not jwt_payload:
        return ErrorResponse(code=401, message="Unauthorized - missing or invalid token")

    # Rate limit key standardized to auth:mfa:confirm
    if not check_rate_limit(headers, "auth:mfa:confirm", max_attempts=10, window_minutes=5):
        return ErrorResponse(code=429, message="rate_limited")

    body = body or {}
    profile_name = body.get("profile_name", "default")
    code = (body.get("code") or "").strip()
    if not code:
        return ErrorResponse(code=400, message="TOTP code is required")

    try:
        profile = ProfileActions.get(client=jwt_payload.cnm, user_id=jwt_payload.sub, profile_name=profile_name)
    except Exception as e:
        log.error(f"Failed to retrieve profile for MFA confirm: {e}")
        return ErrorResponse(code=404, message="profile_not_found")

    if not profile.totp_secret:
        return ErrorResponse(code=400, message="totp_not_initialized")

    if not _totp_verify(profile.totp_secret, code):
        return ErrorResponse(code=401, message="invalid_code")

    try:
        result = ProfileActions.patch(
            client=jwt_payload.cnm, user_id=jwt_payload.sub, profile_name=profile_name, **{"mfa_enabled": True}
        )
        log.debug("Updated user profile to enable MFA", details=result.model_dump())
    except Exception as e:
        log.error(f"Failed to update user profile to enable MFA: {e}")
        return ErrorResponse(code=500, message="Failed to confirm MFA setup", exception=e)

    return SuccessResponse(message="MFA setup confirmed successfully")


def mfa_verify(*, cookies: dict = None, headers: dict = None, body: dict = None, **kwargs) -> Response:
    """Verify TOTP MFA code during login.

    Route:
        POST /auth/v1/mfa/verify

    Request:
        JSON: {
            "code": string               // Required - TOTP code from the authenticator app
        }

    Behavior:
        - Requires valid Authorization: Bearer token (session token)
        - Validates the provided TOTP code against the stored secret
        - Issues a new access token if the code is valid

    Response:
        Success (200):
          {
            "data": {
                "token": "<access_jwt>",          // JWT access token
                "expires_in": 3600,               // Token lifetime in seconds (1 hour)
                "token_type": "Bearer"            // Token type for Authorization header
            },
             "code": 200
    """

    jwt_payload, _ = get_authenticated_user(cookies=cookies)

    mfa_payload, _ = get_mfa_token_user(cookies)

    if not jwt_payload and not mfa_payload:
        return ErrorResponse(code=401, message="Unauthorized - missing or invalid token")

    # Rate limit key standardized to auth:mfa:verify
    if not check_rate_limit(headers, "auth:mfa:verify", max_attempts=10, window_minutes=1):
        return ErrorResponse(code=429, message="rate_limited")

    if mfa_payload:
        client_id = mfa_payload.cid
        client = mfa_payload.cnm
        user_id = mfa_payload.sub
    else:
        client_id = jwt_payload.cid
        client = jwt_payload.cnm
        user_id = jwt_payload.sub

    body = body or {}
    profile_name = body.get("profile_name", "default")
    code = (body.get("code") or "").strip()
    if not code:
        return ErrorResponse(code=400, message="TOTP code is required")

    try:
        profile = ProfileActions.get(client=client, user_id=user_id, profile_name=profile_name)
    except Exception as e:
        log.error(f"Failed to load profile for MFA verify: {e}")
        return ErrorResponse(code=404, message="profile_not_found")

    verified = False
    if profile.totp_secret and _totp_verify(profile.totp_secret, code):
        verified = True

    if not verified and profile.recovery_codes:
        for hashed in list(profile.recovery_codes):
            try:
                if bcrypt.checkpw(code.encode("utf-8"), hashed.encode("utf-8")):
                    verified = True
                    remaining = [h for h in profile.recovery_codes if h != hashed]
                    ProfileActions.patch(client=client, user_id=user_id, profile_name=profile_name, **{"recovery_codes": remaining})
                    break
            except Exception:
                continue

    if not verified:
        return ErrorResponse(code=401, message="invalid_code")

    if not profile.mfa_enabled:
        try:
            ProfileActions.patch(client=client, user_id=user_id, profile_name=profile_name, **{"mfa_enabled": True})
        except Exception:
            pass

    if mfa_payload and mfa_payload.typ == "mfa_pending":
        return emit_session_cookie(SuccessResponse(), client_id, client, user_id, mfa=True)

    return SuccessResponse(message="mfa_verified")


def mfa_status(*, cookies: dict = None, headers: dict = None, query_params: dict = None, **kwargs) -> Response:
    """Get MFA status for the authenticated user.

    Route:
        GET /auth/v1/mfa/status

    Behavior:
        - Requires valid Authorization: Bearer token
        - Returns the MFA status (enabled/disabled) for the user

    Response:
        Success (200):
          {
            "data": {
                "mfa_enabled": boolean          // True if MFA is enabled, False otherwise
            },
             "code": 200
    """
    jwt_payload, _ = get_authenticated_user(cookies=cookies)
    if not jwt_payload:
        return ErrorResponse(code=401, message="Unauthorized - missing or invalid token")

    query_params = query_params or {}
    profile_name = query_params.get("profile_name", "default")

    try:
        profile = ProfileActions.get(client=jwt_payload.cnm, user_id=jwt_payload.sub, profile_name=profile_name)
        mfa_enabled = bool(profile.mfa_enabled)
        methods = profile.mfa_methods or []
        return SuccessResponse(data={"mfa_enabled": mfa_enabled, "mfa_methods": methods})
    except Exception as e:
        log.error(f"Failed to retrieve user profile for MFA status: {e}")
        return ErrorResponse(code=500, message="Failed to retrieve MFA status", exception=e)


def get_permissions(*, cookies: dict = None, headers: dict = None, query_params: dict = None, **kwargs) -> Response:
    """
    Docstring for get_permissions
    Provide /auth/v1/permissions/explain?resource=portfolio:billing&action=write returning: { "allowed": true, "matched_grant": {...}, "implied_by_role": "portfolio_editor", "denied_overrides": [] }

    .. code-block:: json
        {
          "status": "success",
          "code": 200,
          "data": {
            "allowed": true,
            "resource": "portfolio:core-automation",
            "action": "write",
            "matched_effective": "portfolio:core-automation:write",
            "evaluation": {
              "grants_checked": 7,
              "denies_checked": 2,
              "matched_grant": {
                "resource_type": "portfolio",
                "resource_id": "*",
                "actions": ["admin"],
                "effect": "allow"
              },
              "matched_deny": null,
              "implied_by": "tenant_admin",
              "implications": ["write", "read"],
              "decision": "allow"
            },
          },
        }

    """

    jwt_payload, _ = get_authenticated_user(cookies=cookies)
    if not jwt_payload:
        return ErrorResponse(code=401, message="Unauthorized - missing or invalid token")

    resource = query_params.get("resource")
    action = query_params.get("action")
    profile_name = query_params.get("profile_name", "default")

    try:
        profile = ProfileActions.get(client=jwt_payload.cnm, user_id=jwt_payload.sub, profile_name=profile_name)

        explaination = _explain_permissions(profile.permissions, resource, action)

        return SuccessResponse(data=explaination)
    except Exception as e:
        log.error(f"Failed to retrieve profile for permissions: {e}")
        return ErrorResponse(code=404, message="profile_not_found")


def _explain_permissions(permissions: list[str], resource: str, action: str) -> dict:
    """
    Explain how a set of permissions allows or denies a specific action on a resource.

    .. code-block:: python
      _explain_permissions = {
        "allowed": True,
        "resource": "portfolio:core-automation",
        "action": "write",
        "matched_effective": "portfolio:core-automation:write",
        "evaluation": {
          "grants_checked": 7,
          "denies_checked": 2,
          "matched_grant": {
            "resource_type": "portfolio",
            "resource_id": "*",
            "actions": ["admin"],
            "effect": "allow"
          },
          "matched_deny": None,
          "implied_by": "tenant_admin",
          "implications": ["write", "read"],
          "decision": "allow"
      }
    """

    allowed = False
    matched_grant = None
    implied_by_role = None
    denied_overrides = []

    # Define role-based permission implications
    role_implications = {
        "admin": ["*:*"],
        "portfolio_admin": [f"portfolio:{action}" for action in ["read", "write", "delete"]],
        "portfolio_editor": [f"portfolio:{action}" for action in ["read", "write"]],
        "portfolio_viewer": [f"portfolio:read"],
        "user_admin": [f"user:{action}" for action in ["create", "read", "update", "delete"]],
        "user_viewer": [f"user:read"],
    }

    # Check direct permissions first
    for perm in permissions:
        if perm == "*:*":
            allowed = True
            matched_grant = perm
            break
        if perm == f"{resource}:{action}" or perm == f"{resource}:*":
            allowed = True
            matched_grant = perm
            break
        if perm.startswith("-"):
            denied_overrides.append(perm[1:])
            if perm[1:] == f"{resource}:{action}" or perm[1:] == f"{resource}:*":
                allowed = False
                matched_grant = perm
                break

    # If not directly allowed, check role implications
    if not allowed:
        for role, implied_perms in role_implications.items():
            for implied in implied_perms:
                if implied == "*:*" or implied == f"{resource}:{action}" or implied == f"{resource}:*":
                    allowed = True
                    matched_grant = implied
                    implied_by_role = role
                    break
            if allowed:
                break

    return {
        "allowed": allowed,
        "matched_grant": matched_grant,
        "implied_by_role": implied_by_role,
        "denied_overrides": denied_overrides,
    }


auth_direct_endpoints: dict[str, RouteEndpoint] = {
    "POST:/auth/v1/signup": RouteEndpoint(
        user_signup,
        permissions=["user:signup"],
        allow_anonymous=True,
        client_isolation=False,
    ),
    "GET:/auth/v1/me": RouteEndpoint(
        get_user_profile,
        permissions=["user:read"],
        required_token_type="session",
        client_isolation=False,
    ),
    "PUT:/auth/v1/me": RouteEndpoint(
        update_user_profile,
        permissions=["user:update"],
        required_token_type="session",
        client_isolation=False,
    ),
    "PATCH:/auth/v1/me": RouteEndpoint(
        update_user_profile,
        permissions=["user:update"],
        required_token_type="session",
        client_isolation=False,
    ),
    "POST:/auth/v1/me": RouteEndpoint(
        create_user_profile,
        permissions=["user:update"],
        required_token_type="session",
        client_isolation=False,
    ),
    "DELETE:/auth/v1/me": RouteEndpoint(
        delete_user_profile,
        permissions=["user:delete"],
        required_token_type="session",
        client_isolation=False,
    ),
    "POST:/auth/v1/login": RouteEndpoint(
        user_login,
        permissions=["user:login"],
        allow_anonymous=True,
        client_isolation=False,
    ),
    "POST:/auth/v1/refresh": RouteEndpoint(
        refresh_session_cookie,
        permissions=["user:refresh"],
        allow_anonymous=True,
        client_isolation=False,
    ),
    "POST:/auth/v1/forgot": RouteEndpoint(
        forgot_password,
        permissions=["user:forgot_password"],
        allow_anonymous=True,
        client_isolation=False,
    ),
    "POST:/auth/v1/verify-secret": RouteEndpoint(
        verify_secret,
        permissions=["user:verify_secret"],
        allow_anonymous=True,
        client_isolation=False,
    ),
    "PUT:/auth/v1/password": RouteEndpoint(
        set_new_password,
        permissions=["user:set_new_password"],
        allow_anonymous=True,
        client_isolation=False,
    ),
    "POST:/auth/v1/logout": RouteEndpoint(
        user_logout,
        permissions=["user:logout"],
        allow_anonymous=True,
        client_isolation=False,
    ),
    "GET:/auth/v1/organizations": RouteEndpoint(
        list_organizations,
        permissions=["org:list"],
        required_token_type="session",
        client_isolation=False,
    ),
    "GET:/auth/v1/verify": RouteEndpoint(
        verify_email_address,
        permissions=["user:verify_email"],
        allow_anonymous=True,
        client_isolation=False,
    ),
    "POST:/auth/v1/verification/resend": RouteEndpoint(
        resend_verification_email,
        permissions=["user:resend_verification"],
        allow_anonymous=True,
        client_isolation=False,
    ),
    # MFA endpoints are defined in core_api/oauth/auth_mfa.py
    "POST:/auth/v1/mfa/totp/setup": RouteEndpoint(
        mfa_totp_setup,
        permissions=["mfa:setup"],
        required_token_type="session",
        client_isolation=False,
    ),
    "POST:/auth/v1/mfa/totp/confirm": RouteEndpoint(
        mfa_totp_confirm,
        permissions=["mfa:confirm"],
        required_token_type="session",
        client_isolation=False,
    ),
    "POST:/auth/v1/mfa/verify": RouteEndpoint(
        mfa_verify,
        permissions=["mfa:verify"],
        allow_anonymous=True,
        client_isolation=False,
    ),
    "GET:/auth/v1/mfa/status": RouteEndpoint(
        mfa_status,  # Implemented in auth_mfa.py
        permissions=["mfa:status"],
        required_token_type="session",
        client_isolation=False,
    ),
    "GET:/auth/v1/profiles": RouteEndpoint(
        list_user_profiles,
        permissions=["user:profile:list"],
        required_token_type="session",
        client_isolation=False,
    ),
    "POST:/auth/v1/profiles": RouteEndpoint(
        create_user_profile,
        permissions=["user:profile:create"],
        required_token_type="session",
        client_isolation=False,
    ),
    "GET:/auth/v1/profiles/{profile_name}": RouteEndpoint(
        get_user_profile,
        permissions=["user:profile:read"],
        required_token_type="session",
        client_isolation=False,
    ),
    "PATCH:/auth/v1/profiles/{profile_name}": RouteEndpoint(
        update_user_profile,
        permissions=["user:profile:update"],
        required_token_type="session",
        client_isolation=False,
    ),
    "DELETE:/auth/v1/profiles/{profile_name}": RouteEndpoint(
        delete_user_profile,
        permissions=["user:profile:delete"],
        required_token_type="session",
        client_isolation=False,
    ),
    "GET:/auth/v1/permissions/explain": RouteEndpoint(
        get_permissions,
        permissions=["user:permissions:explain"],
        required_token_type="session",
        client_isolation=False,
    ),
}
