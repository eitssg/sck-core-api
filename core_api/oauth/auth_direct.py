from typing import Optional
from datetime import datetime, timezone
import random
import os
import bcrypt
from datetime import timedelta
from core_db.registry import ClientFact
import httpx

import jwt

import core_logging as log

from core_db.response import ErrorResponse, Response, SuccessResponse
from core_db.profile.actions import ProfileActions
from core_db.profile.model import UserProfile

from core_api.request import RouteEndpoint

from .constants import JWT_SECRET_KEY, JWT_ALGORITHM, SESSION_JWT_MINUTES
from .tools import (
    get_client_ip,
    get_authenticated_user,
    encrypt_aws_credentials,
    check_rate_limit,
    encrypt_credentials,
    create_basic_session_jwt,
    get_oauth_app_info,
    is_password_compliant,
)


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


def oauth_signup(*, cookies: dict = None, headers: dict = None, body: dict = None, **kwargs) -> Response:
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

    if not check_rate_limit(headers, "oauth_signup", max_attempts=10, window_minutes=15):
        return Response(status="error", code=429, message="rate_limited")

    # Common input
    first_name = body.get("first_name", "")
    last_name = body.get("last_name", "")
    password = body.get("password", "")
    client_id = body.get("client_id", "")
    aws_access_key = body.get("aws_access_key", "")
    aws_secret_key = body.get("aws_secret_key", "")

    if not client_id:
        return Response(status="error", code=400, message="client_id is required")

    app_info: ClientFact = get_oauth_app_info(client_id=client_id)
    if not app_info:
        return Response(status="error", code=400, message="invalid_client")

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
            return Response(status="error", code=400, message="Email and password are required")

        # Validate password strength
        if not is_password_compliant(password):
            return Response(status="error", code=400, message="password_does_not_meet_requirements")

        captcha_token = body.get("captcha_token")

        ok = _verify_captcha(captcha_token, get_client_ip(headers))
        if not ok:
            return Response(status="error", code=400, message="Invalid captcha")

    # During sign-up, there may or may not be aws credentials.
    # If there are not credentials, we'll safe the password, and we'll add
    # AWS credentials to the user profile at a later time.
    try:
        encrypted_credentials = encrypt_credentials(aws_access_key, aws_secret_key, password)
    except Exception as e:
        log.warning(f"Failed to encrypt credentials (such as bad password validation): {e}")
        return ErrorResponse(status="error", code=500, message="Failed to encrypt credentials", exception=e)

    try:
        # Load in UserProfile for validation with Pydantic (includes email validation)

        data = UserProfile(
            user_id=user_id,
            profile_name="default",
            email=email,
            first_name=first_name,
            last_name=last_name,
            credentials=encrypted_credentials,
        ).model_dump()
    except Exception as e:
        # Pydantic validation errors (including invalid email) are client errors
        error_msg = str(e)
        if "email" in error_msg.lower():
            error_msg = "Invalid email format"

        return Response(status="error", code=400, message=error_msg)

    exists = _profile_exists(user_id=user_id, profile_name="default")

    try:

        if ident:

            # Authenticated via SSO: allow create-or-update
            if exists:
                ProfileActions.patch(client=client, **data)
            else:
                log.debug(f"Creating new profile for SSO user: {user_id}")
                ProfileActions.create(client=client, **data)

        else:

            # Signup via email/password: creation only; reject if exists
            if exists:
                return Response(status="error", code=409, message=f"User '{user_id}' already exists")

            log.debug(f"Creating new profile for email/password user: {user_id}")
            response: SuccessResponse = ProfileActions.create(client=client, **data)
            if not response:
                return Response(status="error", code=500, message="Profile creation failed")
            if response.code != 200:
                return Response(status="error", code=response.code, message="Profile creation failed")

    except Exception as e:
        return ErrorResponse(status="error", code=500, message="Profile update failed", exception=e)

    try:

        # Create session JWT with proper parameter order
        minutes = int(SESSION_JWT_MINUTES)
        jwt_token = create_basic_session_jwt(client_id, client, user_id, minutes)

        # Return a short-lived session token (no cookies) so SPA can call /authorize → /token
        return Response(
            status="ok",
            code=201,
            data={
                "user_id": user_id,
                "profile_name": "default",
                "token": jwt_token,
                "token_type": "Bearer",
            },
        )

    except Exception as e:
        return ErrorResponse(status="error", code=500, message="Issuing session failed", exception=e)


def update_user(*, cookies: dict = None, headers: dict = None, body: dict = None, **kwargs) -> Response:
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
    jwt_payload, _ = get_authenticated_user(cookies, headers)
    if jwt_payload is None:
        return Response(status="error", code=401, message="Unauthorized")

    if not check_rate_limit(headers, "update_user", max_attempts=20, window_minutes=1):
        log.warning(f"Rate limit exceeded for user {jwt_payload.sub} on /v1/users/me")
        return Response(status="error", code=429, message="rate_limited")

    log.debug(
        f"Updating user {jwt_payload.sub} from client '{jwt_payload.cid}' for '{jwt_payload.cnm}' with data:",
        details=dict(body),
    )

    # Extract update fields
    aws_access_key = body.get("aws_access_key")
    aws_secret_key = body.get("aws_secret_key")
    first_name = body.get("first_name")
    last_name = body.get("last_name")
    email = body.get("email")

    # Get current profile
    try:
        response: SuccessResponse = ProfileActions.get(
            client=jwt_payload.cnm,
            user_id=jwt_payload.sub,
            profile_name="default",
        )
        current_data = UserProfile(**response.data)
    except Exception as e:
        log.error(f"Failed to retrieve user profile for {jwt_payload.sub}: {e}")
        return ErrorResponse(status="error", code=500, message="Failed to retrieve user profile", exception=e)

    # Prepare update data (only include fields that are provided)
    update_data = {"user_id": jwt_payload.sub, "profile_name": "default"}

    # Update basic profile fields if provided
    if first_name is not None:
        update_data["first_name"] = first_name
    if last_name is not None:
        update_data["last_name"] = last_name
    if email is not None:
        update_data["email"] = email

    # Handle AWS credentials update
    if aws_access_key and aws_secret_key:
        try:
            # Get existing credentials envelope or create new one
            existing_credentials = current_data.credentials
            if existing_credentials is None:
                existing_credentials = {"CreatedAt": datetime.now(timezone.utc).isoformat()}

            existing_credentials["UpdatedAt"] = datetime.now(timezone.utc).isoformat()

            new_aws_creds = encrypt_aws_credentials(aws_access_key, aws_secret_key)
            existing_credentials.update(new_aws_creds)

            # Preserve password hash if it exists
            update_data["Credentials"] = existing_credentials

            update_data["Identity"] = _get_identity(existing_credentials)

        except Exception as e:
            log.error(f"Failed to encrypt AWS credentials for {jwt_payload.sub}: {e}")
            return ErrorResponse(status="error", code=500, message="Failed to encrypt AWS credentials", exception=e)

    # Perform the update
    try:
        ProfileActions.patch(client=jwt_payload.cnm, **update_data)

        response_data = {
            "message": "User updated successfully",
            "updated_fields": list(update_data.keys()),
        }

        # Include AWS credential status in response
        if "Credentials" in update_data:
            response_data["has_aws_credentials"] = True

        return Response(status="ok", code=200, data=response_data)

    except Exception as e:
        log.error(f"Failed to update user profile for {jwt_payload.sub}: {e}")
        return ErrorResponse(status="error", code=500, message="Failed to update user profile", exception=e)


def _get_identity(aws_credentials: dict) -> dict:
    """Extract AWS identity information from encrypted credentials."""
    import boto3

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
        password = body.get("password")
        if not user_id or not password:
            return Response(status="error", code=400, message="email_and_password_required")

        client_id = body.get("client_id")
        if not client_id:
            return Response(status="error", code=400, message="The field client_id is required")

        if not check_rate_limit(headers, "oauth_login", max_attempts=10, window_minutes=15):
            log.warning(f"Rate limit exceeded for user {user_id} on /auth/v1/login")
            return Response(status="error", code=429, message="rate_limited")

        app_info: ClientFact = get_oauth_app_info(client_id)
        if not app_info:
            return Response(status="error", code=400, message="invalid_client")

        client = app_info.client
        returnTo = body.get("returnTo")

        # Get user profile and validate password
        try:
            response: SuccessResponse = ProfileActions.get(
                client=client,
                user_id=user_id,
                profile_name="default",
            )
            profile_data = UserProfile(**response.data)
        except Exception as e:
            log.debug(f"Profile not found for user {user_id}: {e}")
            return Response(status="error", code=401, message="Authorization Failed")

        # Check if user has a password (some SSO users might not)
        credentials = profile_data.credentials or {}
        stored_hash = credentials.get("Password") or credentials.get("password")
        if not stored_hash:
            log.debug(f"No password found for user {user_id}")
            return Response(status="error", code=401, message="Authorization Failed")

        # Validate password against stored hash
        if not bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
            log.debug(f"Password validation failed for user {user_id}")
            return Response(status="error", code=401, message="Authorization Failed")

        minutes = int(SESSION_JWT_MINUTES)

        # Create session JWT with NO AWS credentials - just user identity
        session_jwt = create_basic_session_jwt(client_id, client, user_id, minutes)
        seconds = int(timedelta(minutes=minutes).total_seconds())

        resp_data = {
            "token": session_jwt,
            "expires_in": seconds,
            "token_type": "Bearer",
        }
        if returnTo:
            resp_data["returnTo"] = returnTo

        return Response(status="ok", code=200, data=resp_data)

    except Exception as e:
        log.error(f"Login error for {user_id}: {e}")
        return ErrorResponse(status="error", code=500, message="Authentication processing error", exception=e)


auth_direct_endpoints: dict[str, RouteEndpoint] = {
    "POST:/auth/v1/signup": RouteEndpoint(oauth_signup, permissions=["user:signup"]),
    "PUT:/auth/v1/users/me": RouteEndpoint(update_user, permissions=["user:update"]),
    "POST:/auth/v1/login": RouteEndpoint(user_login, permissions=["user:login"]),
}
