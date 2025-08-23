from typing import Optional
import os
from datetime import timedelta
import httpx
from fastapi import Request, APIRouter
from fastapi.responses import JSONResponse

from botocore.exceptions import BotoCoreError, ClientError

import jwt

import core_logging as log

from core_db.response import SuccessResponse
from core_db.profile.actions import ProfileActions
from core_db.profile.model import UserProfile

from .tools import check_rate_limit, encrypt_creds, get_user_access_key, encrypt_credentials, create_session_jwt

from .constants import JWT_SECRET_KEY, JWT_ALGORITHM, CRED_ENC_KEY_B64

user_router = APIRouter()


def _read_identity_cookie(cookies) -> Optional[dict]:
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
        ProfileActions.get(user_id=user_id, profile_name=profile_name)
        return True
    except Exception:
        return False


async def _verify_captcha(token: Optional[str], ip: Optional[str]) -> bool:
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
        async with httpx.AsyncClient(timeout=10) as client:
            if ts_secret:
                r = await client.post(
                    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                    data={"secret": ts_secret, "response": token, "remoteip": ip or ""},
                )
                data = r.json()
                return bool(data.get("success"))
            else:
                r = await client.post(
                    "https://www.google.com/recaptcha/api/siteverify",
                    data={"secret": rc_secret, "response": token, "remoteip": ip or ""},
                )
                data = r.json()
                return bool(data.get("success"))
    except Exception as e:
        log.warning(f"CAPTCHA verification failed: {e}")
        return False


@user_router.post("/v1/signup")
async def oauth_signup(request: Request):
    """Create or update the default profile, then return a session token.

    Route:
        POST /auth/v1/signup

    Modes:
        - SSO (GitHub/Apple): requires sck_identity cookie; body: { access_key, secret_key, first_name?, last_name? }.
          Encrypts with server key (JWE), creates or updates profile for authenticated user.
        - Email/password: body: { email, password, access_key, access_secret, first_name?, last_name? }.
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
    try:
        body = await request.json()
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": f"Invalid JSON body: {str(e)}", "code": 400})

    client_ip = request.client.host if request.client else None

    # Common input
    aws_access_key = body.get("access_key")
    aws_secret_key = body.get("access_secret") or body.get("secret_key")
    first_name = body.get("first_name", "")
    last_name = body.get("last_name", "")

    if not aws_access_key or not aws_secret_key:
        return JSONResponse(status_code=400, content={"error": "Access Key and Access Secret are required", "code": 400})

    credentials = {"AccessKeyId": aws_access_key, "SecretAccessKey": aws_secret_key}

    # Determine mode
    ident = _read_identity_cookie(request.cookies)
    if ident:
        # SSO path: use identity cookie for user_id; encrypt with server key
        if not check_rate_limit(request, "oauth_signup", max_attempts=10, window_minutes=15):
            return JSONResponse(status_code=429, content={"error": "rate_limited", "code": 429})
        user_id = ident.get("sub")
        enc_blob = encrypt_creds(credentials)
        next_url = ident.get("next") or "/"
    else:
        # Email/password path
        user_id = body.get("email")
        password = body.get("password")
        captcha_token = body.get("captcha_token")
        if not check_rate_limit(request, "oauth_signup", max_attempts=10, window_minutes=15):
            return JSONResponse(status_code=429, content={"error": "rate_limited", "code": 429})
        ok = await _verify_captcha(captcha_token, client_ip)
        if not ok:
            return JSONResponse(status_code=400, content={"error": "Invalid captcha", "code": 400})
        if not user_id or not password:
            return JSONResponse(status_code=400, content={"error": "Email and password are required", "code": 400})
        enc_blob = encrypt_credentials(credentials, password)
        next_url = "/"

    try:
        # Persist profile with takeover protection / Load in UserProfile for validation with pydantic
        data = UserProfile(
            **{
                "user_id": user_id,
                "profile_name": "default",
                "email": user_id,
                "first_name": first_name,
                "last_name": last_name,
                "credentials": enc_blob,
            }
        ).model_dump()
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Profile data validation failed: {str(e)}", "code": 500})

    exists = _profile_exists(user_id=user_id, profile_name="default")

    try:

        if ident:

            # Authenticated via SSO: allow create-or-update
            if exists:
                ProfileActions.patch(**data)
            else:
                log.debug("Creating new profile for SSO user", details=data)
                ProfileActions.create(**data)

        else:

            # Signup via email/password: creation only; reject if exists
            if exists:
                return JSONResponse(status_code=409, content={"error": f"User '{user_id}' already exists", "code": 409})

            log.debug("Creating new profile for email/password user", details=data)
            response: SuccessResponse = ProfileActions.create(**data)
            if not response:
                return JSONResponse(status_code=500, content={"error": "Profile creation failed", "code": 500})
            if response.code != 200:
                return JSONResponse(status_code=response.code, content={"error": "Profile creation failed", "code": response.code})

    except Exception:
        return JSONResponse(status_code=500, content={"error": "Profile update failed", "code": 500})

    try:

        # Return a short-lived session token (no cookies) so SPA can call /authorize → /token
        cred_jwe = encrypt_creds(credentials)
        session_jwt = create_session_jwt(user_id, cred_jwe)

        payload = {
            "code": 201,
            "data": {
                "user_id": user_id,
                "profile_name": "default",
                "token": session_jwt,
                "token_type": "Bearer",
            },
        }
        return JSONResponse(status_code=201, content=payload)

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Issuing session failed: {str(e)}", "code": 500})


@user_router.post("/v1/login")
async def oauth_login(request: Request):
    """Authenticate with email/password and mint a short-lived session JWT.

    Route:
        POST /auth/v1/login

    Request:
        JSON: { "email": string, "password": string }

    Behavior:
        - Loads the user's default profile and decrypts stored AWS credentials using the provided password.
        - Returns a session JWT (typ=session) that embeds a JWE of the long-term keys (cred_jwe).
        - No cookies are set; clients must send this token in Authorization: Bearer.

    Response:
        200 JSON:
          {
            "data": { "token": "<session_jwt>", "expires_in": <seconds>, "token_type": "Bearer" },
            "code": 200
          }
    """

    try:
        body = await request.json()
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": f"Invalid JSON body: {str(e)}", "code": 400})

    try:
        user_id = body.get("email")
        password = body.get("password")
        if not user_id or not password:
            return JSONResponse(status_code=400, content={"error": "email_and_password_required", "code": 400})

        if not check_rate_limit(request, "oauth_login", max_attempts=10, window_minutes=15):
            log.warning(f"Rate limit exceeded for user {user_id} on /auth/v1/login")
            return JSONResponse(status_code=429, content={"error": "rate_limited", "code": 429})

        access_key, access_secret = get_user_access_key(user_id, password)
        if not access_key or not access_secret:
            return JSONResponse(status_code=401, content={"Authorization": "Authorization Failed.", "code": 401})

        # New: return a short-lived session token that carries a JWE of the raw keys (not STS session)
        cred_jwe = encrypt_creds({"AccessKeyId": access_key, "SecretAccessKey": access_secret})
        session_jwt = create_session_jwt(user_id, cred_jwe)

        resp = JSONResponse(
            status_code=200,
            content={
                "data": {
                    "token": session_jwt,
                    "expires_in": int(timedelta(minutes=int(os.getenv("SESSION_JWT_MINUTES", "30"))).total_seconds()),
                    "token_type": "Bearer",
                },
                "code": 200,
            },
        )
        return resp
    except (BotoCoreError, ClientError) as e:
        error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "Unknown")
        if error_code in ["InvalidUserID.NotFound", "SignatureDoesNotMatch"]:
            return JSONResponse(status_code=401, content={"error": "Invalid AWS credentials", "code": 401})
        elif error_code == "TokenRefreshRequired":
            return JSONResponse(status_code=401, content={"error": "AWS credentials require MFA token", "code": 401})
        else:
            return JSONResponse(status_code=503, content={"error": "AWS authentication service error", "code": 503})
    except Exception:
        return JSONResponse(status_code=500, content={"error": "Authentication processing error", "code": 500})
