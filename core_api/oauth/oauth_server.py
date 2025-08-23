import hashlib
from typing import Set, Optional, Tuple
import uuid
import boto3
from botocore.exceptions import ClientError

import base64
from urllib.parse import urlencode, urlparse, parse_qs
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse

import jwt

import core_logging as log

from core_db.oauth.actions import AuthActions
from core_db.exceptions import BadRequestException, ConflictException, UnknownException
from core_db.response import SuccessResponse
from core_db.registry.client.actions import ClientActions

from .tools import check_rate_limit, decrypt_creds, get_user_access_key, encrypt_creds

from .constants import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_EXPIRATION_HOURS,
    REFRESH_MIN_INTERVAL_SECONDS,
    ALLOWED_SCOPES,
    ACCESS_REFRESH_WINDOW_SECONDS,
    CLIENT_ID_DB,
)

oauth_router = APIRouter()


def _get_credentials(client: str, subject: str) -> dict:
    """Retrieve OAuth2 credentials for a given client and subject."""
    try:
        AwsAccessKey, AwsSecretKey = get_user_access_key(subject)
        sts_client = boto3.client("sts", aws_access_key_id=AwsAccessKey, aws_secret_access_key=AwsSecretKey)
        response = sts_client.get_session_token()
        if response and "Credentials" in response:
            creds = response["Credentials"]
            return {
                "AccessKeyId": creds["AccessKeyId"],
                "SecretAccessKey": creds["SecretAccessKey"],
                "SessionToken": creds["SessionToken"],
                "Expiration": creds["Expiration"],
            }
    except Exception as e:
        log.error(f"Failed to get credentials for client {client} and subject {subject}: {e}")
        return {}


def _mint_access_token(ak: str, sk: str, subject: str) -> str:
    """Mint a new access token with encrypted STS credentials."""
    # Get temporary STS credentials
    sts_creds = _get_credentials("core", subject)  # client param not used in your implementation
    if not sts_creds:
        raise RuntimeError("Failed to obtain STS credentials")

    # Encrypt the STS credentials (don't store plaintext in JWT)
    enc_credentials = encrypt_creds(sts_creds)

    now_utc = datetime.now(timezone.utc)
    exp_time_utc = now_utc + timedelta(hours=JWT_EXPIRATION_HOURS)

    payload = {
        "sub": subject,
        "iat": int(now_utc.timestamp()),
        "exp": int(exp_time_utc.timestamp()),
        "iss": "sck-core-api",
        "jti": f"sts-{uuid.uuid4().hex}",
        "enc_credentials": enc_credentials,  # Encrypted STS session
        "original_access_key": f"{ak[:8]}****",  # Masked for debugging
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)  # Use your JWT secret, not AK
    return token


def _mint_refresh_token(ak: str, sk: str, subject: str) -> str:
    """Mint a new refresh token."""
    payload = {
        "sub": subject,
        "iat": datetime.now(tz=timezone.utc),
        "exp": datetime.now(tz=timezone.utc) + timedelta(seconds=ACCESS_REFRESH_WINDOW_SECONDS),
        "typ": "refresh",
        "client_id": ak,
    }
    token = jwt.encode(payload, ak, algorithm=JWT_ALGORITHM)
    return token


def _pkce_calc_challenge(verifier: str, method: str = "S256") -> str:
    """Compute PKCE code_challenge from code_verifier."""
    m = (method or "S256").upper()
    if m == "PLAIN":
        return verifier
    if m != "S256":
        raise ValueError("unsupported code_challenge_method")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def _get_oauth_app_info(client_id: str) -> dict | None:
    """Return client registration for a given client_id, or None if unregistered.

    Args:
        client_id (str): OAuth client identifier.

    Returns:
        Optional[dict]: Registration info with redirect_uri if known; else None.
    """
    try:
        response = ClientActions.get(client=client_id)
        return response
    except Exception as e:
        log.error(f"Failed to get OAuth app info for client_id {client_id}: {e}")
        return None


def _parse_basic_auth(auth_header: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Parse HTTP Basic client authentication.

    Args:
        auth_header (Optional[str]): Authorization header value.

    Returns:
        Tuple[Optional[str], Optional[str]]: (client_id, client_secret) or (None, None).
    """
    if not auth_header or not auth_header.startswith("Basic "):
        return None, None
    try:
        b64 = auth_header.split(" ", 1)[1].strip()
        raw = base64.b64decode(b64).decode("utf-8")
        client_id, client_secret = raw.split(":", 1)
        return client_id, client_secret
    except Exception:
        return None, None


def _get_client_allowed_scopes(client_id: str) -> Set[str]:
    """Return the set of scopes the registered client is allowed to request.

    Args:
        client_id (str): OAuth client identifier.

    Returns:
        Set[str]: Allowed scopes for the client.
    """
    if client_id == "coreui":
        return ALLOWED_SCOPES
    return set()


def _get_user_allowed_scopes(user_id: str) -> Set[str]:
    """Return the set of scopes the user is allowed to grant.

    Args:
        user_id (str): Authenticated subject identifier.

    Returns:
        Set[str]: Allowed scopes for the user.
    """
    return {"registry-clients:read", "registry-clients:write"}


def _parse_scopes(scope_param: Optional[str]) -> list[str]:
    """Parse a scope string into a list and filter to supported scopes.

    Args:
        scope_param (Optional[str]): Space- or comma-delimited scope string.

    Returns:
        list[str]: Valid scopes requested.
    """
    if not scope_param:
        return []
    parts = [s.strip() for s in scope_param.replace(",", " ").split(" ") if s.strip()]
    return [s for s in parts if s in ALLOWED_SCOPES]


def _grant_scopes(client_id: str, user_id: str, requested: list[str]) -> list[str]:
    """Compute granted scopes as the intersection of requested, client-allowed, and user-allowed.

    Args:
        client_id (str): OAuth client identifier.
        user_id (str): Authenticated subject identifier.
        requested (list[str]): Scopes requested by the client.

    Returns:
        list[str]: Granted scopes.
    """
    client_allowed = _get_client_allowed_scopes(client_id)
    user_allowed = _get_user_allowed_scopes(user_id)
    return list((set(requested) & client_allowed) & user_allowed)


def validate_requested_scopes(client_id: str, requested: str, user_id: str) -> str:
    """Return intersection of client allowed ∩ user permissions ∩ requested."""
    client_scopes = _get_client_allowed_scopes(client_id)
    user_scopes = _get_user_allowed_scopes(user_id)
    requested_scopes = set(requested.split()) if requested else set()

    if not requested_scopes:
        requested_scopes = client_scopes

    granted = client_scopes & user_scopes & requested_scopes
    return " ".join(sorted(granted))


def _validate_client_credentials(client_id: str, client_secret: str) -> Tuple[str, bool]:
    return client_id, True


def authenticate_client(request: Request, form: dict) -> tuple[str, bool]:
    """Authenticate OAuth client using standard methods."""
    # Method 1: HTTP Basic Authentication
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        client_id, client_secret = _parse_basic_auth(auth_header)
        return _validate_client_credentials(client_id, client_secret)

    # Method 2: Form parameters
    client_id = form.get("client_id")
    client_secret = form.get("client_secret")
    return _validate_client_credentials(client_id, client_secret)


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


@oauth_router.post("/v1/authorize")
async def oauth_authorize(request: Request):
    """OAuth 2.0 Authorization Code endpoint.

    Route:
        GET /auth/v1/authorize

    Query:
        client_id, response_type=code, redirect_uri, scope?, state?, code_challenge?, code_challenge_method?, login_hint?

    Behavior:
        - Requires authenticated user (typically via Authorization: Bearer <session JWT>).
        - Validates client registration and exact redirect_uri match.
        - Computes granted scopes (client ∩ user ∩ request).
        - Persists a short-lived authorization code (single-use).
        - Redirects to redirect_uri with ?code and state.
    """
    client_id = request.query_params.get("client_id")
    response_type = request.query_params.get("response_type")
    redirect_uri = request.query_params.get("redirect_uri")
    scope_param = request.query_params.get("scope")
    state = request.query_params.get("state")
    login_hint = request.query_params.get("login_hint")  # optional hint, not identity
    code_challenge = request.query_params.get("code_challenge")
    code_challenge_method = request.query_params.get("code_challenge_method") or "S256"

    if not check_rate_limit(request, "oauth_authorize", max_attempts=10, window_minutes=15):
        log.warning(f"Rate limit exceeded for client {client_id} on /auth/v1/authorize")
        return JSONResponse(status_code=429, content={"error": "rate_limited", "code": 429})

    # 1) Basic validation
    app_info = _get_oauth_app_info(client_id) if client_id else None
    if not app_info or response_type != "code" or not redirect_uri:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "Missing/invalid client_id, response_type, or redirect_uri"},
        )

    # 2) Ensure redirect_uri matches registered one (reuse app_info)
    registered_uris = app_info.get("redirect_uris", [app_info.get("redirect_uri")])  # support both formats
    if redirect_uri not in [uri for uri in registered_uris if uri]:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_redirect_uri", "error_description": "redirect_uri not registered for this client"},
        )

    # 3) Require authenticated user.
    is_auth, user_id = get_authenticated_user(request)
    if not is_auth or not user_id:

        # If you have NOT signed in to THIS server, (I'm talking aboujt the oauth server)
        # then redirect to this server's login page.

        # Only replay allowed OAuth params (and an optional sanitized login_hint).
        allowed = {
            "client_id",
            "response_type",
            "redirect_uri",
            "scope",
            "state",
            "code_challenge",
            "code_challenge_method",
            "login_hint",
        }
        params = {k: v for k, v in request.query_params.items() if k in allowed}

        # Optional: sanitize login_hint
        if "login_hint" in params:
            hint = params["login_hint"].strip()
            if len(hint) > 256 or "\n" in hint or "\r" in hint:
                params.pop("login_hint", None)
            else:
                params["login_hint"] = hint

        login_url = f"/login?returnTo=/auth/v1/authorize&{urlencode(params)}"
        return RedirectResponse(url=login_url, status_code=302)

    # 4) Process scopes (request + policy => granted)
    requested_scopes = _parse_scopes(scope_param)
    granted_scopes = _grant_scopes(client_id, user_id, requested_scopes)

    # 5) Generate and persist the code (tie it to user+client+scopes)
    code = str(uuid.uuid4())
    if not code:
        return JSONResponse(
            status_code=500,
            content={"error": "server_error", "error_description": "Failed to generate authorization code"},
        )

    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    authorization = {
        "client": "core",
        "code": code,
        "client_id": client_id,
        "user_id": user_id,
        "redirect_url": redirect_uri,
        "scope": " ".join(granted_scopes),
        "expires_at": expires_at,
        "used": False,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method if code_challenge else None,
    }
    try:
        resonse: SuccessResponse = AuthActions.create(**authorization)
    except BadRequestException as e:
        return JSONResponse(status_code=400, content={"error": str(e), "code": 400})
    except ConflictException as e:
        return JSONResponse(status_code=409, content={"error": str(e), "code": 409})
    except UnknownException as e:
        return JSONResponse(status_code=500, content={"error": str(e), "code": 500})

    # 6) Redirect back to client app with code + state
    sep = "&" if "?" in redirect_uri else "?"
    redirect_back = f"{redirect_uri}{sep}{urlencode({'code': code, 'state': state or ''})}"

    log.debug(f"Redirecting to: {redirect_back}")

    return RedirectResponse(url=redirect_back, status_code=302)


def authorization_code_grant(request: Request, form: dict):

    client_id = form.get("client_id", "").strip()

    app_info = _get_oauth_app_info(client_id)

    code = (form.get("code") or "").strip()
    redirect_uri = (form.get("redirect_uri") or "").strip()
    code_verifier = (form.get("code_verifier") or "").strip()  # PKCE (public clients)
    if not code or not redirect_uri:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "code and redirect_uri required",
            },
        )

    # Validate redirect_uri matches client registration (reuse app_info)
    registered_uris = app_info.get("redirect_uris", [app_info.get("redirect_uri")])  # support both formats
    if redirect_uri not in [uri for uri in registered_uris if uri]:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "redirect_uri not registered for this client",
            },
        )

    # Load authorization code record
    try:
        rec: SuccessResponse = AuthActions.get(client="core", code=code)
        authz = rec.data if hasattr(rec, "data") else rec
    except Exception:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": "code not found",
            },
        )

    # Validate code record
    code_client_id = authz.get("client_id")
    code_user_id = authz.get("user_id")
    code_redirect = authz.get("redirect_url")
    code_scope = authz.get("scope") or ""
    code_used = authz.get("used")
    code_expires_at = authz.get("expires_at")
    code_challenge = authz.get("code_challenge")
    code_challenge_method = (authz.get("code_challenge_method") or "S256") if code_challenge else None

    if code_client_id != client_id:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": "code client mismatch",
            },
        )

    if redirect_uri != code_redirect:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": "redirect_uri does not match code",
            },
        )

    if code_used:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": "code already used",
            },
        )

    try:
        if isinstance(code_expires_at, str):
            expires_dt = datetime.fromisoformat(code_expires_at.replace("Z", "+00:00"))
        elif isinstance(code_expires_at, datetime):
            expires_dt = code_expires_at
        else:
            expires_dt = None
        if not expires_dt or datetime.now(timezone.utc) > expires_dt.astimezone(timezone.utc):
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_grant",
                    "error_description": "code expired",
                },
            )
    except Exception:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": "invalid code expiry",
            },
        )

    # PKCE verification for public clients
    is_confidential = app_info.get("client_type", "") == "confidential"
    if not is_confidential:
        if not code_challenge:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "error_description": "pkce required for public client",
                },
            )
        if not code_verifier:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "error_description": "code_verifier required",
                },
            )
        try:
            expected = _pkce_calc_challenge(code_verifier, code_challenge_method or "S256")
        except Exception:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "error_description": "invalid code_verifier/method",
                },
            )
        if expected != code_challenge:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_grant",
                    "error_description": "pkce_verification_failed",
                },
            )

    # Extract session JWT carrying cred_jwe (Bearer or cookie)
    authz_hdr = (request.headers.get("Authorization") or "").strip()
    sess_token = authz_hdr.split(" ", 1)[1].strip() if authz_hdr.lower().startswith("bearer ") else request.cookies.get("sck_token")
    if not sess_token:
        return JSONResponse(status_code=401, content={"error": "invalid_grant", "error_description": "missing session"})
    try:
        sess = jwt.decode(
            sess_token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"verify_signature": True, "verify_exp": True, "verify_iat": True},
        )
    except jwt.InvalidTokenError:
        return JSONResponse(status_code=401, content={"error": "invalid_grant", "error_description": "invalid session"})
    if sess.get("typ") != "session" or sess.get("sub") != code_user_id:
        return JSONResponse(
            status_code=401, content={"error": "invalid_grant", "error_description": "session subject/type mismatch"}
        )
    cred_jwe = sess.get("cred_jwe")
    if not cred_jwe:
        return JSONResponse(status_code=401, content={"error": "invalid_grant", "error_description": "no credentials in session"})

    # Decrypt to AK/SK (from session cred_jwe)
    try:
        raw = decrypt_creds(cred_jwe)
        ak, sk = raw.get("AccessKeyId"), raw.get("SecretAccessKey")
        if not ak or not sk:
            raise ValueError("bad cred_jwe")
    except Exception:
        return JSONResponse(
            status_code=400, content={"error": "invalid_grant", "error_description": "unable to derive credentials"}
        )

    # Mint the REAL JWT for your API using STS session inside the token
    try:
        access_token = _mint_access_token(ak, sk, subject=code_user_id)
    except Exception:
        return JSONResponse(
            status_code=502, content={"error": "token_creation_failed", "error_description": "failed to mint access token"}
        )
    # Extract enc_credentials from the access token so we can reuse the STS session in refresh
    try:
        at_claims = jwt.decode(
            access_token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"verify_signature": True, "verify_exp": False, "verify_iat": False},
        )
        at_enc = at_claims.get("enc_credentials")
    except Exception:
        at_enc = None

    # Keep refresh_token carrying cred_jwe so we can refresh statelessly
    refresh_token = _mint_refresh_token(
        user_id=code_user_id,
        client_id=client_id,
        scope=code_scope,
        lifetime_days=30,
        cred_jwe=cred_jwe,
        enc_credentials=at_enc,
        min_interval_seconds=REFRESH_MIN_INTERVAL_SECONDS,
    )

    # Mark code as used
    try:
        AuthActions.update(**{"client": "core", "code": code, "used": True, "used_at": datetime.now(timezone.utc)})
    except Exception:
        log.warning(f"Failed to mark code used: {code}")

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": int(JWT_EXPIRATION_HOURS * 3600),
        "scope": code_scope,
        "refresh_token": refresh_token,
    }


def refresh_token_grant(request: Request, form: dict):

    # RFC 6749 Section 6: refresh an access token
    refresh_token = (form.get("refresh_token") or "").strip()
    if not refresh_token:
        return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": "refresh_token required"})
    try:
        rt = jwt.decode(
            refresh_token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"verify_signature": True, "verify_exp": True, "verify_iat": True},
        )
    except jwt.InvalidTokenError:
        return JSONResponse(status_code=400, content={"error": "invalid_grant", "error_description": "invalid refresh_token"})

    client_id = form.get("client_id", "").strip() or rt.get("aud")

    if rt.get("aud") != client_id or rt.get("typ") != "refresh":
        return JSONResponse(
            status_code=400, content={"error": "invalid_grant", "error_description": "refresh_token audience/type mismatch"}
        )

    user_id = rt.get("sub")
    scope = rt.get("scope", "")
    cred_jwe = rt.get("cred_jwe")
    enc_from_rt = rt.get("enc_credentials")
    if not user_id or not cred_jwe:
        return JSONResponse(status_code=400, content={"error": "invalid_grant", "error_description": "reauth_required"})

    # Enforce minimum refresh cadence (nbf)
    now = datetime.now(timezone.utc)
    nbf = rt.get("nbf")
    if isinstance(nbf, int) and now.timestamp() < nbf:
        retry_after = max(1, int(nbf - now.timestamp()))
        resp = JSONResponse(
            status_code=429,
            content={"error": "slow_down", "error_description": "refresh too soon", "retry_after": retry_after},
        )
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    enc_to_use = None
    if enc_from_rt:
        try:
            sts_creds = decrypt_creds(enc_from_rt)
            exp_str = sts_creds.get("Expiration")
            exp_dt = datetime.fromisoformat(exp_str.replace("Z", "+00:00")) if isinstance(exp_str, str) else None
            if exp_dt and (exp_dt - now).total_seconds() > ACCESS_REFRESH_WINDOW_SECONDS:
                enc_to_use = enc_from_rt
        except Exception:
            enc_to_use = None

    if enc_to_use:
        access_token = _mint_access_token(user_id, enc_to_use)
        new_refresh = _mint_refresh_token(
            user_id=user_id,
            client_id=client_id,
            scope=scope,
            lifetime_days=30,
            cred_jwe=cred_jwe,
            enc_credentials=enc_to_use,
            min_interval_seconds=REFRESH_MIN_INTERVAL_SECONDS,
        )
    else:
        try:
            raw = decrypt_creds(cred_jwe)
            ak, sk = raw.get("AccessKeyId"), raw.get("SecretAccessKey")
        except Exception:
            return JSONResponse(
                status_code=400, content={"error": "invalid_grant", "error_description": "unable to derive credentials"}
            )
        access_token = _mint_access_token(ak, sk, subject=user_id)
        at_claims = jwt.decode(
            access_token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"verify_signature": True, "verify_exp": False, "verify_iat": False},
        )
        enc_credentials = at_claims.get("enc_credentials")
        new_refresh = _mint_refresh_token(
            user_id=user_id,
            client_id=client_id,
            scope=scope,
            lifetime_days=30,
            cred_jwe=cred_jwe,
            enc_credentials=enc_credentials,
            min_interval_seconds=REFRESH_MIN_INTERVAL_SECONDS,
        )
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": int(JWT_EXPIRATION_HOURS * 3600),
        "scope": scope,
        "refresh_token": new_refresh,
    }


@oauth_router.post("/v1/token")
async def oauth_token(request: Request) -> dict:
    """Exchange authorization codes and refresh tokens for access.

    Route:
        POST /auth/v1/token
    Content-Type:
        application/x-www-form-urlencoded

    Grants:
        - authorization_code:
            Required form fields:
              grant_type=authorization_code
              code
              redirect_uri (exact match)
              client_id
              code_verifier (PKCE, for public clients)
            Required auth:
              Authorization: Bearer <session JWT with cred_jwe>
            Returns:
              access_token (JWT with enc_credentials), refresh_token (JWT with cred_jwe + nbf), token_type, expires_in, scope

        - refresh_token:
            Required form fields:
              grant_type=refresh_token
              refresh_token
              client_id
            Behavior:
              Enforces a minimum cadence via nbf, reuses enc_credentials if the STS session is still valid,
              otherwise performs a single STS call to mint a new access token.

    Errors:
        400 invalid_request/invalid_grant, 401 invalid_client, 429 slow_down with Retry-After.
    """
    # Parse form
    try:
        form = await request.form()
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": "invalid_request", "error_description": f"invalid form {str(e)}"})

    # Common client auth (used by both branches)
    auth_header = request.headers.get("Authorization", "")
    cid_basic, secret_basic = _parse_basic_auth(auth_header)
    client_id = (cid_basic or (form.get("client_id") or "")).strip()
    client_secret = (secret_basic or (form.get("client_secret") or "")).strip()

    if not check_rate_limit(request, "oauth_token", max_attempts=10, window_minutes=15):
        log.warning(f"Rate limit exceeded for client {client_id} on /auth/v1/token")
        return JSONResponse(status_code=429, content={"error": "rate_limited", "code": 429})

    # Validate client registration once
    app_info = _get_oauth_app_info(client_id) if client_id else None
    if not app_info:
        return JSONResponse(status_code=401, content={"error": "invalid_client", "error_description": "unknown client"})
    registered_secret = app_info.get("client_secret")
    is_confidential = bool(registered_secret)
    if is_confidential and client_secret != registered_secret:
        return JSONResponse(status_code=401, content={"error": "invalid_client", "error_description": "invalid credentials"})

    grant_type = (form.get("grant_type") or "").strip()
    if grant_type == "authorization_code":
        return await authorization_code_grant(request, form)
    elif grant_type == "refresh_token":
        return await refresh_token_grant(request, form)
    else:
        return JSONResponse(
            status_code=400,
            content={"error": "unsupported_grant_type", "error_description": "use authorization_code or refresh_token"},
        )


@oauth_router.post("/v1/revoke")
async def oauth_revoke(request: Request) -> dict:
    """Token revocation endpoint (RFC 7009).

    Route:
        POST /auth/v1/revoke

    Args:
        request (Request): Incoming FastAPI request with Authorization header.

    Returns:
        dict: Echo of token value (if present).
    """
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    return {"token": token}


@oauth_router.get("/.well-known/oauth-authorization-server")
async def oauth_discovery(request: Request) -> dict:
    """OAuth 2.0 Authorization Server Metadata (RFC 8414)."""
    base_url = str(request.base_url).rstrip("/")
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/auth/v1/authorize",
        "token_endpoint": f"{base_url}/auth/v1/token",
        "revocation_endpoint": f"{base_url}/auth/v1/revoke",
        "introspection_endpoint": f"{base_url}/auth/v1/introspect",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
    }
