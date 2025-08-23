import hashlib
import secrets
from typing import Set, Optional, Tuple
import uuid

import base64
from urllib.parse import urlencode
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse

import jwt

import core_logging as log

from core_db.oauth.actions import AuthActions
from core_db.exceptions import BadRequestException, ConflictException, UnknownException
from core_db.response import SuccessResponse
from core_db.registry.client.actions import ClientActions

from .tools import (
    check_rate_limit,
    get_user_access_key,
    get_authenticated_user,
    create_access_token_with_sts,
)

from .constants import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_EXPIRATION_HOURS,
    REFRESH_MIN_INTERVAL_SECONDS,
    ALLOWED_SCOPES,
)

oauth_router = APIRouter()


def _mint_refresh_token(user_id: str, client_id: str, scope: str, lifetime_days: int = 30) -> str:
    """Mint a refresh token with user identity only - NO AWS credentials."""
    payload = {
        "sub": user_id,
        "aud": client_id,
        "iat": datetime.now(tz=timezone.utc),
        "exp": datetime.now(tz=timezone.utc) + timedelta(days=lifetime_days),
        "typ": "refresh",
        "scope": scope,
        "nbf": int((datetime.now(timezone.utc) + timedelta(seconds=REFRESH_MIN_INTERVAL_SECONDS)).timestamp()),
        # NO AWS credentials - refresh tokens only identify the user
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


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
        response = ClientActions.get(client_id=client_id)
        log.debug(f"OAuth app info for client {client_id}:", details=response.data)
        return response.data
    except Exception as e:
        log.error(f"Failed to get OAuth app info for client {client_id}: {e}")
        return None


def _parse_basic_auth(
    auth_header: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
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


@oauth_router.get("/v1/cred_enc_key")
async def get_cred_enc_key(request: Request) -> JSONResponse:
    """Get the credential encryption key."""

    key_bytes = secrets.token_bytes(32)
    key_b64url = base64.urlsafe_b64encode(key_bytes).decode().rstrip("=")

    return JSONResponse(content={"cred_enc_key": key_b64url})


@oauth_router.get("/v1/authorize")
async def oauth_authorize(request: Request) -> Response:
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
    code_challenge = request.query_params.get("code_challenge")
    code_challenge_method = request.query_params.get("code_challenge_method") or "S256"

    log.debug(f"Received OAuth authorization request:", details=dict(request.query_params))

    if not check_rate_limit(request, "oauth_authorize", max_attempts=10, window_minutes=15):
        log.warning(f"Rate limit exceeded for client {client_id} on /auth/v1/authorize")
        return JSONResponse(status_code=429, content={"error": "rate_limited", "code": 429})

    if not client_id:
        return JSONResponse(
            status_code=400, content={"error": "invalid_request", "Missing required parameter: client_id": "Missing client_id"}
        )

    # 1) Basic validation
    app_info = _get_oauth_app_info(client_id) if client_id else None
    if not app_info or response_type != "code" or not redirect_uri:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": f"Invalid client_id, response_type, or redirect_uri",
            },
        )

    # 2) Ensure redirect_uri matches registered one (reuse app_info)
    registered_uris = app_info.get("ClientRedirectUrls", [])
    if redirect_uri not in [uri for uri in registered_uris if uri]:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_redirect_uri",
                "error_description": f"redirect_uri not registered for this client: {redirect_uri}",
            },
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

        log.debug(f"Unauthenticated request, redirecting to login: {login_url}")

        return RedirectResponse(url=login_url, status_code=302)

    # 4) Process scopes (request + policy => granted)
    requested_scopes = _parse_scopes(scope_param)
    granted_scopes = _grant_scopes(client_id, user_id, requested_scopes)

    # 5) Generate and persist the code (tie it to user+client+scopes)
    code = str(uuid.uuid4())
    if not code:
        return JSONResponse(
            status_code=500,
            content={
                "error": "server_error",
                "error_description": "Failed to generate authorization code",
            },
        )
    client = app_info.get("Client")
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    authorization = {
        "client": client,
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


def authorization_code_grant(request: Request, form: dict, app_info: dict) -> Response:

    client_id = form.get("client_id", "").strip()

    # Get client info including the client name/slug
    app_info = _get_oauth_app_info(client_id)
    if not app_info:
        return JSONResponse(status_code=401, content={"error": "invalid_client", "error_description": "unknown client"})

    # Extract client name (slug) from app_info
    client_name = app_info.get("client") or app_info.get("name") or "unknown"

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

    # Extract session JWT for user identity only (NO credentials)
    authz_hdr = (request.headers.get("Authorization") or "").strip()
    sess_token = authz_hdr.split(" ", 1)[1].strip() if authz_hdr.lower().startswith("bearer ") else request.cookies.get("sck_token")
    if not sess_token:
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_grant", "error_description": "missing session"},
        )

    try:
        sess = jwt.decode(
            sess_token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"verify_signature": True, "verify_exp": True, "verify_iat": True},
        )
    except jwt.InvalidTokenError:
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_grant", "error_description": "invalid session"},
        )

    if sess.get("typ") != "session" or sess.get("sub") != code_user_id:
        return JSONResponse(
            status_code=401,
            content={
                "error": "invalid_grant",
                "error_description": "session subject/type mismatch",
            },
        )

    # Get AWS credentials from database profile (NOT from session token)
    ak, sk = get_user_access_key(code_user_id)
    if not ak or not sk:
        return JSONResponse(
            status_code=401,
            content={
                "error": "invalid_grant",
                "error_description": "no AWS credentials configured",
            },
        )

    # Mint the access token with STS session inside
    try:
        access_token = create_access_token_with_sts(
            ak,
            sk,
            user_id=code_user_id,
            scope=code_scope,
            client_id=client_id,
            client_name=client_name,
        )
    except Exception as e:
        log.error(f"Failed to create access token: {e}")
        return JSONResponse(
            status_code=502,
            content={
                "error": "token_creation_failed",
                "error_description": "failed to mint access token",
            },
        )

    # Update refresh token to include client info
    refresh_token = _mint_refresh_token(
        user_id=code_user_id,
        client_id=client_id,
        client_name=client_name,  # Add client name
        scope=code_scope,
        lifetime_days=30,
    )

    # Mark code as used
    try:
        AuthActions.update(
            client=client_id,
            code=code,
            used=True,
            used_at=datetime.now(timezone.utc),
        )
    except Exception:
        log.warning(f"Failed to mark code used: {code}")

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": int(JWT_EXPIRATION_HOURS * 3600),
        "scope": code_scope,
        "refresh_token": refresh_token,
    }


def refresh_token_grant(request: Request, form: dict) -> Response:

    # RFC 6749 Section 6: refresh an access token
    refresh_token = (form.get("refresh_token") or "").strip()
    if not refresh_token:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "refresh_token required",
            },
        )
    try:
        rt = jwt.decode(
            refresh_token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"verify_signature": True, "verify_exp": True, "verify_iat": True},
        )
    except jwt.InvalidTokenError:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": "invalid refresh_token",
            },
        )

    client_id = form.get("client_id", "").strip() or rt.get("aud")
    client_name = rt.get("client_name", "unknown")  # Get from existing refresh token

    if rt.get("aud") != client_id or rt.get("typ") != "refresh":
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": "refresh_token audience/type mismatch",
            },
        )

    user_id = rt.get("sub")
    scope = rt.get("scope", "")

    if not user_id:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "invalid refresh token"},
        )

    # Get fresh AWS credentials from database (NOT from refresh token)
    ak, sk = get_user_access_key(user_id)
    if not ak or not sk:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "no AWS credentials"},
        )

    # Create new access token with client info
    try:
        access_token = create_access_token_with_sts(
            access_key=ak,
            secret_key=sk,
            user_id=user_id,
            scope=scope,
            client_id=client_id,
            client_name=client_name,
        )
    except Exception as e:
        log.error(f"Failed to create access token: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "token_creation_failed", "error_description": "failed to create access token"},
        )

    # Create new refresh token with client info
    new_refresh = _mint_refresh_token(
        user_id=user_id,
        client_id=client_id,
        client_name=client_name,
        scope=scope,
        lifetime_days=30,
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

    try:
        form = await request.form()
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": f"invalid form {str(e)}",
            },
        )

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
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_client", "error_description": "unknown client"},
        )

    registered_secret = app_info.get("client_secret")
    is_confidential = bool(registered_secret)
    if is_confidential and client_secret != registered_secret:
        return JSONResponse(
            status_code=401,
            content={
                "error": "invalid_client",
                "error_description": "invalid credentials",
            },
        )

    grant_type = (form.get("grant_type") or "").strip()
    if grant_type == "authorization_code":

        return await authorization_code_grant(request, form, app_info)

    elif grant_type == "refresh_token":

        return await refresh_token_grant(request, form)

    else:
        return JSONResponse(
            status_code=400,
            content={
                "error": "unsupported_grant_type",
                "error_description": "use authorization_code or refresh_token",
            },
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
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
    }
