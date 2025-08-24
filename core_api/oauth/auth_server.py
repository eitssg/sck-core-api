from typing import Set, Optional, Tuple
import hashlib
import base64
import uuid
from urllib.parse import urlencode
from datetime import datetime, timedelta, timezone
from core_db.registry import ClientFact
from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse

import jwt

import core_logging as log

from core_db.oauth import AuthActions, Authorizations
from core_db.exceptions import BadRequestException, ConflictException, UnknownException
from core_db.response import SuccessResponse

from .tools import (
    JwtPayload,
    check_rate_limit,
    get_user_access_key,
    get_authenticated_user,
    create_access_token_with_sts,
    get_oauth_app_info,
)

from .constants import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_EXPIRATION_HOURS,
    ALLOWED_SCOPES,
)

oauth_router = APIRouter()


def _mint_refresh_token(jwt_payload: JwtPayload, lifetime_days: int = 30) -> str:
    """Mint a refresh token with user identity only - NO AWS credentials."""

    exp = datetime.now(tz=timezone.utc) + timedelta(days=lifetime_days)
    exp = int(exp.timestamp())

    payload = JwtPayload(
        sub=jwt_payload.sub,
        cnm=jwt_payload.cnm,
        cid=jwt_payload.cid,
        scp=jwt_payload.scp,
        typ="refresh",
        exp=exp,
    )

    return payload.encode()


def _pkce_calc_challenge(verifier: str, method: str = "S256") -> str:
    """Compute PKCE authz.code_challenge from code_verifier."""
    m = (method or "S256").upper()
    if m == "PLAIN":
        return verifier
    if m != "S256":
        raise ValueError("unsupported code_challenge_method")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


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
    return ALLOWED_SCOPES


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


def _validate_client_credentials(client_secret: str, app_info: ClientFact) -> Tuple[str, bool]:

    client_id = app_info.client_id
    secret_hash = app_info.client_secret

    # Generate SHA-256 hash of provided secret to compare with stored hash
    provided_hash = hashlib.sha256(client_secret.encode("utf-8")).hexdigest()

    if provided_hash != secret_hash:
        log.info(f"Invalid client_secret for client {client_id}")
        return client_id, False

    return client_id, True


def _authenticate_client(request: Request, form: dict) -> tuple[str, bool]:
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
    """Generate a new AWS credential encryption key."""

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

    # 1) Validate ALL required parameters BEFORE rate limiting or DB calls
    if not client_id:
        return JSONResponse(
            status_code=400, content={"error": "invalid_request", "error_description": "Missing required parameter: client_id"}
        )

    if not response_type:
        return JSONResponse(
            status_code=400, content={"error": "invalid_request", "error_description": "Missing required parameter: response_type"}
        )

    if response_type != "code":
        return JSONResponse(
            status_code=400,
            content={"error": "unsupported_response_type", "error_description": "Only response_type=code is supported"},
        )

    if not redirect_uri:
        return JSONResponse(
            status_code=400, content={"error": "invalid_request", "error_description": "Missing required parameter: redirect_uri"}
        )

    # Optional: Validate state parameter format if present
    if state and (len(state) > 512 or "\n" in state or "\r" in state):
        return JSONResponse(
            status_code=400, content={"error": "invalid_request", "error_description": "Invalid state parameter format"}
        )

    # 2) Now check rate limiting (only for valid requests)
    if not check_rate_limit(request, "oauth_authorize", max_attempts=10, window_minutes=15):
        log.warning(f"Rate limit exceeded for client {client_id} on /auth/v1/authorize")
        return JSONResponse(status_code=429, content={"error": "rate_limited", "code": 429})

    # 3) Require authenticated user with valid session token
    jwt_payload, jwt_signature = get_authenticated_user(request)
    # Check for missing or invalid authentication
    if not jwt_payload:
        # No valid token at all - redirect to login
        pass  # Continue to login redirect logic below
    elif jwt_payload.typ != "session":
        # Wrong token type - return error instead of redirect
        token_type_name = {"access_token": "access token", "refresh": "refresh token"}.get(
            jwt_payload.typ, f"'{jwt_payload.typ}' token"
        )

        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_token_type",
                "error_description": f"Cannot use {token_type_name} for authorization flow. Please authenticate with session token from login.",
            },
        )
    elif jwt_payload.cid != client_id:
        # Client ID mismatch - return error
        return JSONResponse(
            status_code=400,
            content={
                "error": "client_mismatch",
                "error_description": f"Token was issued for client '{jwt_payload.cid}' but request is for client '{client_id}'",
            },
        )
    else:
        # Valid session token with matching client - continue with OAuth flow
        # Skip the login redirect logic
        pass

    # Only redirect to login if no valid session token
    if not jwt_payload or jwt_payload.typ != "session" or jwt_payload.cid != client_id:

        # If you have NOT signed in to THIS server, (I'm talking aboujt the oauth server)
        # then redirect to this server's login page.

        # Also, if the client_id you specified does not match the authenticated client's ID,
        # you should handle that case (e.g., by showing an error or redirecting).

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

    # 4) Database validation (client lookup) - AFTER auth check and rate limiting
    app_info: ClientFact = get_oauth_app_info(client_id)
    if not app_info:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": f"Invalid client_id. Client '{client_id}' not found in database.",
            },
        )

    if jwt_payload.cnm != app_info.client:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": f"Client mismatch: {jwt_payload.cnm} != {app_info.client}",
            },
        )

    # 5) Validate redirect_uri against registration
    registered_uris = app_info.client_redirect_urls
    if redirect_uri not in [uri for uri in registered_uris if uri]:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_redirect_uri",
                "error_description": f"redirect_uri not registered for this client: {redirect_uri}",
            },
        )

    # 6) Process scopes (request + policy => granted)
    requested_scopes = _parse_scopes(scope_param)
    granted_scopes = _grant_scopes(client_id, jwt_payload.sub, requested_scopes)

    # 7) Generate and persist the code (tie it to user+client+scopes)
    code = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    authorization = {
        "client": jwt_payload.cnm,
        "code": code,
        "client_id": client_id,
        "user_id": jwt_payload.sub,
        "redirect_url": redirect_uri,
        "scope": " ".join(granted_scopes),
        "expires_at": expires_at,
        "used": False,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method if code_challenge else None,
        "jwt_signature": jwt_signature,
    }
    try:
        resonse: SuccessResponse = AuthActions.create(**authorization)
    except BadRequestException as e:
        return JSONResponse(status_code=400, content={"error": str(e), "code": 400})
    except ConflictException as e:
        return JSONResponse(status_code=409, content={"error": str(e), "code": 409})
    except UnknownException as e:
        return JSONResponse(status_code=500, content={"error": str(e), "code": 500})

    # 8) Redirect back to client app with code + state
    sep = "&" if "?" in redirect_uri else "?"
    redirect_back = f"{redirect_uri}{sep}{urlencode({'code': code, 'state': state or ''})}"

    log.debug(f"Redirecting to: {redirect_back}")

    return RedirectResponse(url=redirect_back, status_code=302)


def authorization_code_grant(
    form: dict,
    jwt_payload: JwtPayload,
    jwt_signature: str,
    app_info: ClientFact,
) -> Response:

    code = (form.get("code") or "").strip()
    redirect_uri = (form.get("redirect_uri") or "").strip()
    code_verifier = (form.get("code_verifier") or "").strip()

    if not code or not redirect_uri:
        log.info(f"Missing code or redirect_uri for client {app_info.client_id}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "code and redirect_uri required",
            },
        )

    # Validate redirect_uri matches client registration (reuse app_info)
    registered_uris = app_info.client_redirect_urls or []
    if redirect_uri not in [uri for uri in registered_uris if uri]:
        log.info(f"Invalid redirect_uri for client {app_info.client_id}: {redirect_uri}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "redirect_uri not registered for this client",
            },
        )

    # Load authorization code record
    try:
        rec: SuccessResponse = AuthActions.get(client=jwt_payload.cnm, code=code)
        authz = Authorizations(**rec.data)
    except Exception:
        log.info(f"Failed to retrieve authorization code for client {app_info.client_id}: {code}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": f"code '{code}' not found",
            },
        )

    # Validate code record
    code_challenge_method = (authz.code_challenge_method or "S256") if authz.code_challenge else None

    if authz.used:
        log.info(f"Authorization code already used for client {app_info.client_id}: {code}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": "code already used",
            },
        )

    if jwt_signature != authz.jwt_signature:
        log.info(f"Token signature mismatch for client {app_info.client_id}: {code}")
        return JSONResponse(
            status_code=401,
            content={
                "error": "invalid_grant",
                "error_description": "token signature mismatch",
            },
        )

    if jwt_payload.cid != authz.client_id:
        log.info(f"Code client mismatch for client {app_info.client_id}: {code}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": "code client mismatch",
            },
        )

    if redirect_uri != authz.redirect_url:
        log.info(f"Invalid redirect_uri for client {app_info.client_id}: {redirect_uri}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": "redirect_uri does not match code",
            },
        )

    try:
        if authz.expires_at is not None:
            expires_dt = authz.expires_at
        else:
            expires_dt = None
        if not expires_dt or datetime.now(timezone.utc) > expires_dt.astimezone(timezone.utc):
            log.info(f"Authorization code expired for client {app_info.client_id}: {code}")
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_grant",
                    "error_description": "code expired",
                },
            )
    except Exception:
        log.info(f"Failed to retrieve authorization code expiry for client {app_info.client_id}: {code}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": "invalid code expiry",
            },
        )

    # PKCE verification for public clients
    if app_info.client_type and app_info.client_type == "confidential":
        if not authz.code_challenge:
            log.info(f"Missing code_challenge for client {app_info.client_id}: {code}")
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "error_description": "pkce required for public client",
                },
            )
        if not code_verifier:
            log.info(f"Missing code_verifier for client {app_info.client_id}: {code}")
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
            log.info(f"Failed to calculate PKCE challenge for client {app_info.client_id}: {code}")
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "error_description": "invalid code_verifier/method",
                },
            )
        if expected != authz.code_challenge:
            log.info(f"PKCE verification failed for client {app_info.client_id}: {code}")
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_grant",
                    "error_description": "pkce_verification_failed",
                },
            )

    # Get AWS credentials from database profile (NOT from session token)
    aws_credentials = get_user_access_key(jwt_payload.sub)
    if aws_credentials is None:
        log.info(f"Missing AWS credentials for client {app_info.client_id}: {jwt_payload.sub}")
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
            aws_credentials=aws_credentials,
            jwt_payload=jwt_payload,
        )
    except Exception as e:
        log.info(f"Failed to create access token: {e}")
        return JSONResponse(
            status_code=502,
            content={
                "error": "token_creation_failed",
                "error_description": "failed to mint access token",
            },
        )

    # Update refresh token to include client info
    refresh_token = _mint_refresh_token(
        jwt_payload=jwt_payload,
        lifetime_days=30,
    )

    # Mark code as used
    try:
        AuthActions.patch(
            client=jwt_payload.cnm,
            code=code,
            used=True,
            used_at=datetime.now(timezone.utc),
        )
    except Exception:
        log.info(f"Failed to mark code used: {code}")

    result = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": int(JWT_EXPIRATION_HOURS * 3600),
        "scope": authz.scope or "",
        "refresh_token": refresh_token,
    }
    return JSONResponse(status_code=200, content=result)


def refresh_token_grant(form: dict, jwt_payload: JwtPayload, jwt_signature: str, app_info: ClientFact) -> Response:

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
        rt = JwtPayload(
            **jwt.decode(
                refresh_token,
                JWT_SECRET_KEY,
                algorithms=[JWT_ALGORITHM],
                options={"verify_signature": True, "verify_exp": True, "verify_iat": True},
            )
        )
    except jwt.InvalidTokenError:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": "invalid refresh_token",
            },
        )

    if rt.cid != jwt_payload.cid or rt.typ != "refresh":
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_grant",
                "error_description": "refresh_token audience/type mismatch",
            },
        )

    if not jwt_payload.sub:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "invalid refresh token"},
        )

    # Get fresh AWS credentials from database (NOT from refresh token)
    aws_credentials = get_user_access_key(jwt_payload.sub)
    if not aws_credentials:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "no AWS credentials"},
        )

    # Create new access token with client info
    try:
        access_token = create_access_token_with_sts(
            aws_credentials=aws_credentials,
            user_id=jwt_payload.sub,
            scope=rt.scp or "",
            client_id=jwt_payload.cid,
            client=jwt_payload.cnm,
        )
    except Exception as e:
        log.error(f"Failed to create access token: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "token_creation_failed", "error_description": "failed to create access token"},
        )

    # Create new refresh token with client info
    new_refresh = _mint_refresh_token(
        user_id=jwt_payload.sub,
        client_id=jwt_payload.cid,
        client_name=jwt_payload.cnm,
        scope=rt.scp or "",
        lifetime_days=30,
    )

    result = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": int(JWT_EXPIRATION_HOURS * 3600),
        "scope": rt.scp or "",
        "refresh_token": new_refresh,
    }
    return JSONResponse(status_code=200, content=result)


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

    client_id = form.get("client_id", "").strip()

    if not client_id:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "client_id required"},
        )

    jwt_payload, jwt_signature = get_authenticated_user(request)
    if not jwt_payload or not client_id or client_id != jwt_payload.cid:
        return JSONResponse(
            status_code=401, content={"error": "invalid_client", "error_description": "unauthenticated request", "code": 401}
        )

    client_secret = form.get("client_secret", "").strip()

    if not check_rate_limit(request, "oauth_token", max_attempts=10, window_minutes=15):
        log.warning(f"Rate limit exceeded for client {client_id} on /auth/v1/token")
        return JSONResponse(status_code=429, content={"error": "rate_limited", "code": 429})

    # Validate client registration once
    app_info: ClientFact = get_oauth_app_info(client_id)
    if not app_info:
        return JSONResponse(status_code=401, content={"error": "invalid_client", "error_description": "unknown client"})

    is_confidential = bool(app_info.client_secret)
    _, validated = _validate_client_credentials(client_secret, app_info)
    if is_confidential and not validated:
        log.info(f"Invalid client_secret for client {client_id}")
        return JSONResponse(
            status_code=401,
            content={
                "error": "invalid_client",
                "error_description": "invalid credentials",
            },
        )

    grant_type = (form.get("grant_type") or "").strip()
    if grant_type == "authorization_code":

        return authorization_code_grant(form, jwt_payload, jwt_signature, app_info)

    elif grant_type == "refresh_token":

        return refresh_token_grant(form, jwt_payload, jwt_signature, app_info)

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
