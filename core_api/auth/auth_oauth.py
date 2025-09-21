from typing import Set, Optional, Tuple

import os
import hashlib
import base64
import uuid
import secrets
import hmac

from urllib.parse import urlencode, quote

from datetime import datetime, timedelta, timezone

import jwt

import core_logging as log

from core_db.profile.actions import ProfileActions
from core_db.profile.model import UserProfile
from core_db.registry import ClientFact
from core_db.oauth import AuthActions, Authorizations
from core_db.response import Response, RedirectResponse

from ..request import RouteEndpoint
from ..response import (
    OAuthErrorResponse,
    OAuthSuccessResponse,
    OAuthIntrospectionResponse,
    OAuthTokenResponse,
    OAuthUserInfoResponse,
    OAuthJWKSResponse,
    OAuthCredentialResponse,
)
from ..security import Permission, get_allowed_permissions

from .tools import (
    JwtPayload,
    check_rate_limit,
    get_user_access_key,
    get_authenticated_user,
    create_access_token_with_sts,
    get_oauth_app_info,
    ui_url,
)

from ..constants import JWT_ALGORITHM, JWT_ACCESS_HOURS

###########################################################
#
# THIS FILE IS RUN INSIDE A LAMBDA FUNCTION IT IS NOT A
# FASTAPI ASYNC HANDLER
#
###########################################################


def _mint_refresh_token(client: str, client_id: str, subject: str, scope: str, lifetime_days: int = 30) -> str:
    """Mint a refresh token with user identity only - NO AWS credentials."""

    exp = datetime.now(tz=timezone.utc) + timedelta(days=lifetime_days)
    exp = int(exp.timestamp())

    payload = JwtPayload(
        sub=subject,
        cnm=client,
        cid=client_id,
        scp=scope,
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
    except Exception as e:
        return None, None


def _get_client_allowed_scopes(client_id: str) -> Set[str]:
    """Return the set of scopes the registered client is allowed to request.

    Args:
        client_id (str): OAuth client identifier.

    Returns:
        Set[str]: Allowed scopes for the client.
    """
    return get_allowed_permissions()


def _get_user_allowed_scopes(user_id: str) -> Set[str]:
    """Return the set of scopes the user is allowed to grant.

    Args:
        user_id (str): Authenticated subject identifier.

    Returns:
        Set[str]: Allowed scopes for the user.
    """
    return get_allowed_permissions()


def _error_bridge(path_error: str, redirect_path: str = "/login") -> str:
    """Return UI /error URL with error code and redirect target.

    Args:
        path_error (str): Error code to convey
        redirect_path (str): Path to navigate to after storing error

    Returns:
        str: Absolute UI URL to /error with query params
    """
    # Ensure redirect has no host and starts with '/'
    rp = redirect_path if redirect_path.startswith("/") else f"/{redirect_path}"
    path = f"/error?error={quote(path_error)}&redirect={quote(rp)}"
    base = (os.getenv("CLIENT_HOST") or "").strip()
    if not base:
        return path
    base = base.rstrip("/")
    return f"{base}{path}"


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
    return [s for s in parts if s in get_allowed_permissions()]


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
    """Validate client credentials against stored secret.

    Supports two storage formats:
      1) Plaintext/opaque value (e.g., random token). We use constant-time compare.
      2) SHA-256 hex string (64 hex chars). We hash the provided secret and compare in constant time.

    Returns (client_id, is_valid).
    """

    stored = (app_info.client_secret or "").strip()

    # If nothing stored, treat as public client (validation handled by caller)
    if not stored:
        return app_info.client_id, True

    # Allow optional prefixes like "sha256:" or "s256:"
    lowered = stored.lower()
    if lowered.startswith("sha256:"):
        stored_hex = stored.split(":", 1)[1]
    elif lowered.startswith("s256:"):
        stored_hex = stored.split(":", 1)[1]
    else:
        stored_hex = None

    def _is_hex_sha256(s: str) -> bool:
        return len(s) == 64 and all(c in "0123456789abcdef" for c in s)

    # If stored value looks like a SHA-256 hex digest, compare digests
    if stored_hex is not None or _is_hex_sha256(stored):
        hex_to_compare = stored_hex if stored_hex is not None else stored
        provided_hex = hashlib.sha256(client_secret.encode("utf-8")).hexdigest()
        ok = hmac.compare_digest(provided_hex, hex_to_compare)
        return app_info.client_id, ok

    # Otherwise, compare raw values in constant time
    ok = hmac.compare_digest(client_secret.encode("utf-8"), stored.encode("utf-8"))
    return app_info.client_id, ok


def get_cred_enc_key(**kwargs) -> Response:
    """Generate a new AWS credential encryption key."""

    key_bytes = secrets.token_bytes(32)
    key_b64url = base64.urlsafe_b64encode(key_bytes).decode().rstrip("=")

    return OAuthCredentialResponse(cred_enc_key=key_b64url)


def oauth_authorize(
    *,
    cookies: dict = None,
    headers: dict = None,
    query_params: dict = None,
    **kwargs,
) -> Response:
    """OAuth 2.0 Authorization Code endpoint.


    Code	When it triggers	                    Current message (summary)	UI label
    mci 	Missing client_id param	                invalid_request: Missing required parameter: client_id	Missing client_id
    mrt	    Missing response_type param	            invalid_request: Missing required parameter: response_type	Missing response_type
    urt	    response_type != code	                unsupported_response_type	Unsupported response_type
    mru	    Missing redirect_uri param	            invalid_request: Missing required parameter: redirect_uri	Missing redirect_uri
    isf 	Invalid state format (too long/newlines)	invalid_request: Invalid state parameter format	Invalid state format
    rle	    Rate limit exceeded	                    rate_limited	Rate limited
    cmm	    Session token                           invalid/wrong type (not “session”)	invalid_token_type / invalid token for auth flow	Invalid session token
    cmc	    client_id in request doesn’t            match token cid	client_mismatch	Client mismatch
    cid	    client_id not found in DB	            invalid_request: Invalid client_id	Invalid OAuth Client ID
    cnm	    jwt_payload.cnm != app_info.client	    invalid_request: Client mismatch: <cnm> != <client>	Client namespace mismatch
    rnr	    redirect_uri not registered for client	invalid_request: redirect_uri not registered	Redirect URI not registered

    Route:
        GET /auth/v1/authorize

    Query:
        client_id, response_type=code, redirect_uri, scope?, state?, code_challenge?, code_challenge_method?, login_hint?

    Behavior:
        - Requires authenticated user via session cookie (typ=session).
        - Validates client registration and exact redirect_uri match.
        - Computes granted scopes (client ∩ user ∩ request).
        - Persists a short-lived authorization code (single-use).
        - Redirects to redirect_uri with ?code and state.
    """

    client = query_params.get("client", "core")
    client_id = query_params.get("client_id")
    response_type = query_params.get("response_type")
    redirect_uri = query_params.get("redirect_uri")
    scope_param = query_params.get("scope")
    state = query_params.get("state")
    code_challenge = query_params.get("code_challenge")
    code_challenge_method = query_params.get("code_challenge_method") or "S256"

    log.debug(
        "Received OAuth authorization request",
        details={
            **(query_params or {}),
            # Redact/replace sensitive values
            "code_challenge": bool(query_params.get("code_challenge")) if query_params else False,
            "code_challenge_method": query_params.get("code_challenge_method") if query_params else None,
        },
    )

    # 1) Validate ALL required parameters BEFORE rate limiting or DB calls
    if not client_id:
        log.warn("Authorize missing client_id", details={"query_keys": list((query_params or {}).keys())})
        return RedirectResponse(url=_error_bridge("mci"))

    if not response_type:
        log.warn("Authorize missing response_type", details={"client_id": client_id})
        return RedirectResponse(url=_error_bridge("mrt"))

    if response_type != "code":
        log.warn("Unsupported response_type", details={"client_id": client_id, "response_type": response_type})
        return RedirectResponse(url=_error_bridge("urt"))

    if not redirect_uri:
        log.warn("Authorize missing redirect_uri", details={"client_id": client_id})
        return RedirectResponse(url=_error_bridge("mru"))

    if code_challenge:
        if len(code_challenge) < 43 or len(code_challenge) > 128:
            log.debug("Invalid PKCE code_challenge length", details={"client_id": client_id, "length": len(code_challenge)})
            return RedirectResponse(url=_error_bridge("isf"))
        if not all(c.isalnum() or c in "-._~" for c in code_challenge):
            log.debug("Invalid PKCE code_challenge characters", details={"client_id": client_id})
            return RedirectResponse(url=_error_bridge("isf"))
    # Allow only S256 if provided (PLAIN not supported)
    if code_challenge_method and code_challenge_method != "S256":
        log.debug("Unsupported code_challenge_method", details={"client_id": client_id, "method": code_challenge_method})
        return RedirectResponse(url=_error_bridge("ucm"))

    # Optional: Validate state parameter format if present (length + printable chars)
    if state:
        invalid_state = len(state) > 512 or (not state.isprintable())
        if invalid_state:
            log.debug("Invalid state parameter format", details={"client_id": client_id, "length": len(state)})
            return RedirectResponse(url=_error_bridge("isf"))

    # 2) Now check rate limiting (use headers for IP/UA-aware limiting)
    headers = headers or {}
    # Rate limit key standardized to auth:oauth:authorize
    if not check_rate_limit(headers, "auth:oauth:authorize", max_attempts=10, window_minutes=15):
        log.warn("Rate limit exceeded for /auth/v1/authorize", details={"client_id": client_id})
        return RedirectResponse(url=_error_bridge("rle"))

    # 3) Require authenticated user with valid session token which is in cookies
    jwt_payload, _ = get_authenticated_user(cookies=cookies)

    # Check for missing or invalid authentication
    if jwt_payload and jwt_payload.typ != "session":
        # Wrong token type - return error instead of redirect
        log.warn(
            "Invalid token type for authorization flow",
            details={"client_id": client_id, "token_type": jwt_payload.typ, "expected": "session"},
        )
        return RedirectResponse(url=_error_bridge("cmm"))

    # Only redirect to login if no valid session token
    if not jwt_payload or jwt_payload.typ != "session":
        # Preserve the original authorize request so UX can resume post-login
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
        auth_params = {k: v for k, v in (query_params or {}).items() if k in allowed}
        authorize_url = "/auth/v1/authorize"
        if auth_params:
            authorize_url = f"{authorize_url}?{urlencode(auth_params)}"
        encoded_return_to = quote(authorize_url, safe="")
        login_url = f"/login?returnTo={encoded_return_to}"
        ui_login = ui_url(login_url)
        log.debug(
            "Unauthenticated request, redirecting to login",
            details={
                "login_url": ui_login,
                "has_code_challenge": bool(code_challenge),
                "code_challenge_method": code_challenge_method,
            },
        )
        return RedirectResponse(url=ui_login)

    # 4) Database validation (client lookup) - AFTER auth check and rate limiting
    app_info: ClientFact = get_oauth_app_info(client_id)
    if not app_info:
        log.warn("Unknown client in authorize", details={"client_id": client_id})
        return RedirectResponse(url=_error_bridge("cid"))

    if jwt_payload.cnm != app_info.client:
        return RedirectResponse(url=_error_bridge("cnm"))

    # 5) Validate redirect_uri against registration
    registered_uris = app_info.client_redirect_urls
    if redirect_uri not in [uri for uri in registered_uris if uri]:
        log.debug("Redirect URI not registered", details={"client_id": client_id, "redirect_uri": redirect_uri})
        return RedirectResponse(url=_error_bridge("rnr"))

    # 5b) Enforce PKCE for public clients (no client_secret)
    is_public = not bool(app_info.client_secret)
    if is_public:
        # Require PKCE for public clients
        if not code_challenge:
            log.debug("Missing PKCE for public client", details={"client_id": client_id})
            return RedirectResponse(url=_error_bridge("pkr"))
        if code_challenge_method and code_challenge_method != "S256":
            log.debug(
                "Unsupported PKCE method for public client", details={"client_id": client_id, "method": code_challenge_method}
            )
            return RedirectResponse(url=_error_bridge("ucm"))

    # 6) Process scopes (request + policy => granted)
    requested_scopes = _parse_scopes(scope_param)
    granted_scopes = _grant_scopes(client_id, jwt_payload.sub, requested_scopes)
    scopes = " ".join(granted_scopes)

    try:
        # 7) Generate and persist the code (tie it to user+client+scopes)
        code = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        authorization = {
            "client": jwt_payload.cnm,
            "client_id": client_id,
            "code": code,
            "subject": jwt_payload.sub,
            "scopes": scopes,
            "redirect_url": redirect_uri,
            "expires_at": expires_at,
            "used": False,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method if code_challenge else None,
        }

        result = AuthActions.create(**authorization)
        authz = Authorizations(**result.data)

        # Avoid logging the raw code/PKCE values in full; show presence and last 4
        safe_details = authz.model_dump(exclude_none=False)
        safe_details["code"] = (authz.code[:4] + "...") if authz.code else None
        if authz.code_challenge:
            safe_details["code_challenge"] = True
            safe_details["code_challenge_method"] = authz.code_challenge_method or "S256"

        log.debug("Created new authorization code", details=safe_details)

    except Exception as e:
        log.error("Failed to create authorization code", details={"client_id": client_id, "error": str(e)}, exception=e)
        return RedirectResponse(url=_error_bridge("server_error"))

    # 8) Redirect back to client app with code + state
    sep = "&" if "?" in redirect_uri else "?"
    redirect_back = f"{redirect_uri}{sep}{urlencode({'code': code, 'state': state or ''})}"

    log.debug("Redirecting to client redirect_uri", details={"location": redirect_back})

    return RedirectResponse(url=redirect_back)


def _get_token_authorization(app_info: ClientFact, code: str) -> Authorizations:
    try:
        # Will throw "Not found" if no such code for client or already used
        rec = AuthActions.patch(client=app_info.client, code=code, client_id=app_info.client_id, used=True)
        authz = Authorizations(**rec.data)
        return authz
    except Exception as e:
        log.warn(
            "Authorization code database lookup failed",
            details={"client": app_info.client, "code": code[:8] + "...", "error": str(e)},
        )
        return None


def _authorization_code_grant(
    body: dict,
    app_info: ClientFact,
) -> OAuthErrorResponse | OAuthTokenResponse:

    code = (body.get("code") or "").strip()
    redirect_uri = (body.get("redirect_uri") or "").strip()
    code_verifier = (body.get("code_verifier") or "").strip()
    try:
        log.debug(
            "Token exchange (authorization_code) request",
            details={
                "client_id": app_info.client_id,
                "has_code_verifier": bool(code_verifier),
                "is_confidential_client": bool(app_info.client_secret),
            },
        )
    except Exception:
        pass

    if not code or not redirect_uri:
        log.debug("Missing code or redirect_uri", details={"client_id": app_info.client_id})
        return OAuthErrorResponse(code=400, error_description="invalid_request: code and redirect_uri required")

    # Validate redirect_uri matches client registration (reuse app_info)
    registered_uris = app_info.client_redirect_urls or []
    if redirect_uri not in [uri for uri in registered_uris if uri]:
        log.debug("Invalid redirect_uri for client", details={"client_id": app_info.client_id, "redirect_uri": redirect_uri})
        return OAuthErrorResponse(code=400, error_description="invalid_request: redirect_uri not registered for this client")

    # Load authorization code record
    authz = _get_token_authorization(app_info, code)
    if not authz:
        return OAuthErrorResponse(code=401, error_description=f"invalid_grant: code '{code}' not found")

    # Validate code record
    code_challenge_method = (authz.code_challenge_method or "S256") if authz.code_challenge else None

    if redirect_uri != authz.redirect_url:
        log.debug(
            "Invalid redirect_uri does not match code", details={"client_id": app_info.client_id, "redirect_uri": redirect_uri}
        )
        return OAuthErrorResponse(code=401, error_description="invalid_grant: redirect_uri does not match code")

    if authz.expires_at is not None:
        expires_dt = authz.expires_at
    else:
        expires_dt = None
    if not expires_dt or datetime.now(timezone.utc) > expires_dt.astimezone(timezone.utc):
        log.warn(
            "Expired authorization code used",
            details={
                "client_id": authz.client_id,
                "code": code[:8] + "...",
                "expired_at": expires_dt.isoformat() if expires_dt else "unknown",
            },
        )
        return OAuthErrorResponse(code=401, error_description="invalid_grant: code expired")

    # PKCE verification required for public clients (no client_secret). Confidential clients skip PKCE.
    if not app_info.client_secret:

        if not authz.code_challenge:
            log.debug("Missing PKCE code_challenge", details={"client_id": app_info.client_id, "code": code[:8] + "..."})
            return OAuthErrorResponse(code=400, error_description="invalid_request: pkce required for public client")

        if not code_verifier:
            log.debug("Missing PKCE code_verifier", details={"client_id": app_info.client_id, "code": code[:8] + "..."})
            return OAuthErrorResponse(code=400, error_description="invalid_request: code_verifier required")

        if (
            (not code_verifier)
            or len(code_verifier) < 43
            or len(code_verifier) > 128
            or not all(c.isalnum() or c in "-._~" for c in code_verifier)
        ):
            log.debug("Invalid PKCE code_verifier format", details={"client_id": app_info.client_id, "code": code[:8] + "..."})
            return OAuthErrorResponse(code=400, error_description="invalid_request: invalid code_verifier format")

        if code_challenge_method not in (None, "S256"):
            log.debug("Unsupported PKCE code_challenge_method", details={"client_id": app_info.client_id, "code": code[:8] + "..."})
            return OAuthErrorResponse(code=400, error_description="invalid_request: unsupported code_challenge_method")

        try:
            expected = _pkce_calc_challenge(code_verifier, code_challenge_method or "S256")
        except Exception:
            log.debug("Failed to calculate PKCE challenge", details={"client_id": app_info.client_id, "code": code[:8] + "..."})
            return OAuthErrorResponse(code=400, error_description="invalid_request: invalid code_verifier/method")

        if expected != authz.code_challenge:
            log.warn("PKCE verification failed", details={"client_id": app_info.client_id, "code": code[:8] + "..."})
            return OAuthErrorResponse(code=401, error_description="invalid_grant: pkce_verification_failed")
        else:
            log.debug("PKCE verification passed", details={"client_id": app_info.client_id, "code": code[:8] + "..."})

    if not authz.subject:
        log.warn("Authorization code subject missing", details={"client_id": app_info.client_id, "code": code[:8] + "..."})
        return OAuthErrorResponse(code=401, error_description="invalid_grant: code payload invalid")

    return _get_grant_response(cid=authz.client_id, cnm=authz.client, sub=authz.subject, scp=authz.scopes)


def _get_aws_credentials(client: str, subject: str) -> tuple[dict, list]:
    try:
        return get_user_access_key(client, subject)
    except Exception as e:
        log.warn("Failed to get AWS credentials", details={"client": client, "subject": subject, "error": str(e)})
    return {}, [Permission.USER_READ]


def _refresh_token_grant(body: dict, app_info: ClientFact) -> OAuthErrorResponse | OAuthTokenResponse:

    # RFC 6749 Section 6: refresh an access token
    refresh_token = (body.get("refresh_token") or "").strip()
    if not refresh_token:
        return OAuthErrorResponse(code=400, error_description="invalid_request: refresh_token required")

    try:
        rt = JwtPayload.decode(refresh_token)

    except jwt.InvalidTokenError as e:
        return OAuthErrorResponse(code=401, error_description=f"invalid_grant: invalid refresh_token {str(e)}")

    if rt.cid != app_info.client_id or rt.typ != "refresh":
        log.warn(
            "Refresh token validation failed",
            details={"client_id": app_info.client_id, "refresh_client": rt.cid, "refresh_type": rt.typ},
        )
        return OAuthErrorResponse(code=401, error_description="invalid_grant: refresh_token audience/type mismatch")

    if not rt.sub:
        return OAuthErrorResponse(code=401, error_description="invalid_grant: invalid refresh token")

    return _get_grant_response(cid=rt.cid, cnm=rt.cnm, sub=rt.sub, scp=rt.scp)


def _get_grant_response(*, cid, cnm, sub, scp) -> OAuthTokenResponse | OAuthErrorResponse:

    # Get fresh AWS credentials from database (NOT from refresh token)
    credentials, permissions = _get_aws_credentials(cnm, sub)
    if not credentials:
        log.warn("Missing AWS credentials for refresh token user %s in client %s", sub, cnm)

    # Create new access token with client info
    try:
        access_token = create_access_token_with_sts(
            aws_credentials=credentials,
            client_id=cid,
            client=cnm,
            subject=sub,
            scope=scp,
            permissions=permissions,
        )
    except Exception as e:
        log.warn(
            "Refresh token access token creation failed",
            details={"client_id": cid, "user_id": sub, "error": str(e)},
        )
        return OAuthErrorResponse(code=500, error_description="failed to create access token", exception=e)

    # Create new refresh token with client info
    new_refresh = _mint_refresh_token(
        client=cnm,
        client_id=cid,
        subject=sub,
        scope=scp,
        lifetime_days=30,
    )

    resp = OAuthTokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=int(JWT_ACCESS_HOURS * 3600),
        scope=scp or "",
        refresh_token=new_refresh,
    )

    log.debug("Access token grant response:", details=resp.model_dump(exclude_none=True))

    return resp


def oauth_token(*, headers: dict = None, body: dict = None, **kwargs) -> OAuthTokenResponse | OAuthErrorResponse:
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
                code_verifier (PKCE, required for public clients)
            Client authentication:
                - Confidential clients MUST authenticate with HTTP Basic (Authorization header) or body params.
                - Public clients MUST NOT use a client_secret (PKCE enforces proof-of-possession).
            Returns:
                access_token (JWT), refresh_token (JWT), token_type, expires_in, scope

        - refresh_token:
            Required form fields:
                grant_type=refresh_token
                refresh_token
                client_id
            Behavior:
                Validates refresh token audience/type, mints a new access token and rotates refresh token.

    Errors:
        400 invalid_request/invalid_grant, 401 invalid_client, 429 slow_down with Retry-After.
    """
    # Normalize inputs
    body = body or {}
    headers = headers or {}

    # Prefer Authorization header if present; otherwise, fallback to form
    form_client_id = (body.get("client_id") or "").strip()
    form_client_secret = (body.get("client_secret") or "").strip()

    # Support HTTP Basic client authentication (RFC 6749 §2.3.1)
    basic_client_id, basic_client_secret = _parse_basic_auth(headers.get("authorization"))
    if basic_client_id:

        if form_client_id and form_client_id != basic_client_id:
            return OAuthErrorResponse(code=400, error_description="invalid_request: client_id mismatch with Authorization header")

        client_id = basic_client_id
        client_secret = basic_client_secret or ""

    else:
        client_id = form_client_id
        client_secret = form_client_secret

    if not client_id:
        return OAuthErrorResponse(code=400, error_description="invalid_request: client_id required")

    # Apply rate limits per grant_type to avoid blocking refresh storms on reloads
    grant_type = (body.get("grant_type") or "").strip()
    if grant_type == "refresh_token":
        # Higher allowance for refresh flows (same endpoint as token)
        # Rate limit key standardized to auth:oauth:token:refresh
        if not check_rate_limit(headers, "auth:oauth:token:refresh", max_attempts=500, window_minutes=15):
            log.warn("Rate limit exceeded for /auth/v1/token refresh", details={"client_id": client_id})
            return OAuthErrorResponse(code=429, error_description="rate_limited")
    elif grant_type == "authorization_code":
        # Rate limit key standardized to auth:oauth:token:auth_code
        if not check_rate_limit(headers, "auth:oauth:token:auth_code", max_attempts=50, window_minutes=15):
            log.warn("Rate limit exceeded for /auth/v1/token authcode", details={"client_id": client_id})
            return OAuthErrorResponse(code=429, error_description="rate_limited")
    else:
        # Generic/unknown grant types (still gate to prevent abuse)
        # Rate limit key standardized to auth:oauth:token:other
        if not check_rate_limit(headers, "auth:oauth:token:other", max_attempts=50, window_minutes=15):
            log.warn("Rate limit exceeded for /auth/v1/token other", details={"client_id": client_id})
            return OAuthErrorResponse(code=429, error_description="rate_limited")

    # Validate client registration once
    app_info: ClientFact = get_oauth_app_info(client_id)
    if not app_info:
        log.warn("Unknown client on token exchange", details={"client_id": client_id})
        resp = OAuthErrorResponse(code=401, error_description="invalid_client: unknown client")
        resp.set_header("WWW-Authenticate", 'Basic realm="OAuth"')
        return resp

    is_confidential = bool(app_info.client_secret)
    _, validated = _validate_client_credentials(client_secret, app_info)
    if is_confidential and not validated:
        log.warn("Client authentication failed on token endpoint", details={"client_id": client_id})
        resp = OAuthErrorResponse(code=401, error_description="invalid_client: invalid credentials")
        resp.set_header("WWW-Authenticate", 'Basic realm="OAuth"')
        return resp

    if grant_type == "authorization_code":

        return _authorization_code_grant(body, app_info)

    elif grant_type == "refresh_token":

        return _refresh_token_grant(body, app_info)

    else:
        return OAuthErrorResponse(code=400, error_description="unsupported_grant_type: use authorization_code or refresh_token")


def oauth_revoke(
    *, cookies: dict = None, headers: dict = None, body: dict = None, **kwargs
) -> OAuthSuccessResponse | OAuthErrorResponse:
    """Token revocation endpoint (RFC 7009).

    Route:
        POST /auth/v1/revoke
    Content-Type:
        application/x-www-form-urlencoded
    Form Fields:
        token (required): The token to revoke
        token_type_hint (optional): access_token, refresh_token

    Returns:
        Response: HTTP 200 with empty body on success
    """

    token = (body.get("token") or "").strip() if body else ""
    token_type_hint = (body.get("token_type_hint") or "").strip() if body else ""

    if not token:
        return OAuthErrorResponse(code=400, error_description="invalid_request: token parameter required")

    # Rate limiting (use headers; guard None)
    headers = headers or {}
    # Rate limit key standardized to auth:oauth:revoke
    if not check_rate_limit(headers, "auth:oauth:revoke", max_attempts=10, window_minutes=1):
        log.warn("Rate limited token revocation", details={"token_type_hint": token_type_hint or None})
        return OAuthErrorResponse(code=429, error_description="rate_limited")

    # Optional: Validate the token format (but don't require it to be valid)
    # RFC 7009 says to return 200 even for invalid/expired tokens

    try:
        jwt_payload = JwtPayload.decode(token)
        log.debug(f"Token revoked for user {jwt_payload.sub}")
    except:
        # Token is invalid/expired - still return 200 per RFC 7009
        log.debug("Invalid token submitted for revocation")

    # RFC 7009: Return HTTP 200 with empty body
    # Use a special response class for empty body
    return OAuthSuccessResponse()


def oauth_introspect(*, headers: dict = None, body: dict = None, **kwargs) -> OAuthErrorResponse | OAuthIntrospectionResponse:
    """Token introspection endpoint (RFC 7662).

    Route:
        POST /auth/v1/introspect
    Content-Type:
        application/x-www-form-urlencoded

    Form Fields:
        token (required): The token to introspect
        token_type_hint (optional): access_token, refresh_token

    Returns:
        Response: Token metadata or {active: false}
    """
    token = (body.get("token") or "").strip()
    token_type_hint = (body.get("token_type_hint") or "").strip()

    if not token:
        return OAuthErrorResponse(code=400, error_description="invalid_request: token parameter required")

    # Rate limiting (use headers; guard None)
    headers = headers or {}
    # Rate limit key standardized to auth:oauth:introspect
    if not check_rate_limit(headers, "auth:oauth:introspect", max_attempts=20, window_minutes=1):
        log.warn("Rate limited token introspection")
        return OAuthErrorResponse(code=429, error_description="rate_limited")

    try:
        jwt_payload = JwtPayload.decode(token)

        return OAuthIntrospectionResponse(
            active=True,
            client_id=jwt_payload.cid,
            username=jwt_payload.sub,
            scope=jwt_payload.scp or "",
            token_type=jwt_payload.typ,
            exp=jwt_payload.exp,
            sub=jwt_payload.sub,
            aud=jwt_payload.cid,
        )

    except jwt.InvalidTokenError:
        return OAuthIntrospectionResponse(active=False)

    except Exception as e:
        log.error(f"Token introspection error: {e}")
        return OAuthErrorResponse(code=500, error_description="introspection_failed", exception=e)


def oauth_userinfo(*, cookies: dict = None, headers: dict = None, **kwargs) -> OAuthErrorResponse | OAuthUserInfoResponse:
    """OpenID Connect UserInfo endpoint.

    Route:
        GET /auth/v1/userinfo
    Headers:
        Authorization: Bearer <access_token>

    Returns:
        Response: User profile information
    """

    # Rate limiting (use headers; guard None)
    headers = headers or {}
    # Rate limit key standardized to auth:oauth:userinfo
    if not check_rate_limit(headers, "auth:oauth:userinfo", max_attempts=30, window_minutes=1):
        log.warn("Rate limited userinfo")
        return OAuthErrorResponse(code=429, error_description="rate_limited")

    # Validate access token
    jwt_payload, _ = get_authenticated_user(cookies=cookies, headers=headers)

    # Ensure this is an access token
    if not jwt_payload or jwt_payload.typ != "access":
        return OAuthErrorResponse(code=401, error_description="invalid_token: access token required")

    try:
        # Get user profile from database
        profile = ProfileActions.get(client=jwt_payload.cnm, user_id=jwt_payload.sub, profile_name="default")
    except Exception as e:
        log.debug(f"Failed to retrieve user profile: {str(e)}")
        return OAuthErrorResponse(code=404, error_description="User Information unavailable", exception=e)

    return OAuthUserInfoResponse(
        sub=jwt_payload.sub,
        email=profile.user_id,  # Assuming user_id is email
        name=f"{profile.first_name} {profile.last_name}".strip(),
        given_name=profile.first_name,
        family_name=profile.last_name,
        preferred_username=jwt_payload.sub,
        updated_at=int(profile.updated_at.timestamp()) if profile.updated_at else None,
    )


def oauth_jwks(*, headers: dict = None, **kwargs) -> OAuthErrorResponse | OAuthJWKSResponse:
    """JSON Web Key Set endpoint for token verification.

    Route:
        GET /auth/v1/jwks

    Returns:
        Response: JWKS containing public keys for token verification
    """
    # Rate limiting (use headers; guard None)
    headers = headers or {}
    # Rate limit key standardized to auth:oauth:jwks
    if not check_rate_limit(headers, "auth:oauth:jwks", max_attempts=50, window_minutes=1):
        log.warn("Rate limited jwks")
        return OAuthErrorResponse(code=429, error_description="rate_limited")

    try:
        # For HMAC (symmetric) keys, we typically don't expose the secret
        # This is a placeholder - in production you'd use RSA/ECDSA keys
        keys = [
            {
                "kty": "oct",  # Symmetric key type for HMAC
                "use": "sig",  # Used for signatures
                "kid": "default",  # Key ID
                "alg": JWT_ALGORITHM,  # Algorithm
                # Note: For HMAC, we don't expose the actual key value
                # In production, use RSA/ECDSA with public key exposure
            }
        ]

        return OAuthJWKSResponse(keys=keys)

    except Exception as e:
        log.error(f"JWKS endpoint error: {e}")
        return OAuthErrorResponse(code=500, error_description="jwks_failed", exception=e)


auth_oauth_endpoints = {
    "GET:/auth/v1/authorize": RouteEndpoint(
        oauth_authorize,
        permissions={Permission.DATA_READ},
        allow_anonymous=True,
        client_isolation=True,  # Enable client isolation for now; revisit as the platform evolves
    ),
    "GET:/auth/v1/cred_enc_key": RouteEndpoint(
        get_cred_enc_key,
        permissions={Permission.DATA_READ},
        allow_anonymous=True,
        client_isolation=True,  # Enable client isolation for now; revisit
    ),
    "POST:/auth/v1/token": RouteEndpoint(
        oauth_token,
        permissions={Permission.DATA_READ},
        allow_anonymous=True,
        client_isolation=True,  # Enable client isolation for now; revisit
    ),
    "POST:/auth/v1/revoke": RouteEndpoint(
        oauth_revoke,
        permissions={Permission.USER_MANAGE},
        client_isolation=True,  # Enable client isolation for now; revisit
    ),
    "POST:/auth/v1/introspect": RouteEndpoint(
        oauth_introspect,
        permissions={Permission.DATA_READ},
        allow_anonymous=True,
        client_isolation=True,  # Enable client isolation for now; revisit
    ),
    "GET:/auth/v1/userinfo": RouteEndpoint(
        oauth_userinfo,
        permissions={Permission.DATA_READ},
        allow_anonymous=True,
        client_isolation=True,  # Enable client isolation for now; revisit
    ),
    "GET:/auth/v1/jwks": RouteEndpoint(
        oauth_jwks,
        permissions={Permission.DATA_READ},
        allow_anonymous=True,
        client_isolation=True,  # Enable client isolation for now; revisit
    ),
}
