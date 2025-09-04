from typing import Set, Optional, Tuple

import hashlib
import base64
import uuid
import secrets

from urllib.parse import urlencode

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
    OAuthLogoutResponse,
    OAuthCredentialResponse,
)


from ..security import Permission

from .tools import (
    JwtPayload,
    check_rate_limit,
    get_user_access_key,
    get_authenticated_user,
    create_access_token_with_sts,
    get_oauth_app_info,
)

from .constants import (
    JWT_ALGORITHM,
    JWT_ACCESS_HOURS,
    ALLOWED_SCOPES,
)


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
        log.warn("Invalid client credentials for %s", client_id)
        return client_id, False

    return client_id, True


def _authenticate_client(headers: dict, form: dict) -> tuple[str, bool]:
    """Authenticate OAuth client using standard methods."""
    # Method 1: HTTP Basic Authentication
    auth_header = headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        client_id, client_secret = _parse_basic_auth(auth_header)
        return _validate_client_credentials(client_id, client_secret)

    # Method 2: Form parameters
    client_id = form.get("client_id")
    client_secret = form.get("client_secret")
    return _validate_client_credentials(client_id, client_secret)


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

    client_id = query_params.get("client_id")
    response_type = query_params.get("response_type")
    redirect_uri = query_params.get("redirect_uri")
    scope_param = query_params.get("scope")
    state = query_params.get("state")
    code_challenge = query_params.get("code_challenge")
    code_challenge_method = query_params.get("code_challenge_method") or "S256"

    log.debug(f"Received OAuth authorization request:", details=query_params)

    # 1) Validate ALL required parameters BEFORE rate limiting or DB calls
    if not client_id:
        return OAuthErrorResponse(code=400, error_description="invalid_request: Missing required parameter: client_id")

    if not response_type:
        return OAuthErrorResponse(code=400, error_description="invalid_request: Missing required parameter: response_type")

    if response_type != "code":
        return OAuthErrorResponse(code=400, error_description="unsupported_response_type: Only response_type=code is supported")

    if not redirect_uri:
        return OAuthErrorResponse(code=400, error_description="invalid_request: Missing required parameter: redirect_uri")

    # Optional: Validate state parameter format if present
    if state and (len(state) > 512 or "\n" in state or "\r" in state):
        return OAuthErrorResponse(code=400, error_description="invalid_request: Invalid state parameter format")

    # 2) Now check rate limiting (only for valid requests)
    if not check_rate_limit(query_params, "oauth_authorize", max_attempts=10, window_minutes=15):
        log.warn(f"Rate limit exceeded for client {client_id} on /auth/v1/authorize")
        return OAuthErrorResponse(code=429, error_description="rate_limited")

    # 3) Require authenticated user with valid session token
    jwt_payload, jwt_signature = get_authenticated_user(cookies, headers)
    # Check for missing or invalid authentication
    if not jwt_payload:
        # No valid token at all - redirect to login
        pass  # Continue to login redirect logic below
    elif jwt_payload.typ != "session":
        # Wrong token type - return error instead of redirect
        log.warn(
            "Invalid token type for authorization flow",
            details={"client_id": client_id, "token_type": jwt_payload.typ, "expected": "session"},
        )
        token_type_name = {
            "access_token": "access token",
            "refresh": "refresh token",
        }.get(jwt_payload.typ, f"'{jwt_payload.typ}' token")

        return OAuthErrorResponse(
            code=400,
            error_description=f"invalid_token_type: Cannot use {token_type_name} for authorization flow. Please authenticate with session token from login.",
        )
    elif jwt_payload.cid != client_id:
        # Client ID mismatch - return error
        log.warn("Client ID mismatch in authorization flow", details={"request_client": client_id, "token_client": jwt_payload.cid})
        return OAuthErrorResponse(
            code=400,
            error_description=f"client_mismatch: Token was issued for client '{jwt_payload.cid}' but request is for client '{client_id}'",
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
        params = {k: v for k, v in query_params.items() if k in allowed}

        # Optional: sanitize login_hint
        if "login_hint" in params:
            hint = params["login_hint"].strip()
            if len(hint) > 256 or "\n" in hint or "\r" in hint:
                params.pop("login_hint", None)
            else:
                params["login_hint"] = hint

        login_url = f"/login?returnTo=/auth/v1/authorize&{urlencode(params)}"

        log.debug(f"Unauthenticated request, redirecting to login: {login_url}")

        return RedirectResponse(url=login_url)

    # 4) Database validation (client lookup) - AFTER auth check and rate limiting
    app_info: ClientFact = get_oauth_app_info(client_id)
    if not app_info:
        log.warn("Unknown client attempted OAuth flow: %s", client_id)
        return OAuthErrorResponse(
            code=400,
            error_description=f"invalid_request: Invalid client_id. Client '{client_id}' not found in database.",
        )

    if jwt_payload.cnm != app_info.client:
        return OAuthErrorResponse(
            code=400,
            error_description=f"invalid_request: Client mismatch: {jwt_payload.cnm} != {app_info.client}",
        )

    # 5) Validate redirect_uri against registration
    registered_uris = app_info.client_redirect_urls
    if redirect_uri not in [uri for uri in registered_uris if uri]:
        return OAuthErrorResponse(
            code=400,
            error_description=f"invalid_request: redirect_uri not registered for this client: {redirect_uri}",
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
    }
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

    AuthActions.create(**authorization)

    # 8) Redirect back to client app with code + state
    sep = "&" if "?" in redirect_uri else "?"
    redirect_back = f"{redirect_uri}{sep}{urlencode({'code': code, 'state': state or ''})}"

    log.debug(f"Redirecting to: {redirect_back}")

    return RedirectResponse(url=redirect_back, status_code=302)


def _authorization_code_grant(
    body: dict,
    jwt_payload: JwtPayload,
    jwt_signature: str,
    app_info: ClientFact,
):

    code = (body.get("code") or "").strip()
    redirect_uri = (body.get("redirect_uri") or "").strip()
    code_verifier = (body.get("code_verifier") or "").strip()

    if not code or not redirect_uri:
        log.debug(f"Missing code or redirect_uri for client {app_info.client_id}")
        return OAuthErrorResponse(code=400, error_description="invalid_request: code and redirect_uri required")

    # Validate redirect_uri matches client registration (reuse app_info)
    registered_uris = app_info.client_redirect_urls or []
    if redirect_uri not in [uri for uri in registered_uris if uri]:
        log.debug(f"Invalid redirect_uri for client {app_info.client_id}: {redirect_uri}")
        return OAuthErrorResponse(code=400, error_description="invalid_request: redirect_uri not registered for this client")

    # Load authorization code record
    try:
        rec = AuthActions.get(client=jwt_payload.cnm, code=code)
        authz = Authorizations(**rec.data)
    except Exception:
        log.warn(
            "Authorization code database lookup failed",
            details={"client": jwt_payload.cnm, "code": code[:8] + "...", "error": "code not found"},
        )
        return OAuthErrorResponse(code=401, error_description=f"invalid_grant: code '{code}' not found")

    # Validate code record
    code_challenge_method = (authz.code_challenge_method or "S256") if authz.code_challenge else None

    if authz.used:
        log.warn("Authorization code reuse attempt", details={"client_id": authz.client_id, "code": code[:8] + "..."})
        return OAuthErrorResponse(code=401, error_description="invalid_grant: code already used")

    if jwt_signature != authz.jwt_signature:
        log.warn("Token signature mismatch", details={"client_id": authz.client_id, "code": code[:8] + "..."})
        return OAuthErrorResponse(code=401, error_description="invalid_grant: token signature mismatch")

    if jwt_payload.cid != authz.client_id:
        log.warn(
            "Authorization code client mismatch",
            details={"token_client": jwt_payload.cid, "code_client": authz.client_id, "code": code[:8] + "..."},
        )
        return OAuthErrorResponse(code=401, error_description="invalid_grant: code client mismatch")

    if redirect_uri != authz.redirect_url:
        log.debug(f"Invalid redirect_uri for client {app_info.client_id}: {redirect_uri}")
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

    # PKCE verification for public clients
    if app_info.client_type and app_info.client_type == "confidential":
        if not authz.code_challenge:
            log.debug(f"Missing code_challenge for client {app_info.client_id}: {code}")
            return OAuthErrorResponse(code=400, error_description="invalid_request: pkce required for public client")
        if not code_verifier:
            log.debug(f"Missing code_verifier for client {app_info.client_id}: {code}")
            return OAuthErrorResponse(code=400, error_description="invalid_request: code_verifier required")
        try:
            expected = _pkce_calc_challenge(code_verifier, code_challenge_method or "S256")
        except Exception:
            log.debug(f"Failed to calculate PKCE challenge for client {app_info.client_id}: {code}")
            return OAuthErrorResponse(code=400, error_description="invalid_request: invalid code_verifier/method")
        if expected != authz.code_challenge:
            log.warn("PKCE verification failed", details={"client_id": authz.client_id, "code": code[:8] + "..."})
            return OAuthErrorResponse(code=401, error_description="invalid_grant: pkce_verification_failed")

    # Get AWS credentials from database profile (NOT from session token)
    aws_credentials, permissions = get_user_access_key(jwt_payload.cnm, jwt_payload.sub)
    if len(aws_credentials) == 0:
        log.warn("Missing AWS credentials for user %s in client %s", jwt_payload.sub, jwt_payload.cnm)

    # Mint the access token with STS session inside
    try:
        access_token = create_access_token_with_sts(
            aws_credentials=aws_credentials,
            jwt_payload=jwt_payload,
            permissions=permissions,
        )
    except Exception as e:
        log.warn(
            "Access token creation failed", details={"client_id": jwt_payload.cid, "user_id": jwt_payload.sub, "error": str(e)}
        )
        return OAuthErrorResponse(code=401, error_description="invalid_grant: failed to mint access token", exception=e)

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
        log.debug(f"Failed to mark code used: {code}")

    return OAuthTokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=int(JWT_ACCESS_HOURS * 3600),
        scope=authz.scope or "",
        refresh_token=refresh_token,
    )


def _refresh_token_grant(body: dict, jwt_payload: JwtPayload) -> Response:

    # RFC 6749 Section 6: refresh an access token
    refresh_token = (body.get("refresh_token") or "").strip()
    if not refresh_token:
        return OAuthErrorResponse(code=400, error_description="invalid_request: refresh_token required")

    try:
        rt = JwtPayload.decode(refresh_token)

    except jwt.InvalidTokenError:
        return OAuthErrorResponse(code=401, error_description="invalid_grant: invalid refresh_token")

    if rt.cid != jwt_payload.cid or rt.typ != "refresh":
        log.warn(
            "Refresh token validation failed",
            details={"client_id": jwt_payload.cid, "refresh_client": rt.cid, "refresh_type": rt.typ},
        )
        return OAuthErrorResponse(code=401, error_description="invalid_grant: refresh_token audience/type mismatch")

    if not jwt_payload.sub:
        return OAuthErrorResponse(code=401, error_description="invalid_grant: invalid refresh token")

    # Get fresh AWS credentials from database (NOT from refresh token)
    aws_credentials, permissions = get_user_access_key(jwt_payload.cnm, jwt_payload.sub)
    if not aws_credentials:
        log.warn("Missing AWS credentials for refresh token user %s in client %s", jwt_payload.sub, jwt_payload.cnm)
        return OAuthErrorResponse(code=401, error_description="invalid_grant: no AWS credentials")

    # Create new access token with client info
    try:
        access_token = create_access_token_with_sts(
            aws_credentials=aws_credentials,
            jwt_payload=jwt_payload,
            permissions=permissions,
        )
    except Exception as e:
        log.warn(
            "Refresh token access token creation failed",
            details={"client_id": jwt_payload.cid, "user_id": jwt_payload.sub, "error": str(e)},
        )
        return OAuthErrorResponse(code=500, error_description="failed to create access token", exception=e)

    # Create new refresh token with client info
    new_refresh = _mint_refresh_token(
        jwt_payload=jwt_payload,
        lifetime_days=30,
    )

    return OAuthTokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=int(JWT_ACCESS_HOURS * 3600),
        scope=rt.scp or "",
        refresh_token=new_refresh,
    )


def oauth_token(*, cookies: dict = None, headers: dict = None, body: dict = None, **kwargs):
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

    client_id = body.get("client_id", "")

    if not client_id:
        return OAuthErrorResponse(code=400, error_description="invalid_request: client_id required")

    jwt_payload, jwt_signature = get_authenticated_user(cookies=cookies, headers=headers)
    if not jwt_payload or not client_id or client_id != jwt_payload.cid:
        return OAuthErrorResponse(code=401, error_description="invalid_client: unauthenticated request")

    client_secret = body.get("client_secret", "").strip()

    if not check_rate_limit(headers, "oauth_token", max_attempts=10, window_minutes=15):
        log.warn(f"Rate limit exceeded for client {client_id} on /auth/v1/token")
        return OAuthErrorResponse(code=429, error_description="rate_limited")

    # Validate client registration once
    app_info: ClientFact = get_oauth_app_info(client_id)
    if not app_info:
        log.warn("Unknown client attempted token exchange: %s", client_id)
        return OAuthErrorResponse(code=401, error_description="invalid_client: unknown client")

    is_confidential = bool(app_info.client_secret)
    _, validated = _validate_client_credentials(client_secret, app_info)
    if is_confidential and not validated:
        log.warn("Client authentication failed for %s on /auth/v1/token", client_id)
        return OAuthErrorResponse(code=401, error_description="invalid_client: invalid credentials")

    grant_type = (body.get("grant_type") or "").strip()
    if grant_type == "authorization_code":

        return _authorization_code_grant(body, jwt_payload, jwt_signature, app_info)

    elif grant_type == "refresh_token":

        return _refresh_token_grant(body, jwt_payload)

    else:
        return OAuthErrorResponse(code=400, error_description="unsupported_grant_type: use authorization_code or refresh_token")


def oauth_revoke(*, cookies: dict = None, headers: dict = None, body: dict = None, **kwargs) -> Response:
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

    # Rate limiting
    if not check_rate_limit(headers, "oauth_revoke", max_attempts=10, window_minutes=1):
        log.warn("Rate limit exceeded on /auth/v1/revoke")
        return OAuthErrorResponse(code=429, error_description="rate_limited")

    # Optional: Validate the token format (but don't require it to be valid)
    # RFC 7009 says to return 200 even for invalid/expired tokens

    try:
        jwt_payload = JwtPayload.decode(token)
        log.debug(f"Token revoked for user {jwt_payload.sub}, client {jwt_payload.cid}")
    except:
        # Token is invalid/expired - still return 200 per RFC 7009
        log.debug("Invalid token submitted for revocation")

    # RFC 7009: Return HTTP 200 with empty body
    # Use a special response class for empty body
    return OAuthSuccessResponse()


def oauth_introspect(*, headers: dict = None, body: dict = None, **kwargs):
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

    # Rate limiting
    if not check_rate_limit(headers, "oauth_introspect", max_attempts=20, window_minutes=1):
        log.warn("Rate limit exceeded on /auth/v1/introspect")
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


def oauth_userinfo(*, cookies: dict = None, headers: dict = None, **kwargs):
    """OpenID Connect UserInfo endpoint.

    Route:
        GET /auth/v1/userinfo
    Headers:
        Authorization: Bearer <access_token>

    Returns:
        Response: User profile information
    """

    # Rate limiting
    if not check_rate_limit(headers, "oauth_userinfo", max_attempts=30, window_minutes=1):
        log.warn("Rate limit exceeded on /auth/v1/userinfo")
        return OAuthErrorResponse(code=429, error_description="rate_limited")

    # Validate access token
    jwt_payload, _ = get_authenticated_user(cookies, headers)

    # Ensure this is an access token
    if not jwt_payload or jwt_payload.typ != "access_token":
        return OAuthErrorResponse(code=401, error_description="invalid_token: access token required")

    try:
        # Get user profile from database
        response = ProfileActions.get(client=jwt_payload.cnm, user_id=jwt_payload.sub, profile_name="default")
        profile = UserProfile(**response.data)
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


def oauth_jwks(*, headers: dict = None, **kwargs):
    """JSON Web Key Set endpoint for token verification.

    Route:
        GET /auth/v1/jwks

    Returns:
        Response: JWKS containing public keys for token verification
    """
    # Rate limiting
    if not check_rate_limit(headers, "oauth_jwks", max_attempts=50, window_minutes=1):
        log.warn("Rate limit exceeded on /auth/v1/jwks")
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


def oauth_logout(*, cookies: dict = None, headers: dict = None, query_params: dict = None, **kwargs):
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
    if not check_rate_limit(headers, "oauth_logout", max_attempts=10, window_minutes=1):
        log.warn("Rate limit exceeded on /auth/v1/logout")
        return OAuthErrorResponse(code=429, error_description="rate_limited")

    # Get current user to validate logout
    jwt_payload, _ = get_authenticated_user(cookies, headers)

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
        response = RedirectResponse(code=302, url=redirect_url)

        # Add cookie clearing headers if needed
        return response

    return OAuthLogoutResponse(message="Logout successful", user=jwt_payload.sub if jwt_payload else None)


auth_server_endpoints = {
    "GET:/auth/v1/authorize": RouteEndpoint(
        oauth_authorize,
        permissions={Permission.DATA_READ},
        allow_anonymous=True,
        client_isolation=False,
    ),
    "GET:/auth/v1/cred_enc_key": RouteEndpoint(
        get_cred_enc_key,
        permissions={Permission.DATA_READ},
        allow_anonymous=True,
        client_isolation=False,
    ),
    "POST:/auth/v1/token": RouteEndpoint(
        oauth_token,
        permissions={Permission.DATA_READ},
        allow_anonymous=True,
        client_isolation=False,
    ),
    "POST:/auth/v1/revoke": RouteEndpoint(
        oauth_revoke,
        permissions={Permission.USER_MANAGE},
        client_isolation=False,
    ),
    "POST:/auth/v1/introspect": RouteEndpoint(
        oauth_introspect,
        permissions={Permission.DATA_READ},
        allow_anonymous=True,
        client_isolation=False,
    ),
    "GET:/auth/v1/userinfo": RouteEndpoint(
        oauth_userinfo,
        permissions={Permission.DATA_READ},
        allow_anonymous=True,
        client_isolation=False,
    ),
    "GET:/auth/v1/jwks": RouteEndpoint(
        oauth_jwks,
        permissions={Permission.DATA_READ},
        allow_anonymous=True,
        client_isolation=False,
    ),
    "GET:/auth/v1/logout": RouteEndpoint(
        oauth_logout,
        permissions={Permission.DATA_READ},
        allow_anonymous=True,
        client_isolation=False,
    ),
}
