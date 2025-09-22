from typing import ChainMap

import os
import uuid
import httpx
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import jwt

import core_logging as log

from core_db.registry.client import ClientFact, ClientActions
from core_db.profile import UserProfile, ProfileActions
from core_db.exceptions import NotFoundException, UnknownException

from ..request import RouteEndpoint
from ..security import Permission
from ..response import SuccessResponse, Response, RedirectResponse

from ..constants import (
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_REDIRECT_URI,
)

from .tools import (
    JwtPayload,
    cookie_opts,
    check_rate_limit,
    emit_session_cookie,
    api_url,
)

OAUTH_PARAMS_SUBJECT = "github-signin"
OAUTH_PARAMS_TYPE = "oauth-params"

###########################################################
#
# THIS FILE IS RUN INSIDE A LAMBDA FUNCTION IT IS NOT A
# FASTAPI ASYNC HANDLER
#
###########################################################


def _make_state() -> str:
    """Generate a cryptographically random OAuth state value."""
    return uuid.uuid4().hex


def _mock_enabled() -> bool:
    return os.getenv("SCK_MOCK_GITHUB", "0").lower() in ("1", "true", "yes")


def _exchange_github_token(code: str) -> str:
    """Exchange the authorization code for a GitHub access token.

    Returns the access token string or raises an Exception.
    """
    with httpx.Client(timeout=10) as client:
        token_res = client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": GITHUB_REDIRECT_URI,
            },
        )

    if token_res.status_code != 200:
        raise RuntimeError(f"token_exchange_status:{token_res.status_code}")

    token_json = token_res.json()
    gh_access_token = token_json.get("access")
    if not gh_access_token:
        raise ValueError("no_access_token")
    return gh_access_token


def _fetch_github_user(gh_access_token: str) -> tuple[dict, str | None]:
    """Fetch GitHub user and primary verified email.

    Returns (gh_user_dict, primary_email_or_None) or raises Exception.
    """
    with httpx.Client(timeout=10) as client:
        user_res = client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {gh_access_token}",
                "Accept": "application/vnd.github+json",
            },
        )
        email_res = client.get(
            "https://api.github.com/user/emails",
            headers={
                "Authorization": f"Bearer {gh_access_token}",
                "Accept": "application/vnd.github+json",
            },
        )

    if user_res.status_code != 200:
        raise RuntimeError(f"user_fetch_status:{user_res.status_code}")

    gh_user = user_res.json()
    emails = email_res.json() if email_res.status_code == 200 else []
    primary_email = next(
        (e.get("email") for e in emails if e.get("primary") and e.get("verified")),
        gh_user.get("email"),
    )
    return gh_user, primary_email


def _mock_github_profile(query_params: dict) -> tuple[dict, str, str]:
    """Synthesize a mock GitHub profile for dev/testing."""
    primary_email = query_params.get("mock_email") or "mockuser@example.com"
    gh_user = {
        "id": "mock-12345",
        "login": "mockuser",
        "name": "Mock User",
        "email": primary_email,
    }
    user_id = primary_email
    return gh_user, primary_email, user_id


def github_login(*, query_params: dict = None, body: dict = None, **kwargs) -> RedirectResponse:
    """Initiate GitHub OAuth login flow.

    Route:
        POST /auth/github/login

    Behavior:
        1. Extracts OAuth parameters from the request body (falls back to query if absent)
        2. Validates required OAuth parameters (client_id, response_type, redirect_uri)
        3. Stores OAuth parameters and state in secure cookies
        4. Redirects DIRECTLY to GitHub for authentication (not loading page)

    Body Parameters (JSON or form):
        returnTo (str, optional): Final destination after OAuth flow completion.
                                 Defaults to "/dashboard".
        client_id (str): OAuth client identifier (required for OAuth flow).
        response_type (str): OAuth response type (required for OAuth flow).
        redirect_uri (str): OAuth callback URI (required for OAuth flow).
        scope (str, optional): Requested OAuth scopes.
        state (str, optional): OAuth state parameter for security.
        code_challenge (str, optional): PKCE code challenge.
        code_challenge_method (str, optional): PKCE challenge method.

    Returns:
        RedirectResponse: Direct redirect to GitHub OAuth authorization
    """
    try:
        # Prefer POST body params; fall back to query if not provided
        params = ChainMap(body or {}, query_params or {})

        # Validate OAuth parameters and create JWT token (includes client_id)
        oauth_params = get_oauth_params_token(params)

        # Generate state for GitHub OAuth
        github_state = _make_state()

        # Capture the final destination
        return_to = params.get("returnTo", "/dashboard")

        # Build GitHub authorization URL
        github_params = {
            "client_id": GITHUB_CLIENT_ID,
            "redirect_uri": GITHUB_REDIRECT_URI,
            "scope": "read:user user:email",
            "state": github_state,
        }
        mock_github = os.getenv("SCK_MOCK_GITHUB", "0").lower() in ("1", "true", "yes")
        if mock_github:
            # In dev, Vite runs at 8080; serve a local mock authorize endpoint there
            gh_auth_url = f"http://localhost:8080/mock_github_oauth?{urlencode(github_params)}"
        else:
            gh_auth_url = f"https://github.com/login/oauth/authorize?{urlencode(github_params)}"

        log.info(
            "GitHub OAuth flow initiated",
            details={"return_to": return_to, "has_oauth_params": bool(oauth_params), "github_state": github_state[:8] + "..."},
        )

        # Create 302 redirect response to GitHub and store OAuth flow parameters for callback
        resp = RedirectResponse(url=gh_auth_url)
        resp.set_cookie("github_oauth_state", github_state, max_age=10 * 60, **cookie_opts())
        resp.set_cookie("github_return_to", return_to, max_age=10 * 60, **cookie_opts())
        resp.set_cookie("github_oauth_params", oauth_params, max_age=10 * 60, **cookie_opts())
        return resp

    except ValueError as e:
        log.warn("Invalid OAuth parameters for GitHub login: %s", str(e))
        return RedirectResponse(url="/error?error=server_error&redirect=/login")
    except Exception as e:
        log.warn("GitHub login initiation failed: %s", str(e))
        return RedirectResponse(url="/error?error=temporarily_unavailable&redirect=/login")


def github_callback(
    *,
    cookies: dict = None,
    headers: dict = None,
    query_params: dict = None,
    **kwargs,
) -> Response:
    """Complete GitHub OAuth flow and integrate with OAuth server.

    Route:
        GET /auth/github/callback

    Behavior:
        1. Validates OAuth state and cookies before making any GitHub API calls
        2. Exchanges GitHub authorization code for user access token
        3. Fetches user profile and email information from GitHub API
        4. Creates or retrieves user profile in the database
        5. Creates session JWT for OAuth server integration
        6. Redirects to OAuth authorize endpoint to continue OAuth flow

    Returns:
        RedirectResponse:
            - Success: Redirect to /auth/v1/authorize with session token
            - Error: Redirect to /login with error parameters
    """

    # Rate limiting first (before any processing)
    if not check_rate_limit(headers, "github_oauth", max_attempts=10, window_minutes=15):
        log.warn("Rate limit exceeded for GitHub OAuth callback")
        return RedirectResponse(url="/error?error=rle&redirect=/login")

    # 1. VALIDATE COOKIES FIRST - fail fast before any GitHub API calls
    github_oauth_params = cookies.get("github_oauth_params")
    github_state = cookies.get("github_oauth_state")

    # cookies must have been set!
    if not github_state or not github_oauth_params:
        log.warn("GitHub OAuth callback missing required state cookie")
        return RedirectResponse(url="/error?error=isf&redirect=/login")

    # Validate OAuth parameters JWT
    try:
        jwt_payload = JwtPayload.decode(github_oauth_params)
        if jwt_payload.typ != OAUTH_PARAMS_TYPE or jwt_payload.sub != OAUTH_PARAMS_SUBJECT:
            raise ValueError("Invalid JWT type or subject")
    except (jwt.InvalidTokenError, ValueError) as e:
        log.warn("GitHub OAuth state cookie is invalid: %s", str(e))
        return RedirectResponse(url="/error?error=isf&redirect=/login")

    # Validate GitHub OAuth state
    code = query_params.get("code")
    state = query_params.get("state")
    if not code or not state or state != github_state:
        log.warn(
            "GitHub OAuth state validation failed",
            details={
                "has_code": bool(code),
                "has_state": bool(state),
                "state_match": state == github_state if state and github_state else False,
            },
        )
        return RedirectResponse(url="/error?error=isf&redirect=/login")

    # 2-3. Get user identity (mock or real)
    try:
        if _mock_enabled():
            gh_user, primary_email, user_id = _mock_github_profile(query_params)
            log.info("MOCK GitHub OAuth used; synthesizing user", details={"user_id": user_id})
        else:
            gh_access_token = _exchange_github_token(code)
            gh_user, primary_email = _fetch_github_user(gh_access_token)
            user_id = primary_email or f"github:{gh_user.get('id')}"
            if not user_id:
                log.warn("Could not determine user ID from GitHub response")
                return RedirectResponse(url="/error?error=server_error&redirect=/login")
            log.info(
                "GitHub user authenticated",
                details={"user_id": user_id, "github_id": gh_user.get("id"), "has_verified_email": bool(primary_email)},
            )
    except RuntimeError as re:
        msg = str(re)
        if msg.startswith("token_exchange_status:"):
            status = int(msg.split(":", 1)[1])
            log.warn("GitHub token exchange failed with status %d", status)
            # User-actionable: authorization code expired/invalid, or app denied
            if status in (400, 401, 403):
                # Prompt the user to retry GitHub sign-in
                return RedirectResponse(url="/error?error=ghe_invalid_code&redirect=/login")
            # Upstream outage or unexpected
            if status >= 500:
                return RedirectResponse(url="/error?error=temporarily_unavailable&redirect=/login")
            # Fallback generic GitHub token error
            return RedirectResponse(url="/error?error=ghe_token&redirect=/login")
        if msg.startswith("user_fetch_status:"):
            status = int(msg.split(":", 1)[1])
            log.warn("GitHub user fetch failed with status %d", status)
            # 401: token invalid/expired -> user should retry auth
            if status == 401:
                return RedirectResponse(url="/error?error=ghe_reauth&redirect=/login")
            # 403: insufficient scopes -> configuration issue visible to user
            if status == 403:
                return RedirectResponse(url="/error?error=ghe_scope&redirect=/login")
            # 5xx: GitHub outage
            if status >= 500:
                return RedirectResponse(url="/error?error=temporarily_unavailable&redirect=/login")
            # Other non-OK statuses
            return RedirectResponse(url="/error?error=ghe_user&redirect=/login")
        log.warn("GitHub OAuth processing failed: %s", msg)
        return RedirectResponse(url="/error?error=ghe_unknown&redirect=/login")
    except Exception as e:
        log.warn("GitHub OAuth processing failed: %s", str(e))
        return RedirectResponse(url="/error?error=ghe_unknown&redirect=/login")

    # 4. VALIDATE CLIENT AND GET USER PROFILE
    client_id = jwt_payload.cid
    client = jwt_payload.cnm

    try:
        app_info = ClientActions.get(client=client)
    except Exception as e:
        log.warn("GitHub OAuth callback with unknown client_id: %s", client_id)
        return RedirectResponse(url="/error?error=cid&redirect=/login")

    if app_info.client_id != client_id:
        log.warn("GitHub OAuth callback client_id does not match client record: %s", client_id)
        return RedirectResponse(url="/error?error=cid&redirect=/login")

    # 5. CREATE OR UPDATE USER PROFILE
    try:

        _get_or_create_user_profile(client, user_id, gh_user, primary_email)

    except Exception as e:
        log.warn("Failed to create profile for GitHub user %s: %s", user_id, str(e))
        # Surface a user-visible error so Login can display a specific message
        return RedirectResponse(url="/error?error=upro&redirect=/login")

    # 6. CREATE SESSION JWT AND REDIRECT TO OAUTH FLOW
    try:

        # Build OAuth authorize URL with preserved parameters
        oauth_params = {
            "response_type": jwt_payload.rty,
            "client_id": jwt_payload.cid,
            "scope": jwt_payload.scp,
            "redirect_uri": jwt_payload.rdu,
        }

        # Preserve original state from initial OAuth request, if provided and well-formed
        if jwt_payload.sid:
            try:
                sid = str(jwt_payload.sid)
                if sid and len(sid) <= 512 and sid.isprintable():
                    oauth_params["state"] = sid
            except Exception:
                # Omit state if formatting is invalid
                pass

        # Add PKCE if it was in original request
        if jwt_payload.cch:
            oauth_params["code_challenge"] = jwt_payload.cch
            oauth_params["code_challenge_method"] = jwt_payload.ccm

        oauth_url = f"/auth/v1/authorize?{urlencode(oauth_params)}"
        oauth_url = api_url(oauth_url)

        log.info(
            "GitHub OAuth completed, redirecting to OAuth server",
            details={
                "user_id": user_id,
                "client": client,
                "oauth_url": oauth_url.split("?")[0],  # Log endpoint, not full URL with params
            },
        )

        # Create redirect response to OAuth server with session cookie
        resp: RedirectResponse = emit_session_cookie(
            RedirectResponse(url=oauth_url),
            client_id,
            client,
            user_id,
        )

        # Clean up GitHub OAuth cookies
        resp.delete_cookie("github_oauth_state", path="/")
        resp.delete_cookie("github_return_to", path="/")
        resp.delete_cookie("github_oauth_params", path="/")
        resp.delete_cookie("github_auth_url", path="/")

        return resp

    except Exception as e:
        log.warn("GitHub OAuth session creation failed: %s", str(e))
        return RedirectResponse(url="/error?error=server_error&redirect=/login")


def _get_or_create_user_profile(client: str, user_id: str, gh_user: dict, primary_email: str | None) -> UserProfile:

    try:

        profile = ProfileActions.get(client=client, user_id=user_id, profile_name="default")
        log.debug("Loaded existing profile for GitHub user %s", user_id)
        return profile

    except NotFoundException as e:

        """Create a new user profile in the database."""
        user_profile = {
            "user_id": user_id,
            "profile_name": "default",
            "email": primary_email or "",
            "first_name": (gh_user.get("name", "").split(" ")[0] if gh_user.get("name") else ""),
            "last_name": (
                " ".join(gh_user.get("name", "").split(" ")[1:]) if gh_user.get("name") and " " in gh_user.get("name", "") else ""
            ),
            "permissions": [str(Permission.DATA_READ), str(Permission.DATA_WRITE)],
        }

        try:

            profile = ProfileActions.create(client=client, **user_profile)
            log.info("Created new profile for GitHub user %s", user_id)
            return profile

        except Exception as e:
            log.warn("Failed to create profile for GitHub user %s: %s", user_id, str(e))
            raise UnknownException(f"Error creating user profile") from e

    except Exception as e:
        log.warn("Failed to create profile for GitHub user %s: %s", user_id, str(e))
        raise UnknownException(f"Error creating user profile") from e


def get_oauth_params_token(query_params: dict) -> str:
    """Create JWT token containing OAuth flow parameters for preservation across GitHub OAuth.

    This function extracts OAuth parameters from the request and encodes them into a JWT
    token that can be stored in cookies during the GitHub OAuth flow.

    Args:
        query_params (dict): Query parameters from the request

    Returns:
        str: JWT token string containing encoded OAuth parameters

    Raises:
        ValueError: If required OAuth parameters are missing or invalid
    """
    client_id = query_params.get("client_id", "")
    client = query_params.get("client", "")
    response_type = query_params.get("response_type", "code")
    redirect_uri = query_params.get("redirect_uri", "")
    scope = query_params.get("scope", "")
    state = query_params.get("state", "")
    code_challenge = query_params.get("code_challenge", "")
    code_challenge_method = query_params.get("code_challenge_method", "")

    # Validate required OAuth parameters
    if not client_id:
        raise ValueError("Missing required OAuth parameter: client_id")

    if not response_type:
        raise ValueError("Missing required OAuth parameter: response_type")

    if not redirect_uri:
        raise ValueError("Missing required OAuth parameter: redirect_uri")

    # Validate response_type value
    if response_type not in ["code", "token", "id_token"]:
        raise ValueError(f"Invalid response_type: {response_type}")

    # Validate PKCE parameters
    if code_challenge and not code_challenge_method:
        raise ValueError("Missing code_challenge_method when code_challenge is provided")

    if code_challenge_method and not code_challenge:
        raise ValueError("Missing code_challenge when code_challenge_method is provided")

    if code_challenge_method and code_challenge_method not in ["S256", "plain"]:
        raise ValueError(f"Invalid code_challenge_method: {code_challenge_method}")

    iat = int(datetime.now(timezone.utc).timestamp())
    exp = int((datetime.now(timezone.utc) + timedelta(minutes=10)).timestamp())

    try:
        jwt_token = JwtPayload(
            sub=OAUTH_PARAMS_SUBJECT,
            typ=OAUTH_PARAMS_TYPE,
            cid=client_id,
            cnm=client,
            scp=scope,
            iat=iat,
            exp=exp,
            sid=state,
            rty=response_type,
            rdu=redirect_uri,
            cch=code_challenge,
            ccm=code_challenge_method,
        )

        return jwt_token.encode()
    except Exception as e:
        raise ValueError(f"Failed to create OAuth parameters token: {str(e)}")


auth_github_endpoints: dict[str, RouteEndpoint] = {
    "POST:/auth/github/login": RouteEndpoint(github_login, allow_anonymous=True, client_isolation=False),
    "GET:/auth/github/callback": RouteEndpoint(github_callback, allow_anonymous=True, client_isolation=False),
}
