import uuid
import httpx
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import jwt
import core_logging as log

from core_db.response import SuccessResponse, RedirectResponse
from core_db.registry.client import ClientFact, ClientActions
from core_db.profile import UserProfile, ProfileActions

from core_api.request import RouteEndpoint

from .constants import (
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_REDIRECT_URI,
    SCK_TOKEN_COOKIE_NAME,
    SCK_TOKEN_SESSION_MINUTES,
)

from .tools import (
    JwtPayload,
    create_basic_session_jwt,
    cookie_opts,
    check_rate_limit,
)

OAUTH_PARAMS_SUBJECT = "github-signin"
OAUTH_PARAMS_TYPE = "oauth-params"


def _make_state() -> str:
    """Generate a cryptographically random OAuth state value."""
    return uuid.uuid4().hex


async def github_login(*, query_params: dict = None, **kwargs) -> RedirectResponse:
    """Initiate GitHub OAuth login flow.

    Route:
        GET /auth/github/login

    Behavior:
        1. Extracts OAuth parameters from the request
        2. Validates required OAuth parameters (client_id, response_type, redirect_uri)
        3. Stores OAuth parameters and state in secure cookies
        4. Redirects DIRECTLY to GitHub for authentication (not loading page)

    Query Parameters:
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
        # Validate OAuth parameters and create JWT token
        oauth_params = get_oauth_params_token(query_params)

        # Generate state for GitHub OAuth
        github_state = _make_state()

        # Capture the final destination
        return_to = query_params.get("returnTo", "/dashboard")

        # Build GitHub authorization URL
        github_params = {
            "client_id": GITHUB_CLIENT_ID,
            "redirect_uri": GITHUB_REDIRECT_URI,
            "scope": "read:user user:email",
            "state": github_state,
        }
        gh_auth_url = f"https://github.com/login/oauth/authorize?{urlencode(github_params)}"

        # Create redirect response to GitHub
        resp = RedirectResponse(url=gh_auth_url, status_code=302)

        # Store OAuth flow parameters for callback
        resp.set_cookie("github_oauth_state", github_state, max_age=10 * 60, **cookie_opts())
        resp.set_cookie("github_return_to", return_to, max_age=10 * 60, **cookie_opts())
        resp.set_cookie("github_oauth_params", oauth_params, max_age=10 * 60, **cookie_opts())

        log.info(
            "GitHub OAuth flow initiated",
            details={"return_to": return_to, "has_oauth_params": bool(oauth_params), "github_state": github_state[:8] + "..."},
        )

        return resp

    except ValueError as e:
        log.warn("Invalid OAuth parameters for GitHub login: %s", str(e))
        return RedirectResponse(url="/login?error=invalid_oauth_params&msg=Invalid OAuth parameters", status_code=400)
    except Exception as e:
        log.warn("GitHub login initiation failed: %s", str(e))
        return RedirectResponse(url="/login?error=github_login_failed&msg=GitHub login failed to start", status_code=500)


async def github_callback(
    *,
    cookies: dict = None,
    headers: dict = None,
    query_params: dict = None,
    **kwargs,
):
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
        return RedirectResponse(
            url="/login?error=rate_limited&msg=Rate limit exceeded. Please try again later.",
            status_code=429,
        )

    # 1. VALIDATE COOKIES FIRST - fail fast before any GitHub API calls
    github_oauth_params = cookies.get("github_oauth_params")
    github_state = cookies.get("github_oauth_state")
    return_to = cookies.get("github_return_to", "/dashboard")

    if not github_state:
        log.warn("GitHub OAuth callback missing required state cookie")
        return RedirectResponse(
            url="/login?error=missing_state&msg=OAuth session expired. Please try signing in again.",
        )

    # Validate OAuth parameters JWT
    try:
        jwt_payload = JwtPayload.decode(github_oauth_params)
        if jwt_payload.typ != OAUTH_PARAMS_TYPE or jwt_payload.sub != OAUTH_PARAMS_SUBJECT:
            raise ValueError("Invalid JWT type or subject")
    except (jwt.InvalidTokenError, ValueError) as e:
        log.warn("GitHub OAuth state cookie is invalid: %s", str(e))
        return RedirectResponse(
            url="/login?error=invalid_state&msg=Invalid authentication state. Please try signing in again.",
        )

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
        return RedirectResponse(
            url="/login?error=invalid_state&msg=Invalid authentication state. Please try signing in again.",
        )

    # 2. EXCHANGE CODE FOR GITHUB ACCESS TOKEN
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            token_res = await client.post(
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
            log.warn("GitHub token exchange failed with status %d", token_res.status_code)
            return RedirectResponse(
                url="/login?error=github_token_exchange_failed&msg=Failed to exchange GitHub token. Please try again.",
                status_code=502,
            )

        token_json = token_res.json()
        gh_access_token = token_json.get("access")
        if not gh_access_token:
            log.warn("No access token received from GitHub")
            return RedirectResponse(
                url="/login?error=no_access_token&msg=Failed to retrieve access token from GitHub. Please try again.",
                status_code=502,
            )

    except Exception as e:
        log.warn("GitHub token exchange failed: %s", str(e))
        return RedirectResponse(
            url="/login?error=github_token_exchange_failed&msg=GitHub OAuth processing failed. Please try again.",
            status_code=500,
        )

    # 3. FETCH USER DATA FROM GITHUB
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            user_res = await client.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {gh_access_token}",
                    "Accept": "application/vnd.github+json",
                },
            )
            email_res = await client.get(
                "https://api.github.com/user/emails",
                headers={
                    "Authorization": f"Bearer {gh_access_token}",
                    "Accept": "application/vnd.github+json",
                },
            )

        if user_res.status_code != 200:
            log.warn("GitHub user fetch failed with status %d", user_res.status_code)
            return RedirectResponse(
                url="/login?error=github_user_fetch_failed&msg=Failed to retrieve user information from GitHub. Please try again.",
                status_code=502,
            )

        gh_user = user_res.json()
        emails = email_res.json() if email_res.status_code == 200 else []

        # Extract primary verified email
        primary_email = next(
            (e["email"] for e in emails if e.get("primary") and e.get("verified")),
            gh_user.get("email"),
        )

        user_id = primary_email or f"github:{gh_user.get('id')}"
        if not user_id:
            log.warn("Could not determine user ID from GitHub response")
            return RedirectResponse(
                url="/login?error=no_user_id&msg=Failed to retrieve user ID from GitHub. Please try again.",
                status_code=502,
            )

        log.info(
            "GitHub user authenticated",
            details={"user_id": user_id, "github_id": gh_user.get("id"), "has_verified_email": bool(primary_email)},
        )

    except Exception as e:
        log.warn("GitHub user data fetch failed: %s", str(e))
        return RedirectResponse(
            url="/login?error=github_oauth_failed&msg=GitHub OAuth processing failed. Please try again.",
            status_code=500,
        )

    # 4. VALIDATE CLIENT AND GET USER PROFILE
    client_id = jwt_payload.cid

    try:
        response: SuccessResponse = ClientActions.get(client_id=client_id)
        app_info = ClientFact(**response.data)
    except Exception as e:
        log.warn("GitHub OAuth callback with unknown client_id: %s", client_id)
        return RedirectResponse(
            url="/login?error=unknown_client&msg=Unknown client ID. Please try again.",
            status_code=400,
        )

    client = app_info.client

    # 5. CREATE OR UPDATE USER PROFILE
    try:
        profile_response = ProfileActions.get(client=client, user_id=user_id, profile_name="default")
        user_profile = UserProfile(**profile_response.data)
        log.debug("Loaded existing profile for GitHub user %s", user_id)

    except Exception:
        # Profile doesn't exist - create new one
        log.info(
            "Creating new profile for GitHub user", details={"user_id": user_id, "client": client, "email": primary_email or ""}
        )

        user_profile = UserProfile(
            user_id=user_id,
            profile_name="default",
            email=primary_email or "",
            first_name=(gh_user.get("name", "").split(" ")[0] if gh_user.get("name") else ""),
            last_name=(
                " ".join(gh_user.get("name", "").split(" ")[1:]) if gh_user.get("name") and " " in gh_user.get("name", "") else ""
            ),
        )

        try:
            ProfileActions.create(client=client, **user_profile.model_dump())
        except Exception as create_error:
            log.warn("Failed to create profile for GitHub user %s: %s", user_id, str(create_error))
            return RedirectResponse(
                url="/login?error=profile_creation_failed&msg=Failed to create user profile",
                status_code=500,
            )

    # 6. CHECK AWS CREDENTIALS STATUS
    credentials = user_profile.credentials or {}
    aws_creds_status = "present" if "AwsCredentials" in credentials else "missing"

    # 7. CREATE SESSION JWT AND REDIRECT TO OAUTH FLOW
    try:
        minutes = int(SCK_TOKEN_SESSION_MINUTES)
        # Create session JWT for OAuth server (30 minute expiry)
        session_token = create_basic_session_jwt(client_id, client, user_id, minutes=minutes)

        # Create state parameter with AWS credential status
        credential_state = f"github_oauth:{aws_creds_status}"
        if jwt_payload.sid:
            credential_state = f"{credential_state}:{jwt_payload.sid}"

        # Build OAuth authorize URL with preserved parameters
        oauth_params = {
            "response_type": jwt_payload.rty,
            "client_id": jwt_payload.cid,
            "scope": jwt_payload.scp,
            "redirect_uri": jwt_payload.rdu,
            "state": credential_state,
        }

        # Add PKCE if it was in original request
        if jwt_payload.cch:
            oauth_params["code_challenge"] = jwt_payload.cch
            oauth_params["code_challenge_method"] = jwt_payload.ccm

        oauth_url = f"/auth/v1/authorize?{urlencode(oauth_params)}"

        log.info(
            "GitHub OAuth completed, redirecting to OAuth server",
            details={
                "user_id": user_id,
                "client": client,
                "aws_creds_status": aws_creds_status,
                "oauth_url": oauth_url.split("?")[0],  # Log endpoint, not full URL with params
            },
        )

        # Create redirect response to OAuth server
        resp = RedirectResponse(url=oauth_url, status_code=302)

        # Set session cookie for OAuth server
        resp.set_cookie(SCK_TOKEN_COOKIE_NAME, session_token, max_age=minutes * 60, **cookie_opts())

        # Clean up GitHub OAuth cookies
        resp.delete_cookie("github_oauth_state", path="/")
        resp.delete_cookie("github_return_to", path="/")
        resp.delete_cookie("github_oauth_params", path="/")
        resp.delete_cookie("github_auth_url", path="/")

        return resp

    except Exception as e:
        log.warn("GitHub OAuth session creation failed: %s", str(e))
        return RedirectResponse(
            url="/login?error=session_creation_failed&msg=Could not complete GitHub OAuth process",
            status_code=500,
        )


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

    jwt_token = JwtPayload(
        sub=OAUTH_PARAMS_SUBJECT,
        typ=OAUTH_PARAMS_TYPE,
        cid=client_id,
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


auth_github_endpoints: dict[str, RouteEndpoint] = {
    "GET:/auth/github/login": RouteEndpoint(github_login, allow_anonymous=True, client_isolation=False),
    "GET:/auth/github/callback": RouteEndpoint(github_callback, allow_anonymous=True, client_isolation=False),
}
