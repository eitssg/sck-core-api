import uuid
import httpx
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from fastapi import Response
from fastapi.responses import RedirectResponse

import jwt
import core_logging as log

from core_db.response import SuccessResponse
from core_db.registry.client import ClientFact, ClientActions
from core_db.profile import UserProfile, ProfileActions

from core_api.request import RouteEndpoint

from .constants import (
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_REDIRECT_URI,
    SCK_TOKEN_COOKIE_NAME,
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
        4. Redirects to React app loading page (/goto/github)
        5. React app will then redirect user to GitHub for authentication

    Query Parameters:
        returnTo (str, optional): Final destination after OAuth flow completion.
                                 Defaults to "/dashboard".
        - All other OAuth params will be preserved for the final OAuth flow
        client_id (str): OAuth client identifier (required for OAuth flow).
        response_type (str): OAuth response type (required for OAuth flow).
        redirect_uri (str): OAuth callback URI (required for OAuth flow).
        scope (str, optional): Requested OAuth scopes.
        state (str, optional): OAuth state parameter for security.
        code_challenge (str, optional): PKCE code challenge.
        code_challenge_method (str, optional): PKCE challenge method.

    Cookies Set:
        github_oauth_state: Random state for GitHub OAuth (10 min TTL).
        github_return_to: Final destination URL (10 min TTL).
        github_oauth_params: JWT containing OAuth parameters (10 min TTL).
        github_auth_url: Complete GitHub authorization URL (5 min TTL).

    Returns:
        RedirectResponse: Redirect to "/goto/github" loading page.
    """
    # Capture the final destination and OAuth parameters
    return_to = query_params.get("returnTo", "/dashboard")

    # Preserve OAuth parameters for later use
    oauth_params = get_oauth_params_token(query_params)

    # Generate state for GitHub OAuth
    github_state = _make_state()

    # Store the OAuth flow parameters for after GitHub auth
    resp = RedirectResponse(url="about:blank", status_code=302)

    resp.set_cookie("github_oauth_state", github_state, max_age=10 * 60, **cookie_opts())
    resp.set_cookie("github_return_to", return_to, max_age=10 * 60, **cookie_opts())

    # Store OAuth params if they exist (for OAuth flow after GitHub auth)
    resp.set_cookie("github_oauth_params", oauth_params, max_age=10 * 60, **cookie_opts())

    # Redirect to GitHub
    github_params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_REDIRECT_URI,
        "scope": "read:user user:email",
        "state": github_state,
    }
    gh_auth_url = f"https://github.com/login/oauth/authorize?{urlencode(github_params)}"

    # Redirect to your React app's loading page
    resp = RedirectResponse(url="/goto/github", status_code=302)

    # Store all the data React app needs
    resp.set_cookie("github_oauth_state", github_state, max_age=10 * 60, **cookie_opts())
    resp.set_cookie("github_return_to", return_to, max_age=10 * 60, **cookie_opts())
    resp.set_cookie("github_oauth_params", oauth_params, max_age=10 * 60, **cookie_opts())

    # For my react application to forward to github
    resp.set_cookie("github_auth_url", gh_auth_url, max_age=5 * 60, **cookie_opts())  # Short TTL

    log.debug(f"Redirecting to loading page, GitHub URL prepared: {gh_auth_url}")
    return resp


async def github_callback(
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
        5. Checks AWS credential status for the user
        6. Creates session JWT for OAuth server integration
        7. Redirects to OAuth authorize endpoint with credential status

    Query Parameters:
        code (str): Authorization code from GitHub (required).
        state (str): OAuth state parameter for validation (required).

    Required Cookies:
        github_oauth_state: State for validation against query parameter.
        github_oauth_params: JWT containing original OAuth parameters.
        github_return_to: Final destination URL.

    Error Handling:
        All errors redirect to /login with query parameters:
        - error: Error code for categorization
        - msg: User-friendly error message

    Returns:
        RedirectResponse:
            - Success: Redirect to /auth/v1/authorize with session token
            - Error: Redirect to /login with error parameters

    Cookies Set (Success):
        sck_token: Session JWT for OAuth server authentication (30 min TTL).

    Cookies Deleted:
         4. Create session JWT for your OAuth server
         5. Redirect to OAuth authorize endpoint with credential status in state
    """

    #################################################
    # Now start setting by validating our cookie
    # If it doen't have the values we need, no point
    # contacting the GitHub API
    #################################################

    # 1. VALIDATE COOKIES FIRST - fail fast before any GitHub API calls
    github_oauth_params = cookies.get("github_oauth_params")
    github_state = cookies.get("github_oauth_state")
    return_to = cookies.get("github_return_to")

    if not github_state:
        log.warning("GitHub OAuth callback missing required state cookie")
        return RedirectResponse(
            url="/login?error=missing_state&msg=OAuth session expired. Please try signing in again.",
            status_code=302,
        )

    try:
        jwt_payload = JwtPayload.decode(github_oauth_params)
        if jwt_payload.typ != OAUTH_PARAMS_TYPE or jwt_payload.sub != OAUTH_PARAMS_SUBJECT:
            raise ValueError("GitHub OAuth state cookie has invalid type or subject")
    except (jwt.InvalidTokenError, ValueError) as e:
        log.warning(f"GitHub OAuth state cookie is invalid: {e}")
        return RedirectResponse(
            url="/login?error=invalid_state&msg=Invalid authentication state. Please try signing in again.",
            status_code=302,
        )

    # Validate GitHub OAuth state

    code = query_params.get("code")
    state = query_params.get("state")
    if not code or not state or not github_state or state != github_state:
        log.warning("GitHub OAuth state validation failed")
        return RedirectResponse(
            url="/login?error=invalid_state&msg=Invalid authentication state. Please try signing in again.",
            status_code=302,
        )

    try:
        # Exchange code for GitHub access token
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
            log.error(f"GitHub token exchange failed: {token_res.status_code}")
            return RedirectResponse(
                url="/login?error=github_token_exchange_failed&msg=Failed to exchange GitHub token. Please try again.",
                status_code=502,
            )

        token_json = token_res.json()
        gh_access_token = token_json.get("access_token")
        if not gh_access_token:
            log.error("No access token received from GitHub")
            return RedirectResponse(
                url="/login?error=no_access_token&msg=Failed to retrieve access token from GitHub. Please try again.",
                status_code=502,
            )

        # Fetch user data from GitHub
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
            log.error(f"GitHub user fetch failed: {user_res.status_code}")
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
            log.error("Could not determine user ID from GitHub response")
            return RedirectResponse(
                url="/login?error=no_user_id&msg=Failed to retrieve user ID from GitHub. Please try again.",
                status_code=502,
            )

        log.debug(f"GitHub OAuth completed for user: {user_id}")

    except Exception as e:
        log.error(f"GitHub OAuth callback failed: {e}")
        return RedirectResponse(
            url="/login?error=github_oauth_failed&msg=GitHub OAuth processing failed. Please try again.",
            status_code=500,
        )

    #########################################
    # Now start setting up our JWT token
    #########################################

    if not check_rate_limit(headers, "github_oauth", max_attempts=10, window_minutes=15):
        log.warning("Rate limit exceeded for GitHub OAuth callback")
        return RedirectResponse(
            url="/login?error=rate_limited&msg=Rate limit exceeded. Please try again later.",
            status_code=429,
        )

    if not return_to:
        log.warning("GitHub OAuth callback missing return_to cookie, using default")
        return_to = "/dashboard"  # Graceful fallback

    client_id = jwt_payload.cid

    try:
        response: SuccessResponse = ClientActions.get(client_id=client_id)()
        app_info = ClientFact(**response.data)
    except Exception as e:
        log.warning(f"GitHub OAuth callback with unknown client_id '{client_id}': {e}")
        return RedirectResponse(
            url="/login?error=unknown_client&msg=Unknown client ID. Please try again.",
            status_code=400,
        )

    client = app_info.client

    try:
        # Fixed: Add client="core" parameter
        profile_response = ProfileActions.get(client=client, user_id=user_id, profile_name="default")
        user_profile = UserProfile(**profile_response.data)

        log.debug(f"Loaded existing profile for GitHub user {user_id}")

    except Exception as e:
        # Profile doesn't exist - create new one
        log.debug(f"Profile not found for GitHub user {user_id}, creating new profile: {e}")

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
            # Fixed: Add client="core" parameter
            ProfileActions.create(client=client, **user_profile.dict())
        except Exception as create_error:
            log.error(f"Failed to create profile for GitHub user {user_id}: {create_error}")
            return RedirectResponse(
                url="/login?error=profile_creation_failed&msg=Failed to create user profile",
                status_code=500,
            )

        log.debug(f"Created new profile for GitHub user {user_id}")

    credentials = user_profile.credentials or {}

    if "AwsCredentials" not in credentials:
        aws_creds_status = "missing"  # New user needs credentials
    else:
        aws_creds_status = "present"

    try:

        # Create session JWT for your OAuth server (identity only, no AWS credentials)
        session_token = create_basic_session_jwt(client_id, client, user_id, minutes=30)

        # Create state parameter with AWS credential status
        # Format: "github_oauth:{aws_status}:{original_state}"
        credential_state = f"github_oauth:{aws_creds_status}"
        if jwt_payload.sid:
            credential_state = f"{credential_state}:{jwt_payload.sid}"

        # Default OAuth parameters for your server
        default_oauth_params = {
            "response_type": jwt_payload.rty,
            "client_id": jwt_payload.cid,
            "scope": jwt_payload.scp,
            "redirect_uri": jwt_payload.rdu,
            "state": credential_state,
        }

        # Add PKCE if it was in original request
        if jwt_payload.cch:
            default_oauth_params["code_challenge"] = jwt_payload.cch
            default_oauth_params["code_challenge_method"] = jwt_payload.ccm

        # Construct OAuth authorize URL
        oauth_url = f"/auth/v1/authorize?{urlencode(default_oauth_params)}"

        log.debug(f"Redirecting to OAuth server with state '{credential_state}': {oauth_url}")

        # Redirect to your OAuth server with session token
        resp = RedirectResponse(url=oauth_url, status_code=302)

        # Set session cookie for OAuth server
        resp.set_cookie(SCK_TOKEN_COOKIE_NAME, session_token, max_age=30 * 60, **cookie_opts())

        # Clean up GitHub OAuth cookies
        resp.delete_cookie("github_oauth_state", path="/")
        resp.delete_cookie("github_return_to", path="/")
        resp.delete_cookie("github_oauth_params", path="/")

        return resp

    except Exception as e:
        log.error(f"GitHub OAuth callback failed: {e}")
        return RedirectResponse(
            url="/login?error=app_error&msg=Could not complete GitHub OAuth process",
            status_code=429,
        )


def get_oauth_params_token(query_params: dict) -> str:
    """Create JWT token containing OAuth flow parameters for preservation across GitHub OAuth.

    This function extracts OAuth parameters from the request and encodes them into a JWT
    token that can be stored in cookies during the GitHub OAuth flow. This ensures that
    the original OAuth flow parameters are preserved when GitHub redirects back to the
    callback endpoint.

    Args:
        request (Request): The FastAPI request object containing query parameters.

    Returns:
         str: The token string for the OAuth parameters.
        str: JWT token string containing encoded OAuth parameters with 10-minute expiration.

    Raises:
        ValueError: If any required OAuth parameter is missing or invalid:
            - Missing client_id, response_type, or redirect_uri
            - Invalid response_type (must be 'code', 'token', or 'id_token')
            - Incomplete PKCE parameters (challenge without method or vice versa)
            - Invalid code_challenge_method (must be 'S256' or 'plain')

    Required Query Parameters:
        client_id (str): OAuth client identifier.
        response_type (str): OAuth response type ('code', 'token', 'id_token').
        redirect_uri (str): OAuth callback URI.

    Optional Query Parameters:
        scope (str): Requested OAuth scopes.
        state (str): OAuth state parameter.
        code_challenge (str): PKCE code challenge.
        code_challenge_method (str): PKCE challenge method ('S256', 'plain').

    JWT Claims:
        sub: "github-signin" (identifies this as GitHub OAuth params)
        typ: "oauth-params" (token type)
        cid: client_id
        scp: scope
        sid: state
        rty: response_type
        rdu: redirect_uri
        cch: code_challenge (if provided)
        ccm: code_challenge_method (if provided)
        iat: issued at timestamp
        exp: expiration timestamp (10 minutes)

    """
    client_id = query_params.get("client_id", "")
    response_type = query_params.get("response_type", "")
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
        raise ValueError(f"Invalid response_type: {response_type}. Must be 'code', 'token', or 'id_token'")

    # If PKCE is being used, both challenge and method are required
    if code_challenge and not code_challenge_method:
        raise ValueError("Missing code_challenge_method when code_challenge is provided")

    if code_challenge_method and not code_challenge:
        raise ValueError("Missing code_challenge when code_challenge_method is provided")

    # Validate code_challenge_method value if provided
    if code_challenge_method and code_challenge_method not in ["S256", "plain"]:
        raise ValueError(f"Invalid code_challenge_method: {code_challenge_method}. Must be 'S256' or 'plain'")

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
    "GET:/auth/github/login": RouteEndpoint(github_login),
    "GET:/auth/github/callback": RouteEndpoint(github_callback),
}
