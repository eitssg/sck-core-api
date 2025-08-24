import uuid
import httpx
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse

import jwt
import core_logging as log

from core_db.profile.actions import ProfileActions
from core_db.profile.model import UserProfile

from .constants import (
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_REDIRECT_URI,
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
)

from .tools import (
    encrypt_credentials,
    create_basic_session_jwt,
    cookie_opts,
    check_rate_limit,
)


def _make_state() -> str:
    """Generate a cryptographically random OAuth state value."""
    return uuid.uuid4().hex


github_router = APIRouter()


@github_router.get("/github/login")
async def github_login(request: Request) -> RedirectResponse:
    """Start GitHub OAuth login.

    Route:
        GET /auth/github/login

    Behavior:
        Stores OAuth parameters and redirects to GitHub for authentication.
        After GitHub auth, will redirect back to your OAuth server flow.

    Query Parameters:
        - returnTo: Final destination after OAuth flow (default: /dashboard)
        - All other OAuth params will be preserved for the final OAuth flow
    """
    # Capture the final destination and OAuth parameters
    return_to = request.query_params.get("returnTo", "/dashboard")

    # Preserve OAuth parameters for later use
    oauth_params = {}
    oauth_keys = {"client_id", "response_type", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"}
    for key in oauth_keys:
        if key in request.query_params:
            oauth_params[key] = request.query_params[key]

    # Generate state for GitHub OAuth
    github_state = _make_state()

    # Store the OAuth flow parameters for after GitHub auth
    resp = RedirectResponse(url="about:blank", status_code=302)
    resp.set_cookie("github_oauth_state", github_state, max_age=10 * 60, **cookie_opts())
    resp.set_cookie("github_return_to", return_to, max_age=10 * 60, **cookie_opts())

    # Store OAuth params if they exist (for OAuth flow after GitHub auth)
    if oauth_params:
        resp.set_cookie(
            "github_oauth_params",
            jwt.encode(
                {"params": oauth_params, "exp": int((datetime.now(timezone.utc) + timedelta(minutes=10)).timestamp())},
                JWT_SECRET_KEY,
                algorithm=JWT_ALGORITHM,
            ),
            max_age=10 * 60,
            **cookie_opts(),
        )

    # Redirect to GitHub
    github_params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_REDIRECT_URI,
        "scope": "read:user user:email",
        "state": github_state,
    }
    gh_auth_url = f"https://github.com/login/oauth/authorize?{urlencode(github_params)}"
    resp.headers["Location"] = gh_auth_url

    log.debug(f"Starting GitHub OAuth flow, redirecting to: {gh_auth_url}")
    return resp


@github_router.get("/github/callback")
async def github_callback(request: Request) -> Response:
    """Complete GitHub OAuth and redirect to your OAuth server flow.

    Route:
        GET /auth/github/callback

    Behavior:
        1. Exchange GitHub code for user info
        2. Create or retrieve user profile
        3. Check if user has AWS credentials configured
        4. Create session JWT for your OAuth server
        5. Redirect to OAuth authorize endpoint with credential status in state
    """
    code = request.query_params.get("code")
    state = request.query_params.get("state")

    # Validate GitHub OAuth state
    github_state = request.cookies.get("github_oauth_state")
    return_to = request.cookies.get("github_return_to", "/dashboard")

    if not code or not state or not github_state or state != github_state:
        log.warning("GitHub OAuth state validation failed")
        return JSONResponse(status_code=400, content={"error": "invalid_state"})

    if not check_rate_limit(request, "github_oauth", max_attempts=10, window_minutes=15):
        log.warning("Rate limit exceeded for GitHub OAuth callback")
        return JSONResponse(status_code=429, content={"error": "rate_limited"})

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
            return JSONResponse(status_code=502, content={"error": "github_token_exchange_failed"})

        token_json = token_res.json()
        gh_access_token = token_json.get("access_token")
        if not gh_access_token:
            log.error("No access token received from GitHub")
            return JSONResponse(status_code=400, content={"error": "no_access_token_from_github"})

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
            return JSONResponse(status_code=502, content={"error": "github_user_fetch_failed"})

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
            return JSONResponse(status_code=400, content={"error": "no_user_id"})

        log.debug(f"GitHub OAuth completed for user: {user_id}")

        # Try to load existing user profile
        user_profile = None
        aws_creds_status = "missing"  # Default state

        try:
            # Fixed: Add client="core" parameter
            profile_response = ProfileActions.get(client="core", user_id=user_id, profile_name="default")
            user_profile = profile_response.data
            log.debug(f"Loaded existing profile for GitHub user {user_id}")

            # Check if user has AWS credentials in the profile
            credentials = user_profile.get("credentials", {})

            # Check for AWS credentials in the credentials envelope
            if isinstance(credentials, dict):
                # Check if the envelope has the aws_credentials field
                if "aws_credentials" in credentials and credentials["aws_credentials"]:
                    aws_creds_status = "configured"
                    log.debug(f"User {user_id} has AWS credentials configured")
                else:
                    aws_creds_status = "missing"
                    log.debug(f"User {user_id} exists but no AWS credentials configured")
            elif isinstance(credentials, str):
                # Legacy format - assume it's JWE encrypted credentials
                aws_creds_status = "configured"
                log.debug(f"User {user_id} has legacy AWS credentials configured")
            else:
                aws_creds_status = "missing"
                log.debug(f"User {user_id} exists but no credentials envelope found")

        except Exception as e:
            # Profile doesn't exist - create new one
            log.debug(f"Profile not found for GitHub user {user_id}, creating new profile: {e}")
            try:
                credentials_envelope = encrypt_credentials()  # No AWS creds, no password

                profile_data = UserProfile(
                    user_id=user_id,
                    profile_name="default",
                    email=primary_email or "",
                    first_name=gh_user.get("name", "").split(" ")[0] if gh_user.get("name") else "",
                    last_name=(
                        " ".join(gh_user.get("name", "").split(" ")[1:])
                        if gh_user.get("name") and " " in gh_user.get("name", "")
                        else ""
                    ),
                    credentials=credentials_envelope,
                ).model_dump()

                # Fixed: Add client="core" parameter
                ProfileActions.create(client="core", **profile_data)
                aws_creds_status = "missing"  # New user needs credentials
                log.debug(f"Created new profile for GitHub user {user_id}")

            except Exception as create_error:
                log.error(f"Failed to create profile for GitHub user {user_id}: {create_error}")
                return JSONResponse(status_code=500, content={"error": "Failed to create user profile"})

        # Create session JWT for your OAuth server (identity only, no AWS credentials)
        session_token = create_basic_session_jwt(user_id, minutes=30)

        # Retrieve stored OAuth parameters if they exist
        oauth_params = {}
        stored_params_cookie = request.cookies.get("github_oauth_params")
        if stored_params_cookie:
            try:
                stored_data = jwt.decode(stored_params_cookie, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
                oauth_params = stored_data.get("params", {})
            except jwt.InvalidTokenError:
                log.warning("Invalid stored OAuth params cookie")

        # Create state parameter with AWS credential status
        # Format: "github_oauth:{aws_status}:{original_state}"
        original_state = oauth_params.get("state", "")
        credential_state = f"github_oauth:{aws_creds_status}"
        if original_state:
            credential_state = f"{credential_state}:{original_state}"

        # Default OAuth parameters for your server
        default_oauth_params = {
            "response_type": "code",
            "client_id": oauth_params.get("client_id", "coreui"),  # Your React app's client ID
            "scope": oauth_params.get("scope", "read write"),
            "redirect_uri": oauth_params.get("redirect_uri", return_to),
            "state": credential_state,  # Include AWS credential status
        }

        # Add PKCE if it was in original request
        if "code_challenge" in oauth_params:
            default_oauth_params["code_challenge"] = oauth_params["code_challenge"]
            default_oauth_params["code_challenge_method"] = oauth_params.get("code_challenge_method", "S256")

        # Construct OAuth authorize URL
        oauth_url = f"/auth/v1/authorize?{urlencode(default_oauth_params)}"

        log.debug(f"Redirecting to OAuth server with state '{credential_state}': {oauth_url}")

        # Redirect to your OAuth server with session token
        resp = RedirectResponse(url=oauth_url, status_code=302)

        # Set session cookie for OAuth server
        resp.set_cookie("sck_token", session_token, max_age=30 * 60, **cookie_opts())

        # Clean up GitHub OAuth cookies
        resp.delete_cookie("github_oauth_state", path="/")
        resp.delete_cookie("github_return_to", path="/")
        resp.delete_cookie("github_oauth_params", path="/")

        return resp

    except Exception as e:
        log.error(f"GitHub OAuth callback failed: {e}")
        return JSONResponse(status_code=500, content={"error": "GitHub OAuth processing failed"})
