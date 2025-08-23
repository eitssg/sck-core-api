import uuid

import httpx
from datetime import datetime, timedelta, timezone

from urllib.parse import urlencode, urlparse, parse_qs
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, JSONResponse

import jwt
from botocore.exceptions import BotoCoreError, ClientError

import core_logging as log

from .constants import GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_REDIRECT_URI, JWT_SECRET_KEY, JWT_ALGORITHM

from tools import get_user_access_key, encrypt_creds, create_session_jwt, cookie_opts, check_rate_limit


def _make_state() -> str:
    """Generate a cryptographically random OAuth state value.

    Returns:
        str: Random state string.
    """
    return uuid.uuid4().hex


def _set_identity_cookie(resp: RedirectResponse | JSONResponse, user_id: str, provider: str, next_url: str) -> None:
    """Set short-lived identity cookie so the credentials form knows who the user is.

    Args:
        resp (RedirectResponse | JSONResponse): Response object to mutate.
        user_id (str): Authenticated user identifier (e.g., email).
        provider (str): OAuth provider name (e.g., "github").
        next_url (str): Post-login destination URL.

    Returns:
        None
    """
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=10)
    ident = {
        "sub": user_id,
        "provider": provider,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": "sck-core-api",
        "jti": f"ident-{uuid.uuid4().hex}",
        "next": next_url,
    }
    token = jwt.encode(ident, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    resp.set_cookie("sck_identity", token, max_age=10 * 60, **cookie_opts())


github_router = APIRouter()


# Start GitHub OAuth


@github_router.get("/github/login")
async def github_login(request: Request):
    """Start GitHub OAuth login.

    Route:
        GET /auth/github/login

    Behavior:
        Sets oauth_state and oauth_next cookies and redirects to GitHub.

    Args:
        request (Request): Incoming FastAPI request with optional returnTo query.

    Returns:
        RedirectResponse: 302 to GitHub authorization endpoint.
    """
    return_to = request.query_params.get("returnTo", "/auth/v1/authorize")
    passthrough = {k: v for k, v in request.query_params.items() if k != "returnTo"}
    next_url = return_to
    if passthrough:
        sep = "&" if "?" in return_to else "?"
        next_url = f"{return_to}{sep}{urlencode(passthrough)}"

    state = _make_state()
    resp = RedirectResponse(url="about:blank", status_code=302)
    resp.set_cookie("oauth_state", state, **cookie_opts())
    resp.set_cookie("oauth_next", next_url, **cookie_opts())

    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_REDIRECT_URI,
        "scope": "read:user user:email",
        "state": state,
    }
    gh_auth = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    resp.headers["Location"] = gh_auth
    return resp


# Handle GitHub callback
@github_router.get("/github/callback")
async def github_callback(request: Request):
    """Complete GitHub OAuth, then login or continue signup.

    Route:
        GET /auth/github/callback

    Behavior:
        - Exchanges code for GitHub access token and fetches user info.
        - If default profile exists and is JWE-encrypted by server key, creates a session JWT (typ=session, cred_jwe)
          and redirects to oauth_next with the token in the URL fragment.
        - If no profile or cannot decrypt with server key, redirects to /credentials and sets sck_identity cookie for onboarding.
    """
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    cookie_state = request.cookies.get("oauth_state")
    next_url = request.cookies.get("oauth_next") or "/"

    if not code or not state or not cookie_state or state != cookie_state:
        return JSONResponse(status_code=400, content={"error": "invalid_state"})

    if not check_rate_limit(request, "oauth_token", max_attempts=10, window_minutes=15):
        log.warning("Rate limit exceeded for user 'github-sso' on /auth/v1/token")
        return JSONResponse(status_code=429, content={"error": "rate_limited", "code": 429})

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
        return JSONResponse(status_code=502, content={"error": "github_token_exchange_failed"})

    token_json = token_res.json()
    gh_access_token = token_json.get("access_token")
    if not gh_access_token:
        return JSONResponse(status_code=400, content={"error": "no_access_token_from_github"})

    async with httpx.AsyncClient(timeout=10) as client:
        user_res = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {gh_access_token}", "Accept": "application/vnd.github+json"},
        )
        email_res = await client.get(
            "https://api.github.com/user/emails",
            headers={"Authorization": f"Bearer {gh_access_token}", "Accept": "application/vnd.github+json"},
        )

    if user_res.status_code != 200:
        return JSONResponse(status_code=502, content={"error": "github_user_fetch_failed"})

    gh_user = user_res.json()
    emails = email_res.json() if email_res.status_code == 200 else []
    primary_email = next((e["email"] for e in emails if e.get("primary") and e.get("verified")), gh_user.get("email"))

    user_id = primary_email or f"github:{gh_user.get('id')}"
    if not user_id:
        return JSONResponse(status_code=400, content={"error": "no_user_id"})

    # Load profile and try to decrypt with server key (JWE). If not present, redirect to setup.
    access_key, access_secret = get_user_access_key(user_id)

    if access_key is None or access_secret is None:
        # No profile yet -> redirect user to set up credentials
        setup_url = "/credentials"
        resp = RedirectResponse(url=setup_url, status_code=302)
        resp.delete_cookie("oauth_state", path="/")
        resp.delete_cookie("oauth_next", path="/")
        _set_identity_cookie(resp, user_id=user_id, provider="github", next_url=next_url)
        return resp

    try:
        cred_jwe = encrypt_creds({"AccessKeyId": access_key, "SecretAccessKey": access_secret})
        session_jwt = create_session_jwt(user_id, cred_jwe)
        # Deliver session token via URL fragment; SPA reads it and removes from URL
        sep = "#" if "#" not in next_url else "&"
        dest = f"{next_url}{sep}session_token={session_jwt}"
        resp = RedirectResponse(url=dest, status_code=302)
        resp.delete_cookie("oauth_state", path="/")
        resp.delete_cookie("oauth_next", path="/")
        return resp
    except (BotoCoreError, ClientError) as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code in ["InvalidUserID.NotFound", "SignatureDoesNotMatch"]:
            return JSONResponse(status_code=401, content={"error": "Invalid AWS credentials", "code": 401})
        elif error_code == "TokenRefreshRequired":
            return JSONResponse(status_code=401, content={"error": "AWS credentials require MFA token", "code": 401})
        else:
            return JSONResponse(status_code=503, content={"error": "AWS authentication service error", "code": 503})
    except Exception:
        return JSONResponse(status_code=500, content={"error": "Authentication processing error", "code": 500})
