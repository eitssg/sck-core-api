import os
import hashlib
import random
from fastapi.testclient import TestClient
from core_api.api.fast_api import get_app
from urllib.parse import urlencode, urlparse, parse_qs  # added parse helpers

app = get_app()

server = TestClient(app)


def test_public_browser_auth():

    # Get the URL for the form showing a nice spinner that says "Authorizing, please wati..."
    WEB_APP_CLIENT_ID = os.getenv("WEB_APP_CLIENT_ID", "")
    WEB_APP_SECRET = os.getenv("WEB_APP_SECRET", "")
    WEB_APP_AUTHORIZE = os.getenv("WEB_APP_AUTHORIZE", "")

    # page in my react app where I put up a spinner and wait for the /token
    REACT_APP_REDIRECT_URI = WEB_APP_AUTHORIZE
    REACT_APP_LOGIN_PAGE = "/login"

    # STEP 1 - Generate Verifier
    #     code_verifier = "random_string"
    #     code_challenge = "hashed_string"
    code_verifier = str(random.randint(100000, 999999))  # simple random string for testing
    code_challenge = hashlib.sha256(code_verifier.encode()).hexdigest()

    # STEP 2 - Call /authorize, save the code and state and redirectTo.  This should redirect to the server's login page.
    #     GET
    #        /auth/v1/authorize?client_id=coreui&redirect_uri=http://localhost:8090/authorize&response_type=code&scope=openid
    #
    #     The React WebApp does this:
    oauth_params = {
        "client_id": WEB_APP_CLIENT_ID,
        "response_type": "code",
        "login_hint": "email",
        "redirect_uri": REACT_APP_REDIRECT_URI,
        "state": "authorize",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    query = urlencode(oauth_params)
    response = server.get(f"http://localhost:8090/auth/v1/authorize?{query}", follow_redirects=False)

    # check the 302 to make sure it is telling us to go to the login page
    assert response.status_code == 302

    location = response.headers["Location"]

    # Verify it is a redirect to /login with a populated, safe returnTo
    parsed = urlparse(location)
    assert parsed.path == REACT_APP_LOGIN_PAGE

    # Perfect the SERVER has been told to go to the <server>/login page.
    # This is NOT the CLIENT REACT /login page (it's the SERVER /login page.  May also be a react_app perhaps)

    q = parse_qs(parsed.query)
    assert "returnTo" in q and q["returnTo"]  # must be present and non-empty

    # Ensure returnTo is a safe relative path (no external redirects)
    return_to_path = q["returnTo"][0]
    assert return_to_path.startswith("/") and "://" not in return_to_path
    assert return_to_path == "/auth/v1/authorize"  # our server fixes returnTo to /authorize

    # Verify original OAuth params are echoed as top-level login query params (not inside returnTo)
    for k, v in oauth_params.items():
        assert q.get(k, [None])[0] == v

    # Save the URL we will call after login (path + original params)
    return_to_authorize = f"{return_to_path}?{urlencode(oauth_params)}"

    # STEP 3 - Call /login to login to the Backend system that is authenticating the user.  It requires:
    #
    #    POST
    #       email
    #       password
    #       access_key
    #       access_secret
    #
    #    Response
    #       <token>
    #

    # Now that we are on the OAUTH SERVER /login page, we need to collect the appropriate information (email, password).
    # If the user doesn't exist, we should get an unauthorized response.

    form_email = "jbarwick@eits.com.sg"
    form_password = "mypassword"

    # call the OAUTH SERVER to login
    response = server.post("http://localhost:8090/auth/v1/login", json={"email": form_email, "password": form_password})

    assert response.status_code == 200

    body = response.json()

    assert "data" in body
    assert "code" in body

    assert body["code"] == 200

    data = body["data"]

    assert "token" in data

    # This is the OAUTH server token.  It is not the CORE API token.
    # It is NOT the CORE-AUTOMATION API SERVER TOKEN.
    token = data["token"]

    assert "expires_in" in data and data["expires_in"] == 86400
    assert "token_type" in data and data["token_type"] == "Bearer"

    # STEP 4 - Call /authorize again, but this time set the authorization header to the token to exchange the code for a token
    #     For OUR oauth server, we expect the token to be included in the Authorization header

    headers = {"Authorization": f"Bearer {token}"}
    response = server.get(return_to_authorize, headers=headers, follow_redirects=False)

    assert response.status_code == 302

    # we expect code and state to be supplied in the location

    location = response.headers["Location"]

    # Verify it is a redirect to /login with a populated, safe returnTo
    parsed = urlparse(location)

    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == REACT_APP_REDIRECT_URI

    assert "code" in parse_qs(parsed.query)
    assert "state" in parse_qs(parsed.query)

    code = parsed.query.split("code=")[1].split("&")[0]
    state = parsed.query.split("state=")[1].split("&")[0]

    # STEP 5 - Now on to the 'authorize' part of the progam

    # We need to call "/auth/v1/token" to convert our OAUTH server token to a CORE_API token

    # To use this API, the BROWSER APP needs to login, NOT the user.  We'll get the token from the 'code'
    auth = {WEB_APP_CLIENT_ID: WEB_APP_SECRET}
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": code_verifier,
        "redirect_uri": REACT_APP_REDIRECT_URI,
    }
    response = server.post("http://localhost:8090/auth/v1/token", data=data, auth=auth)

    assert response.status_code == 200
