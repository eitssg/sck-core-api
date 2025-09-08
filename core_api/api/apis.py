"""Utilities to bridge FastAPI with AWS API Gateway/Lambda proxy.

This module provides helpers to:

- Build a Cognito-like identity from the current authenticated session
- Convert a FastAPI request into an API Gateway Lambda proxy ``event``/``context``
- Convert a Lambda proxy ``result`` back into a FastAPI ``Response``

It mirrors API Gateway behavior locally so development and production behave
the same (headers, multi-value headers, redirects, JSON detection, base64, etc.).

Attributes:
    MEDIA_TYPE: Default media type when none is provided (``"application/json"``).
    STATUS_CODE: Key used by Lambda proxy responses for HTTP status (``"statusCode"``).
    BODY: Key used by Lambda proxy responses for body content (``"body"``).
"""

from typing import Optional

import base64
import json

from dotenv.cli import get
from fastapi.responses import JSONResponse, RedirectResponse

import core_logging as log

from fastapi import Request, Response
from fastapi.routing import APIRoute
import jwt

from core_api.oauth.auth_creds import decrypt_creds

from ..oauth.tools import get_authenticated_user

from core_framework.models.aws import AWSCredentials

from ..request import ProxyEvent

from .tools import (
    ProxyContext,
    CognitoIdentity,
    generate_proxy_event,
    generate_proxy_context,
    get_ip_address,
    get_user_information,
)

MEDIA_TYPE = "application/json"
STATUS_CODE = "statusCode"
BODY = "body"


def get_cognito_identity(session_token: str, role: Optional[str] = None) -> Optional[CognitoIdentity]:
    """Construct a Cognito-style identity from the session.

    Uses ``get_user_information`` to pull AWS-style identity details derived from
    the current session token and optional role, and enriches it with the caller's
    IP address and placeholders expected by API Gateway/Lambda integrations.

    Args:
        session_token: Current session token (cookie-backed).
        role: Optional role/assumed-role indicator used by back-end identity tools.

    Returns:
        CognitoIdentity: Identity payload suitable for inclusion in a proxy ``event``.
    """

    identity_data = get_user_information(session_token, role)

    cognito_identity = CognitoIdentity(
        accountId=identity_data.get("Account"),
        user=identity_data.get("UserId"),
        userArn=identity_data.get("Arn"),
        caller=identity_data.get("caller", __name__),
        sourceIp=get_ip_address(),
        accessKey=identity_data.get("AccessKeyId"),
        # Additional AWS Cognito fields
        cognitoIdentityPoolId=identity_data.get("CognitoIdentityPoolId"),
        cognitoIdentityId=identity_data.get("CognitoIdentityId"),
        principalOrgId=identity_data.get("PrincipalOrgId"),
        userAgent="",  # Will be set by generate_proxy_event
    )

    return cognito_identity


async def authorize_request(request: Request) -> CognitoIdentity:
    """Build an authenticated identity for the current request.

    Extracts the current authenticated user context using cookies/headers, decrypts
    any available AWS-style credentials, and returns a ``CognitoIdentity`` with
    fields commonly used in API Gateway/Lambda proxy flows.

    Args:
        request: FastAPI Request with headers and cookies.

    Returns:
        CognitoIdentity: Identity populated as authenticated when credentials exist,
        otherwise an unauthenticated/anonymous identity.
    """

    # Your OAuth-based authentication
    jwt_token, _ = get_authenticated_user(request.cookies, request.headers)

    aws_credentials = decrypt_creds(jwt_token.enc) if jwt_token and jwt_token.enc else {}

    cognitoAuthenticationProvider = "ack-core-api"
    cognitoIdentityId = jwt_token.sub if jwt_token else "anonymous"
    if aws_credentials:
        cognitoAuthenticationType = "authenticated"
        accessKey = aws_credentials.get("AccessKeyId")
        accountId = aws_credentials.get("Account")
        cognitoIdentityId = aws_credentials.get("CognitoIdentityId")
        userArn = aws_credentials.get("UserArn")
        user = aws_credentials.get("User")
    else:
        cognitoAuthenticationType = "unauthenticated"
        accessKey = None
        accountId = None
        cognitoIdentityId = None
        userArn = None
        user = None

    sourceIp = get_ip_address()

    userAgent = request.headers.get("user-agent", "")

    identity = CognitoIdentity(
        accountId=accountId,
        cognitoIdentityId=cognitoIdentityId,
        sourceIp=sourceIp,
        accessKey=accessKey,
        cognitoAuthenticationType=cognitoAuthenticationType,
        cognitoAuthenticationProvider=cognitoAuthenticationProvider,
        userArn=userArn,
        userAgent=userAgent,
        user=user,
    )

    return identity


async def generate_event_context(request: Request, identity: CognitoIdentity) -> tuple[ProxyEvent, ProxyContext]:
    """Create API Gateway proxy ``event`` and Lambda ``context`` from a request.

    Includes method, path, headers, cookies, query/path params, body (UTF-8 or
    base64 for binary), and the provided ``CognitoIdentity``.

    Args:
        request: Incoming FastAPI request.
        identity: Authenticated user identity (or anonymous fallback).

    Returns:
        (ProxyEvent, ProxyContext): Event/context pair ready for handler invocation.
    """
    query_params = dict(request.query_params)
    path_params = dict(request.path_params)
    headers = dict(request.headers)
    cookies = dict(request.cookies)
    body = await request.body()

    # Handle binary vs text content properly
    try:
        body_data = body.decode("utf-8") if body else ""
        is_base64_encoded = False
    except UnicodeDecodeError:
        body_data = base64.b64encode(body).decode("utf-8")
        is_base64_encoded = True

    router: APIRoute = request.scope.get("route", None)
    resource = router.path_format

    if identity is None:
        ip = get_ip_address()
        user_agent = headers.get("user-agent", "")
        identity = CognitoIdentity(sourceIp=ip, caller="anonymous", userAgent=user_agent)

    event: ProxyEvent = generate_proxy_event(
        protocol=request.url.scheme,
        identity=identity,
        method=request.method,
        resource=resource,
        path=request.url.path,
        path_params=path_params,
        query_params=query_params,
        body=body_data,
        headers=headers,
        cookies=cookies,
        is_base64_encoded=is_base64_encoded,
        stage="local",  # API Gateway stage
    )

    context: ProxyContext = generate_proxy_context(event)

    return event, context


async def generate_response_from_lambda(result: dict) -> Response:
    """Convert a Lambda proxy ``result`` into the appropriate FastAPI response.

    Emulates API Gateway behavior locally:
    - Redirects: 3xx with ``Location`` -> ``RedirectResponse``
    - JSON: ``Content-Type: application/json`` or body parses as JSON -> ``JSONResponse``
    - Generic: everything else (HTML/text/binary/malformed JSON) -> ``Response``
    Also supports ``multiValueHeaders`` (notably multiple ``Set-Cookie``) and
    ``isBase64Encoded`` for binary bodies.

    Args:
        result: Lambda proxy response dict (``statusCode``, ``body``, optional ``headers``,
            optional ``multiValueHeaders``, optional ``isBase64Encoded``).

    Returns:
        fastapi.Response: A suitable Response subclass matching the payload semantics.
    """
    status_code = result.get(STATUS_CODE, 200)
    body = result.get(BODY, "")
    headers = result.get("headers", {})
    multi_value_headers = result.get("multiValueHeaders", {})
    is_base64 = result.get("isBase64Encoded", False)

    # Handle base64 encoded responses (binary files, images, etc.)
    if is_base64 and body:
        try:
            content = base64.b64decode(body)
            body_text = content.decode("utf-8", errors="ignore")
        except Exception as e:
            log.warning(f"Failed to decode base64 content: {e}")
            content = body.encode("utf-8")
            body_text = body
    else:
        content = body.encode("utf-8") if isinstance(body, str) else (body or b"")
        body_text = body if isinstance(body, str) else ""

    # Merge headers (multi-value headers take precedence)
    final_headers = {}
    final_headers.update(headers)

    # Handle multi-value headers (AWS API Gateway behavior)
    cookies = []
    for key, values in multi_value_headers.items():
        if key.lower() == "set-cookie":
            # Set-Cookie headers are special - never combine with commas
            cookies.extend(values if isinstance(values, list) else [values])
        elif isinstance(values, list):
            # Other multi-value headers are combined with commas (HTTP standard)
            final_headers[key] = ", ".join(str(v) for v in values)
        else:
            final_headers[key] = str(values)

    # Determine content type (AWS API Gateway default behavior)
    content_type = final_headers.get("content-type", final_headers.get("Content-Type", MEDIA_TYPE))

    log.debug(
        "Processing Lambda response:",
        details={
            "status": status_code,
            "content_type": content_type,
            "headers_count": len(final_headers),
            "cookies_count": len(cookies),
            "body_length": len(body_text) if body_text else 0,
            "is_base64": is_base64,
        },
    )

    # AWS API Gateway Response Type Selection Logic

    # 1. REDIRECT RESPONSES (3xx status + Location header)
    if 300 <= status_code < 400:
        location = None
        for key, value in final_headers.items():
            if key.lower() == "location":
                location = value
                break

        if location:
            log.debug(f"Creating RedirectResponse to: {location}")
            redirect_response = RedirectResponse(url=location, status_code=status_code)

            # Add all headers except Location (RedirectResponse handles it)
            for key, value in final_headers.items():
                if key.lower() != "location":
                    redirect_response.headers[key] = value

            # Add Set-Cookie headers individually (AWS API Gateway behavior)
            for cookie in cookies:
                redirect_response.headers.append("Set-Cookie", cookie)

            return redirect_response

    # 2. JSON RESPONSES (Content-Type or valid JSON detection)
    is_json_content_type = content_type.lower().startswith("application/json")
    is_valid_json_body = body_text and _is_valid_json(body_text)

    if is_json_content_type or is_valid_json_body:
        try:
            # Parse and validate JSON content
            json_data = json.loads(body_text) if body_text else {}

            log.debug(f"Creating JSONResponse with {len(str(json_data))} characters")
            json_response = JSONResponse(content=json_data, status_code=status_code)

            # Add custom headers (JSONResponse automatically sets Content-Type and Content-Length)
            for key, value in final_headers.items():
                if key.lower() not in ["content-type", "content-length"]:
                    json_response.headers[key] = value

            # Add Set-Cookie headers individually
            for cookie in cookies:
                json_response.headers.append("Set-Cookie", cookie)

            return json_response

        except json.JSONDecodeError as e:
            # Body looks like JSON but is malformed - log and fall through to generic response
            log.warning(f"Malformed JSON in response body: {e}. Body preview: {body_text[:100]}...")

    # 3. GENERIC RESPONSE (HTML, text, binary, malformed JSON)
    log.debug(f"Creating generic Response with content-type: {content_type}")
    response = Response(
        content=content,
        status_code=status_code,
        headers=final_headers,
        media_type=content_type,
    )

    # Add Set-Cookie headers individually (maintains AWS API Gateway behavior)
    for cookie in cookies:
        response.headers.append("Set-Cookie", cookie)

    return response


def _is_valid_json(text: str) -> bool:
    """Return True if ``text`` parses as JSON, otherwise False."""
    try:
        json.loads(text)
        return True
    except (json.JSONDecodeError, TypeError):
        return False
