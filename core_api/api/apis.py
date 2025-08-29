"""FastAPI router and request handling for core API.

This module provides routing configuration, request authorization, and AWS Lambda
function integration for the API Gateway implementation. It handles the translation
between FastAPI requests and AWS Lambda proxy events.

The module supports both local mode (direct handler invocation) and remote mode
(AWS Lambda invocation) based on environment configuration.

Example:
    Basic router usage::

        from core_api.api.apis import get_fast_api_router

        app = FastAPI()
        app.include_router(get_fast_api_router(), prefix="/api")

Attributes:
    MEDIA_TYPE (str): Default media type for API responses ("application/json").
    STATUS_CODE (str): Key name for status code in Lambda responses.
    BODY (str): Key name for response body in Lambda responses.
"""

from typing import Optional

import base64
import json

from dotenv.cli import get
from fastapi.responses import JSONResponse, RedirectResponse

import core_logging as log

from fastapi import Request, Response
from fastapi.routing import APIRoute

from core_api.oauth.auth_creds import decrypt_creds

from ..oauth.tools import get_authenticated_user

from ..security import get_security_context

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
    """
    Get AWS Cognito Identity
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


async def authorize_request(request: Request, role: str) -> CognitoIdentity:
    """Authorize the request by validating the token in the Authorization header.

    Extracts and validates the Bearer token from the Authorization header,
    then retrieves user information from AWS Cognito.

    Args:
        request (Request): The FastAPI Request object containing headers.
        role (str): The AWS IAM role ARN required for this operation.

    Returns:
        CognitoIdentity: The authenticated user's identity information.

    Raises:
        ValueError: If Authorization header is missing, malformed, or token is invalid.
        HTTPException: If user is not authorized for the requested operation.

    Note:
        The Authorization header must be in the format: "Bearer <token>"

    Example:
        .. code-block:: python

            identity = await authorize_request(request, "arn:aws:iam::123:role/ReadRole")
            print(f"User: {identity.username}")
    """

    # Your OAuth-based authentication
    jwt_token, _ = get_authenticated_user(request.cookies, request.headers)

    aws_credentials = decrypt_creds(jwt_token)

    session_token = aws_credentials.get("SessionToken")

    return get_cognito_identity(session_token, role)


async def generate_event_context(request: Request, identity: CognitoIdentity) -> tuple[ProxyEvent, ProxyContext]:
    """Generate Lambda event and context from FastAPI request.

    Converts a FastAPI request into AWS Lambda proxy event and context objects
    that can be used to invoke Lambda functions or local handlers.

    Args:
        request (Request): FastAPI request object containing all request data.
        identity (CognitoIdentity): Authenticated user's identity information.

    Returns:
        tuple[ProxyEvent, ProxyContext]: A tuple containing:
            - ProxyEvent: AWS API Gateway proxy event object
            - ProxyContext: AWS Lambda context object

    Note:
        The generated event includes all request components: headers, query parameters,
        path parameters, body, and authentication context.

    Example:
        .. code-block:: python

            event, context = await generate_event_context(request, identity)
            # event.httpMethod == "GET"
            # event.path == "/api/v1/users"
            # event.body == '{"name": "John"}'
    """
    query_params = dict(request.query_params)
    path_params = dict(request.path_params)
    headers = dict(request.headers)
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

    event: ProxyEvent = generate_proxy_event(
        protocol=request.url.scheme,
        identity=identity,
        source_ip=request.client.host if request.client else "127.0.0.1",
        method=request.method,
        resource=resource,
        path=request.url.path,
        path_params=path_params,
        query_params=query_params,
        body=body_data,
        headers=headers,
        is_base64_encoded=is_base64_encoded,
        stage="local",  # API Gateway stage
    )

    context = generate_proxy_context(event)

    return event, context


async def generate_response_from_lambda(result: dict) -> Response:
    """Convert AWS Lambda proxy response to appropriate FastAPI Response object.

    This function emulates AWS API Gateway's response processing, converting the
    standardized Lambda proxy integration response format into the correct FastAPI
    Response type. It handles all AWS API Gateway response behaviors including
    redirects, JSON responses, error codes, cookies, and multi-value headers.

    AWS API Gateway Lambda Proxy Integration Response Format:
        The Lambda function must return a response in this exact format:

        .. code-block:: python

            {
                "isBase64Encoded": false,
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-cache"
                },
                "multiValueHeaders": {
                    "Set-Cookie": [
                        "session_id=abc123; Path=/; HttpOnly",
                        "csrf_token=xyz789; Path=/; Secure"
                    ]
                },
                "body": '{"message": "Success"}'
            }

    Args:
        result (dict): AWS Lambda proxy integration response containing:

            - **statusCode** (int): HTTP status code (200, 302, 404, etc.)
            - **body** (str): Response body content (JSON string, HTML, etc.)
            - **headers** (dict, optional): Single-value HTTP headers
            - **multiValueHeaders** (dict, optional): Multi-value HTTP headers (like Set-Cookie)
            - **isBase64Encoded** (bool, optional): Whether body is base64 encoded

    Returns:
        Response: Appropriate FastAPI Response subclass:

            - **RedirectResponse**: For 3xx status codes with Location header
            - **JSONResponse**: For application/json content type or valid JSON body
            - **Response**: For all other content types (HTML, text, binary, etc.)

    Response Type Selection Logic:
        1. **Redirect (3xx + Location)**: Creates RedirectResponse with proper status code
        2. **JSON Content**: Creates JSONResponse when Content-Type is application/json OR body is valid JSON
        3. **Generic Content**: Creates basic Response for HTML, text, binary, or invalid JSON

    AWS API Gateway Behaviors Emulated:
        - **Multi-value headers**: Properly handles multiple Set-Cookie headers
        - **Header case sensitivity**: Preserves original header case from Lambda
        - **Base64 decoding**: Automatically decodes base64-encoded binary content
        - **Content-Type detection**: Uses Lambda headers or defaults to application/json
        - **Cookie handling**: Preserves all Set-Cookie values without merging

    Example Lambda Responses:

        **OAuth Redirect Response**:

        .. code-block:: python

            # Lambda returns
            {
                "statusCode": 302,
                "headers": {
                    "Location": "/auth/v1/authorize?client_id=app&state=xyz123"
                },
                "multiValueHeaders": {
                    "Set-Cookie": [
                        "github_oauth_state=abc123; Max-Age=600; HttpOnly; SameSite=Lax",
                        "github_return_to=/dashboard; Max-Age=600; HttpOnly"
                    ]
                },
                "body": ""
            }
            # Returns: RedirectResponse with cookies preserved

        **API Success Response**:

        .. code-block:: python

            # Lambda returns
            {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json",
                    "X-Total-Count": "25",
                    "Cache-Control": "max-age=300"
                },
                "body": '{"portfolios": [{"id": 1, "name": "My Portfolio"}], "total": 25}'
            }
            # Returns: JSONResponse with parsed JSON content

        **Error Response**:

        .. code-block:: python

            # Lambda returns
            {
                "statusCode": 403,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": '{"error": "insufficient_permissions", "error_description": "Missing portfolio:write permission"}'
            }
            # Returns: JSONResponse with error details

        **Binary File Response**:

        .. code-block:: python

            # Lambda returns
            {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/pdf",
                    "Content-Disposition": "attachment; filename=report.pdf"
                },
                "body": "JVBERi0xLjQKJeLjz9MKM...",  # base64 encoded PDF
                "isBase64Encoded": true
            }
            # Returns: Response with decoded binary content

    Note:
        This function ensures development behavior matches production AWS API Gateway
        exactly, providing consistent response handling across environments.

    Raises:
        json.JSONDecodeError: If body appears to be JSON but is malformed (gracefully handled)
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
    """Check if text is valid JSON without raising exceptions."""
    try:
        json.loads(text)
        return True
    except (json.JSONDecodeError, TypeError):
        return False
