from typing import Any, Dict, Optional

import core_logging as log

from ..api.handler import ProxyEvent
from ..response import get_proxy_error_response, get_proxy_response
from ..request import (
    RouteEndpoint,
    check_permissions_with_wildcard,
    extract_security_context,
    validate_client_access,
)


from core_db.response import ErrorResponse, Response
from core_db.exceptions import (
    OperationException,
    NotFoundException,
    UnauthorizedException,
)

from .auth_client import auth_client_endpoints
from .auth_direct import auth_direct_endpoints
from .auth_github import auth_github_endpoints
from .auth_server import auth_server_endpoints


endpoints: dict[str, RouteEndpoint] = {
    **auth_server_endpoints,
    **auth_client_endpoints,
    **auth_direct_endpoints,
    **auth_github_endpoints,
}


def handler(event: Any, context: Optional[Any] = None) -> Dict[str, Any]:
    """AWS API Gateway Lambda proxy integration handler for OAuth server endpoints.

    This function serves as the entry point for AWS Lambda when deployed behind
    AWS API Gateway. It processes incoming API Gateway proxy integration events,
    routes them to the appropriate OAuth endpoint handlers, and returns responses
    in the format required by AWS API Gateway.

    This handler enables the OAuth server to run as a serverless Lambda function
    while maintaining identical behavior to the FastAPI development environment.

    AWS API Gateway Event Structure:
        The event parameter contains the complete AWS API Gateway proxy integration
        event with the following structure:

        .. code-block:: python

            {
                "httpMethod": "GET",
                "path": "/auth/v1/authorize",
                "resource": "/auth/v1/authorize",
                "pathParameters": {"client": "mycompany"},
                "queryStringParameters": {
                    "client_id": "react-app",
                    "response_type": "code",
                    "redirect_uri": "https://app.example.com/callback"
                },
                "headers": {
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIs...",
                    "Content-Type": "application/json",
                    "Cookie": "session_id=abc123; sck_token=xyz789"
                },
                "multiValueHeaders": {
                    "Accept": ["application/json", "text/html"]
                },
                "cookies": {
                    "session_id": "abc123",
                    "sck_token": "xyz789"
                },
                "body": '{"username": "user@example.com"}',
                "isBase64Encoded": false,
                "requestContext": {
                    "requestId": "c6af9ac6-7b61-11e6-9a41-93e8deadbeef",
                    "stage": "prod",
                    "httpMethod": "POST",
                    "identity": {...}
                }
            }

    Args:
        event (Any): AWS API Gateway proxy integration event containing:

            - **httpMethod** (str): HTTP method (GET, POST, PUT, DELETE, etc.)
            - **path** (str): Request path (e.g., "/auth/v1/authorize")
            - **pathParameters** (dict, optional): Path parameter values from URL
            - **queryStringParameters** (dict, optional): Query string parameters
            - **headers** (dict): Single-value HTTP request headers
            - **multiValueHeaders** (dict, optional): Multi-value HTTP headers
            - **cookies** (dict, optional): Parsed cookies (API Gateway v2.0+)
            - **body** (str): Request body content (JSON string, form data, etc.)
            - **isBase64Encoded** (bool): Whether body content is base64 encoded
            - **requestContext** (dict): Complete AWS API Gateway request context

        context (Optional[Any]): AWS Lambda runtime context containing execution
            environment information. Not currently used by OAuth endpoints but
            available for logging, monitoring, or timeout handling.

    Returns:
        Dict[str, Any]: AWS API Gateway Lambda proxy integration response in the
        **exact format required by AWS API Gateway**:

        .. code-block:: python

            {
                "isBase64Encoded": false,
                "statusCode": 302,
                "headers": {
                    "Location": "/auth/v1/authorize?client_id=app&state=xyz",
                    "Content-Type": "application/json",
                    "Cache-Control": "no-cache"
                },
                "multiValueHeaders": {
                    "Set-Cookie": [
                        "session_id=abc123; Path=/; HttpOnly; SameSite=Lax",
                        "oauth_state=xyz789; Max-Age=600; HttpOnly"
                    ]
                },
                "body": '{"access_token": "eyJhbGciOiJIUzI1NiIs..."}'
            }

        **Required Response Fields**:
            - **statusCode** (int): HTTP status code (200, 302, 400, 401, 403, 500, etc.)
            - **body** (str): Response body content (JSON string, HTML, plain text)

        **Optional Response Fields**:
            - **headers** (dict): Single-value HTTP response headers
            - **multiValueHeaders** (dict): Multi-value headers (e.g., multiple Set-Cookie)
            - **isBase64Encoded** (bool): Set to true for binary content (images, PDFs, etc.)

    Route Resolution:
        Routes are resolved using the pattern `"{httpMethod}:{path}"`:

        - **GET:/auth/v1/authorize** → OAuth authorization endpoint
        - **POST:/auth/v1/token** → OAuth token exchange endpoint
        - **GET:/auth/github/login** → GitHub OAuth initiation
        - **GET:/auth/github/callback** → GitHub OAuth callback
        - **POST:/auth/v1/login** → Direct user login
        - **PUT:/auth/v1/users/me** → User profile updates

    Example Responses:

        **OAuth Authorization Redirect**:

        .. code-block:: python

            {
                "statusCode": 302,
                "headers": {
                    "Location": "/auth/github/login?returnTo=/dashboard"
                },
                "multiValueHeaders": {
                    "Set-Cookie": [
                        "oauth_state=abc123; Max-Age=600; HttpOnly",
                        "oauth_params=eyJjbGllbnRfaWQi...; Max-Age=600; HttpOnly"
                    ]
                },
                "body": ""
            }

        **OAuth Token Response**:

        .. code-block:: python

            {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json",
                    "Cache-Control": "no-store"
                },
                "body": '{"access_token": "eyJhbGci...", "token_type": "Bearer", "expires_in": 3600}'
            }

        **OAuth Error Response**:

        .. code-block:: python

            {
                "statusCode": 400,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": '{"error": "invalid_request", "error_description": "Missing required parameter: client_id"}'
            }

    Error Handling:
        All exceptions are caught and converted to AWS API Gateway compatible error
        responses. This ensures the Lambda function never crashes and always returns
        a valid response that API Gateway can process.

        **Error Response Format**:

        .. code-block:: python

            {
                "statusCode": 500,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": '{"error": "internal_server_error", "error_description": "An unexpected error occurred"}'
            }

    Note:
        This handler is designed to be **identical** in behavior whether running
        in AWS Lambda behind API Gateway (production) or called via FastAPI proxy
        (development). The response format must exactly match AWS API Gateway
        requirements or the integration will fail.

    AWS Integration:
        When deployed to AWS Lambda, this function is invoked by API Gateway for
        all `/auth/*` routes. The Lambda function name and API Gateway integration
        must be configured to use the "Lambda Proxy Integration" pattern.

    Raises:
        Never raises exceptions - all errors are converted to HTTP error responses
        in AWS API Gateway format to prevent Lambda execution failures.
    """
    try:
        # Parse and validate AWS API Gateway event
        request = ProxyEvent(**event)
        route_key = request.route_key

        # Check if route exists
        if route_key not in endpoints:
            # Return 404 for unknown routes
            error_response = ErrorResponse(status="error", code=404, message=f"Route not found: {key}")
            return get_proxy_error_response(error_response).model_dump()

        endpoint_route = endpoints.get(route_key, None)

        if not endpoint_route:
            raise NotFoundException(f"Unsupported resource API: {route_key}")

        security_context = None
        if not endpoint_route.allow_anonymous:
            security_context = extract_security_context(request)

            if not security_context:
                raise UnauthorizedException("Authorization required")

            if security_context.token_type != endpoint_route.required_token_type:
                raise UnauthorizedException(f"Invalid token type for this operation: {security_context.token_type}")

            missing_perms = check_permissions_with_wildcard(security_context.permissions, endpoint_route.required_permissions)
            if missing_perms:
                raise PermissionError(f"Missing permissions for this operation: {[p.value for p in missing_perms]}")

            if endpoint_route.client_isolation:
                validate_client_access(security_context, request)

        # Call the endpoint handler
        response: Response = endpoints[route_key].handler(
            headers=request.headers,
            cookies=request.cookies or {},
            query_params=request.queryStringParameters or {},
            path_params=request.pathParameters or {},
            body=request.body or {},
        )

        # Convert Response to ProxyResponse and return as dict
        return get_proxy_response(response).model_dump()

    except (ValueError, TypeError) as e:
        error_response = ErrorResponse(message=str(e), code=400, metadata={"correlation_id": correlation_id})
        log.warning("Client error in API request", details=error_response.model_dump())
        return get_proxy_error_response(error_response)

    except OperationException as e:
        # Handle known operation exceptions
        error_response = ErrorResponse(status="error", code=e.code, message=e.message, exception=e)
        log.error("Operation error in API request", details=error_response.model_dump())
        return get_proxy_error_response(error_response).model_dump()

    except Exception as e:
        # Handle unexpected exceptions
        error_response = ErrorResponse(
            status="error",
            code=500,
            message=f"Internal server error: {str(e)}",
            exception=e,
        )
        log.error("Unexpected error in API request", details=error_response.model_dump())
        return get_proxy_error_response(error_response).model_dump()
