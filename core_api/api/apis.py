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

import base64

import core_framework as util
import core_helper.aws as aws

from fastapi import Request, APIRouter, HTTPException
from fastapi.responses import Response
from fastapi.routing import APIRoute

from ..proxy import api_paths, handler
from ..request import ProxyEvent
from .tools import (
    ProxyContext,
    CognitoIdentity,
    generate_proxy_event,
    generate_proxy_context,
    get_user_information,
    get_header,
)

MEDIA_TYPE = "application/json"
STATUS_CODE = "statusCode"
BODY = "body"


class RouterSingleton:
    """Singleton class for managing FastAPI router instance.

    This class ensures only one router is created and reused across the application,
    automatically configuring all API routes based on the proxy configuration.

    Attributes:
        _router (APIRouter | None): Private router instance, None until first access.

    Note:
        The router is lazily initialized on first access and includes all routes
        defined in the ``api_paths`` configuration.
    """

    _router: APIRouter | None = None

    @classmethod
    def get_router(cls) -> APIRouter:
        """Get or create the FastAPI router instance.

        Creates a new router if one doesn't exist, automatically adding all API routes
        from the proxy configuration. Each route is configured to forward requests
        to the ``proxy_forward`` endpoint.

        Returns:
            APIRouter: Singleton router instance with configured API routes.

        Note:
            Routes are created from ``api_paths`` keys in format "METHOD:resource",
            where METHOD is the HTTP method and resource is the URL path.

        Example:
            .. code-block:: python

                router = RouterSingleton.get_router()
                # Subsequent calls return the same instance
                same_router = RouterSingleton.get_router()
                assert router is same_router  # True
        """
        if cls._router is None:
            cls._router = APIRouter()
            for method_resource in api_paths.keys():
                method, resource = method_resource.split(":")
                cls._router.add_api_route(
                    resource,
                    endpoint=proxy_forward,
                    methods=[method],
                    response_class=Response,
                )
        return cls._router


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
    headers = request.headers
    _, bearer = get_header(headers, "Authorization")

    if bearer:
        if not bearer.startswith("Bearer"):
            raise ValueError("Authorization header is not in the correct format")
        parts = bearer.split(" ")
        if len(parts) != 2:
            raise ValueError("Authorization header is not in the correct format")
        token = parts[1]
    else:
        token = None

    if not token:
        raise ValueError("No Authorization token provided")

    identity = get_user_information(token, role)

    if not identity:
        raise ValueError("User is not authorized")

    return identity


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
    """Convert Lambda response to FastAPI Response object.

    Transforms the AWS Lambda proxy response format into a FastAPI Response
    with appropriate status code, body content, and media type.

    Args:
        result (dict): The response object from Lambda function with structure:

            .. code-block:: python

                {
                    "isBase64Encoded": False,
                    "statusCode": 200,
                    "headers": {
                        "Content-Type": "application/json"
                    },
                    "body": '{"key": "value"}'  # JSON string
                }

    Returns:
        Response: FastAPI Response object with extracted content and status.

    Note:
        The response body is assumed to be a JSON string and is set directly
        as the response content with "application/json" media type.

    Example:
        .. code-block:: python

            lambda_result = {
                "statusCode": 201,
                "body": '{"id": 123, "name": "John"}'
            }
            response = await generate_response_from_lambda(lambda_result)
            # response.status_code == 201
            # response.body == b'{"id": 123, "name": "John"}'
    """
    status_code = result.get(STATUS_CODE, 200)
    body = result.get(BODY, "{}")
    headers = result.get("headers", {})
    multi_value_headers = result.get("multiValueHeaders", {})
    is_base64 = result.get("isBase64Encoded", False)

    # Handle base64 encoded responses (like binary files)
    if is_base64:
        content = base64.b64decode(body)
    else:
        content = body.encode("utf-8") if isinstance(body, str) else (body or b"")

    # Merge headers (multi-value headers take precedence)
    final_headers = {}
    final_headers.update(headers)

    # Handle multi-value headers (combine with commas like HTTP spec)
    for key, values in multi_value_headers.items():
        if isinstance(values, list):
            final_headers[key] = ", ".join(str(v) for v in values)
        else:
            final_headers[key] = str(values)

    # Determine media type from headers or default
    media_type = final_headers.get("content-type", MEDIA_TYPE)

    return Response(content=content, status_code=status_code, headers=final_headers, media_type=media_type)


async def proxy_forward(request: Request) -> Response:
    """Forward API requests to AWS Lambda function or local handler.

    This is the main request processing function that handles authentication,
    event generation, and forwarding to either a local handler or AWS Lambda
    function based on the environment configuration.

    Args:
        request (Request): FastAPI request object containing all request data.

    Returns:
        Response: Lambda function response wrapped in FastAPI Response object.

    Raises:
        ValueError: If automation account not configured or authorization fails.
        HTTPException: If Lambda invocation fails or other processing errors occur.

    Note:
        - Read operations (GET) use read-only IAM roles
        - Write operations (POST, PUT, DELETE, PATCH) use write IAM roles
        - Local mode invokes handlers directly without AWS Lambda
        - Remote mode invokes AWS Lambda functions with proper IAM roles

    Example:
        This function is typically not called directly but registered as an endpoint:

        .. code-block:: python

            router.add_api_route("/users", proxy_forward, methods=["GET"])
            # Handles: GET /users -> Lambda function or local handler
    """
    try:
        # Lambda functions are in the automation account
        account = util.get_automation_account()

        if not account:
            raise ValueError("No Automation Account specified in the environment")

        # Read role for "get", Write role for other methods
        is_write_operation = request.method.lower() != "get"
        role = util.get_automation_api_role_arn(account, is_write_operation)

        # Authorize the user for this operation
        identity = await authorize_request(request, role)

        # Generate Lambda event and context
        lambda_event, context = await generate_event_context(request, identity)

        # Convert event to dict for Lambda invocation
        event = lambda_event.model_dump()

        # Execute in local mode or invoke AWS Lambda
        if util.is_local_mode():
            # Local mode: invoke handler directly
            result = handler(event, context)
        else:
            # Remote mode: invoke AWS Lambda function
            arn = util.get_api_lambda_arn()
            result = aws.invoke_lambda(arn, event, role=role)

        return await generate_response_from_lambda(result)

    except ValueError as e:
        # Authorization errors (401)
        return Response(content=util.to_json({"message": str(e)}), status_code=401, media_type=MEDIA_TYPE)
    except Exception as e:
        # Internal server errors (500)
        error_response = {"message": "Internal server error", "error": str(e) if util.is_debug_mode() else "An error occurred"}
        return Response(content=util.to_json(error_response), status_code=500, media_type=MEDIA_TYPE)


def get_fast_api_router() -> APIRouter:
    """Create a FastAPI Router with all proxy endpoints.

    Returns a configured FastAPI router that includes all API endpoints defined
    in the proxy configuration. This is the main entry point for integrating
    the API with a FastAPI application.

    Returns:
        APIRouter: The FastAPI APIRouter instance with all configured routes.

    Note:
        This function returns a singleton router instance. Multiple calls
        return the same router with the same route configuration.

    Example:
        Integration with FastAPI application::

            from fastapi import FastAPI
            from core_api.api.apis import get_fast_api_router

            app = FastAPI()
            app.include_router(get_fast_api_router(), prefix="/api")

        With custom configuration::

            router = get_fast_api_router()
            app.include_router(router, prefix="/api/v1", tags=["Core API"])
    """
    return RouterSingleton.get_router()
