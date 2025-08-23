"""AWS API Gateway proxy integration handler for Lambda functions.

This module provides the proxy integration layer between AWS API Gateway and
Lambda function handlers. It processes API Gateway proxy events, handles
authentication, routes requests to appropriate handlers, and formats responses
in the AWS Lambda proxy integration format.

The module implements:
- Route-based request routing using HTTP method + resource path
- JWT token authentication with AWS Cognito integration
- Correlation ID tracking for distributed tracing
- Error handling with appropriate HTTP status codes
- Response formatting for AWS API Gateway compatibility

Example:
    AWS API Gateway integration::

        # Event from API Gateway
        event = {
            "httpMethod": "GET",
            "resource": "/api/v1/portfolios/{id}",
            "pathParameters": {"id": "123"},
            "headers": {"Authorization": "Bearer token"}
        }

        # Handler processes and returns AWS format
        response = handler(event, context)
        # Returns: {"statusCode": 200, "headers": {...}, "body": "..."}

Attributes:
    api_paths (ActionHandlerRoutes): Registry of route keys to handler functions.
        Route keys are in format "METHOD:resource" (e.g., "GET:/api/v1/portfolios").
"""

from typing import Any, Dict, Optional
import uuid

import core_logging as log
import core_framework as util

from core_db.response import ErrorResponse, Response
from core_db.exceptions import (
    BadRequestException,
    NotFoundException,
    UnauthorizedException,
    UnknownException,
)

# Registry actions and routes for API Gateway
from .event.event import event_actions
from .item.portfolio import item_portfolio_actions
from .item.app import item_app_actions
from .item.branch import item_branch_actions
from .item.build import item_build_actions
from .item.component import item_component_actions
from .registry.client import registry_client_actions
from .registry.portfolio import registry_portfolio_actions
from .registry.app import registry_app_actions
from .registry.zone import registry_zone_actions
from .facts.facter import facts_actions

from .oauth.proxy_auth import get_credentials

from .request import ProxyEvent, ActionHandlerRoutes

from .api.tools import (
    get_header,
    HDR_AUTHORIZATION,
    HDR_CONTENT_TYPE,
    HDR_X_CORRELATION_ID,
    get_user_information,
)

# Build the router for the API Gateway REST interface
api_paths: ActionHandlerRoutes = {
    **event_actions,
    **item_portfolio_actions,
    **item_app_actions,
    **item_branch_actions,
    **item_build_actions,
    **item_component_actions,
    **registry_client_actions,
    **registry_portfolio_actions,
    **registry_app_actions,
    **registry_zone_actions,
    **facts_actions,
}


class ProxyResponse(dict):
    """AWS Lambda proxy integration response formatter.

    Formats Lambda function responses into the structure required by AWS API Gateway
    proxy integration. Automatically sets required headers and status codes based
    on the core Response object.

    The response format matches AWS Lambda proxy integration requirements:
    - statusCode: HTTP status code for the response
    - headers: HTTP headers to return to the client
    - body: Response body as JSON string
    - isBase64Encoded: Boolean indicating if body is base64 encoded

    Args:
        response (Response): Core response object containing status and data.
        correlation_id (Optional[str]): Request correlation ID for tracing.

    Note:
        This class extends dict to provide the exact structure AWS API Gateway
        expects from Lambda proxy integration responses.

    Example:
        .. code-block:: python

            # Create response from core Response object
            core_response = Response(data={"id": 123}, code=200)
            proxy_response = ProxyResponse(core_response, "uuid-123")

            # Returns AWS Lambda proxy format:
            # {
            #     "statusCode": 200,
            #     "headers": {"Content-Type": "application/json"},
            #     "body": '{"data": {"id": 123}, "code": 200}',
            #     "isBase64Encoded": False
            # }
    """

    def __init__(
        self, response: Response, correlation_id: Optional[str] = None
    ) -> None:
        """Initialize proxy response with core response data.

        Args:
            response (Response): Core response object to format.
            correlation_id (Optional[str]): Correlation ID for request tracing.
        """
        super().__init__()

        self["statusCode"] = response.code
        self["headers"] = {HDR_CONTENT_TYPE: "application/json"}

        if correlation_id:
            self["headers"][HDR_X_CORRELATION_ID] = correlation_id

        self["body"] = response.model_dump_json(exclude_none=True)
        self["isBase64Encoded"] = False


def get_correlation_id(request: ProxyEvent) -> str:
    """Extract or generate correlation ID for request tracing.

    Attempts to extract correlation ID from request headers, falls back to
    request ID from API Gateway context, or generates a new UUID if neither
    is available. The correlation ID is added to request headers for
    downstream services.

    Args:
        request (ProxyEvent): The API Gateway proxy event object.

    Returns:
        str: Correlation ID for this request (existing or newly generated).

    Note:
        The correlation ID is automatically added to the request headers
        if it doesn't already exist, ensuring all downstream services
        can participate in distributed tracing.

    Example:
        .. code-block:: python

            correlation_id = get_correlation_id(proxy_event)

            # Use in logging
            log.info("Processing request", correlation_id=correlation_id)

            # Pass to downstream services
            headers = {"X-Correlation-Id": correlation_id}
    """
    # Check if correlation ID is already in headers
    _, correlation_id = get_header(request.headers, HDR_X_CORRELATION_ID)

    if not correlation_id:
        # Try to use API Gateway request ID
        if request.requestContext and request.requestContext.requestId:
            correlation_id = request.requestContext.requestId
        else:
            # Generate new correlation ID
            correlation_id = str(uuid.uuid4())

        # Add to request headers for downstream services
        request.headers[HDR_X_CORRELATION_ID] = correlation_id

    return correlation_id


def check_if_user_authorized(event: ProxyEvent) -> Dict[str, Any]:
    """Validate user authorization and establish session credentials.

    Extracts and validates the JWT token from the Authorization header,
    retrieves AWS STS credentials from the JWT token, and establishes
    the appropriate IAM role session based on the HTTP method.

    Args:
        event (ProxyEvent): API Gateway proxy event containing headers and method.

    Returns:
        Dict[str, Any]: User identity information with AWS credentials.

    Raises:
        UnauthorizedException: If no headers are present in the request.
        ValueError: If Authorization header is missing, malformed, or token is invalid.
        ValueError: If automation account is not configured in environment.
        ValueError: If user is not authorized for the requested operation.

    Note:
        The function establishes thread-local AWS credentials by extracting
        STS credentials from the JWT token and assuming an appropriate IAM role:

        - **Read operations** (GET): Uses read-only role permissions
        - **Write operations** (POST, PUT, DELETE, PATCH): Uses read-write role permissions
    """
    # Validate headers are present
    headers = event.headers
    if not headers:
        raise UnauthorizedException("No headers in request context")

    # FIXED: Extract AWS STS credentials from JWT token instead of expecting raw token
    # Use model_dump() to convert ProxyEvent to dict for get_credentials compatibility
    credentials = get_credentials(event)

    if not credentials:
        raise ValueError("No valid authentication token provided or token has expired")

    # Determine required IAM role based on HTTP method
    method = event.httpMethod
    account = util.get_automation_account()

    if not account:
        raise ValueError("No Automation Account specified in the environment")

    # Read role for GET requests, write role for all other methods
    is_write_operation = method.lower() not in ["get", "head", "options"]
    role = util.get_automation_api_role_arn(account, is_write_operation)

    # FIXED: Use extracted STS credentials instead of JWT token directly
    # Pass the STS session token and credentials to get_user_information
    identity = get_user_information(
        credentials["SessionToken"],  # STS session token
        role,
        access_key_id=credentials["AccessKeyId"],
        secret_access_key=credentials["SecretAccessKey"],
    )

    if not identity:
        raise ValueError("User is not authorized")

    # Return only populated identity fields
    return identity.model_dump(exclude_none=True)


def handler(event: Any, context: Optional[Any] = None) -> Dict[str, Any]:
    """AWS API Gateway proxy integration handler for Lambda functions.

    This is the main entry point for API Gateway proxy integration. It processes
    incoming API Gateway events, validates authentication, routes requests to
    appropriate action handlers, and formats responses for API Gateway.

    **Request Processing Flow:**

    1. **Event Validation**: Ensures event is a valid dictionary and creates ProxyEvent
    2. **Correlation Tracking**: Extracts or generates correlation ID for tracing
    3. **Authentication**: Validates JWT token and establishes user session
    4. **Route Matching**: Maps HTTP method + resource to registered handler function
    5. **Handler Execution**: Invokes the matched handler with request parameters
    6. **Response Formatting**: Converts handler response to API Gateway format

    **Route Registration:**

    Routes are registered in the ``api_paths`` dictionary using route keys in the
    format "METHOD:resource". For example:

    .. code-block:: python

        api_paths = {
            "GET:/api/v1/portfolios": portfolio_list_handler,
            "POST:/api/v1/portfolios": portfolio_create_handler,
            "GET:/api/v1/portfolios/{id}": portfolio_get_handler,
        }

    **Authentication & Authorization:**

    All requests require JWT authentication via the Authorization header:

    - **GET requests**: Require read-only IAM role permissions
    - **POST/PUT/DELETE/PATCH**: Require read-write IAM role permissions
    - **Token validation**: Performed against AWS Cognito identity pools
    - **Role assumption**: Automatic IAM role assumption based on operation type

    Args:
        event (Any): AWS API Gateway proxy event containing:

            .. code-block:: python

                {
                    "httpMethod": "GET|POST|PUT|DELETE|PATCH",
                    "resource": "/api/v1/resource/{param}",
                    "pathParameters": {"param": "value"},
                    "queryStringParameters": {"key": "value"},
                    "headers": {
                        "Authorization": "Bearer <jwt_token>",
                        "Content-Type": "application/json"
                    },
                    "body": '{"key": "value"}',  # JSON string for POST/PUT
                    "requestContext": {
                        "requestId": "uuid",
                        "identity": {...}
                    }
                }

        context (Optional[Any]): AWS Lambda context object with runtime information.
            Contains execution metadata like remaining time, memory limits, etc.

    Returns:
        Dict[str, Any]: AWS Lambda proxy integration response:

            .. code-block:: python

                {
                    "statusCode": 200,
                    "headers": {
                        "Content-Type": "application/json",
                        "X-Correlation-Id": "uuid"
                    },
                    "body": '{"data": {...}, "code": 200}',  # JSON string
                    "isBase64Encoded": false
                }

    Raises:
        The handler never raises exceptions, instead returning appropriate error responses:

        - **400**: Invalid event structure or malformed request
        - **401**: Missing or invalid authentication token
        - **403**: User not authorized for requested operation
        - **404**: Route not found or resource doesn't exist
        - **500**: Internal server error or handler exception

    Note:
        - All errors are logged with correlation IDs for debugging
        - Response format matches AWS API Gateway proxy integration requirements
        - Handler functions receive unpacked ProxyEvent parameters as kwargs
        - Correlation IDs are automatically propagated to response headers

    Example:
        Handler registration and usage::

            # Register handler function
            def portfolio_list_handler(**kwargs):
                return Response(data=portfolios, code=200)

            api_paths["GET:/api/v1/portfolios"] = portfolio_list_handler

            # API Gateway event processing
            event = {
                "httpMethod": "GET",
                "resource": "/api/v1/portfolios",
                "headers": {"Authorization": "Bearer token"}
            }

            response = handler(event, lambda_context)
            # Returns: {"statusCode": 200, "body": "...", ...}

        Error handling::

            # Invalid route
            event = {"httpMethod": "GET", "resource": "/unknown"}
            response = handler(event, lambda_context)
            # Returns: {"statusCode": 404, "body": '{"message": "Route not found"}'}

            # Authentication failure
            event = {"httpMethod": "GET", "resource": "/api/v1/portfolios"}
            response = handler(event, lambda_context)
            # Returns: {"statusCode": 401, "body": '{"message": "Authentication required"}'}
    """
    correlation_id = None

    try:
        # Validate event structure
        if not isinstance(event, dict):
            raise ValueError("Event is not a dictionary")

        # Parse and validate incoming request
        request = ProxyEvent(**event)

        # Extract or generate correlation ID for tracing
        correlation_id = get_correlation_id(request)

        log.info(
            "Processing API Gateway request",
            details={
                "method": request.httpMethod,
                "resource": request.resource,
                "correlation_id": correlation_id,
            },
        )

        # Build route key for handler lookup
        route_key = request.route_key
        action_handler = api_paths.get(route_key, None)

        if not action_handler:
            raise NotFoundException(f"Unsupported resource API: {route_key}")

        # Validate user authorization and establish session credentials
        if route_key not in ["POST:/api/v1/login"]:
            user_identity = check_if_user_authorized(request)
        else:
            user_identity = {"user": "anonymous"}

        log.info(
            "Executing action handler",
            details={
                "action": route_key,
                "correlation_id": correlation_id,
                "user": user_identity.get("user"),
            },
        )

        # Execute action handler with request parameters
        # TODO: Update handler signature to accept ProxyEvent directly
        result = action_handler(**request.model_dump())

        log.info(
            "Action completed successfully",
            details={
                "action": route_key,
                "correlation_id": correlation_id,
                "result": result.code,
            },
        )
        log.debug("Action result data:", details=result.model_dump())

        return ProxyResponse(result, correlation_id)

    except (ValueError, TypeError) as e:
        error_response = ErrorResponse(
            message=str(e), code=400, metadata={"correlation_id": correlation_id}
        )
        log.warning("Client error in API request", details=error_response.model_dump())
        return ProxyResponse(error_response, correlation_id)

    except UnauthorizedException as e:
        error_response = ErrorResponse(
            message="Authentication required",
            code=401,
            metadata={"correlation_id": correlation_id},
        )
        log.warning("Authentication failed", details=error_response.model_dump())
        return ProxyResponse(error_response, correlation_id)

    except NotFoundException as e:
        error_response = ErrorResponse(
            message=str(e), code=404, metadata={"correlation_id": correlation_id}
        )
        log.warning("Returning 404 response", details=error_response.model_dump())
        return ProxyResponse(error_response, correlation_id)

    except PermissionError as e:
        error_response = ErrorResponse(
            message="User not authorized for this operation",
            code=403,
            metadata={"correlation_id": correlation_id},
        )
        log.warning(
            "Authorization error in API request", details=error_response.model_dump()
        )
        return ProxyResponse(error_response, correlation_id)

    except BadRequestException as e:
        error_response = ErrorResponse(
            message="Bad request", code=400, metadata={"correlation_id": correlation_id}
        )
        log.warning("Bad request in API handler", details=error_response.model_dump())
        return ProxyResponse(error_response, correlation_id)

    except UnknownException as e:
        error_response = ErrorResponse(
            message="Internal server error",
            code=500,
            metadata={"correlation_id": correlation_id},
        )
        log.error("Unknown error in API handler", details=error_response.model_dump())
        return ProxyResponse(error_response, correlation_id)

    except Exception as e:
        error_response = ErrorResponse(
            message="Internal server error",
            code=500,
            metadata={"correlation_id": correlation_id},
        )
        log.error(
            "Unexpected error in API handler", details=error_response.model_dump()
        )
        return ProxyResponse(error_response, correlation_id)
