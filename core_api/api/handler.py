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
    api_endpoints (ActionHandlerRoutes): Registry of route keys to handler functions.
        Route keys are in format "METHOD:resource" (e.g., "GET:/api/v1/portfolios").
"""

from typing import Any, Dict, Optional

import core_framework as util

import core_logging as log

from core_db.response import ErrorResponse, Response
from core_db.exceptions import (
    OperationException,
    NotFoundException,
    UnauthorizedException,
)

# Registry actions and routes for API Gateway
from ..event.event import event_actions
from ..item.portfolio import item_portfolio_actions
from ..item.app import item_app_actions
from ..item.branch import item_branch_actions
from ..item.build import item_build_actions
from ..item.component import item_component_actions
from ..registry.client import registry_client_actions
from ..registry.portfolio import registry_portfolio_actions
from ..registry.app import registry_app_actions
from ..registry.zone import registry_zone_actions
from ..facts.facter import facts_actions

from ..response import get_proxy_error_response, get_proxy_response
from ..request import ProxyEvent, RouteEndpoint, get_correlation_id
from ..security import (
    validate_client_access,
    check_permissions_with_wildcard,
    extract_security_context,
)
from ..oauth.auth_creds import get_credentials
import core_helper.aws as aws_helper

# Build the router for the API Gateway REST interface
api_endpoints: dict[str, RouteEndpoint] = {
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

    Routes are registered in the ``api_endpoints`` dictionary using route keys in the
    format "METHOD:resource". For example:

    .. code-block:: python

        api_endpoints = {
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

            api_endpoints["GET:/api/v1/portfolios"] = portfolio_list_handler

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
    try:
        # Parse and validate incoming request
        request = ProxyEvent(**event)

        # Extract or generate correlation ID for tracing
        correlation_id = get_correlation_id(request)

        log.set_correlation_id(correlation_id)

        log.info(
            "Processing API Gateway request",
            details={"method": request.httpMethod, "resource": request.resource},
        )

        cookie_dict = {c.split("=")[0]: c.split("=")[1] for c in request.cookies} if request.cookies else {}

        # Extract AWS credentials from Bearer JWT
        aws_credentials = get_credentials(cookie_dict, request.headers)

        # Build route key for handler lookup
        route_key = request.route_key
        endpoint_route = api_endpoints.get(route_key, None)

        if not endpoint_route:
            raise NotFoundException(f"Unsupported resource API: {route_key}")

        security_context = None
        if not endpoint_route.allow_anonymous:

            security_context = extract_security_context(request, role_arn=util.get_api_lambda_arn, require_aws_credentials=True)

            # bale out if the security_context cannot be determined.
            if not security_context:
                raise UnauthorizedException("Authorization required")

            # Validate token type
            if security_context.token_type != endpoint_route.required_token_type:
                raise UnauthorizedException(f"Invalid token type for this operation: {security_context.token_type}")

            # Check permissions
            missing_perms = check_permissions_with_wildcard(security_context.permissions, endpoint_route.required_permissions)
            if missing_perms:
                raise PermissionError(f"Missing permissions for this operation: {[p.value for p in missing_perms]}")

            if aws_credentials and security_context.user_id:
                # This now handles the optimization internally
                aws_helper.set_user_context(security_context.user_id, aws_credentials)
                log.debug("User context ready", details={"user_id": security_context.user_id})
            elif aws_credentials and not security_context.user_id:
                log.warning("AWS credentials found but no user_id in security context")
            elif not aws_credentials and security_context.user_id:
                log.warning("User_id found but no AWS credentials in JWT token")

            # Validate client access
            if endpoint_route.client_isolation:
                validate_client_access(security_context, request)

        # Call the endpoint handler with enhanced security context
        response: Response = api_endpoints[route_key].handler(
            headers=request.headers,
            cookies=cookie_dict,
            query_params=request.queryStringParameters or {},
            path_params=request.pathParameters or {},
            body=request.body or {},
            security=security_context,
        )

        log.info(
            "Action completed successfully",
            details={
                "action": route_key,
                "correlation_id": correlation_id,
                "result": response.code,
            },
        )
        log.debug("Action result data:", details=response.model_dump())

        # Convert Response to ProxyResponse and return as dict
        return get_proxy_response(response).model_dump()

    except (ValueError, TypeError) as e:
        error_response = ErrorResponse(message=str(e), code=400, metadata={"correlation_id": correlation_id})
        log.warning("Client error in API request", details=error_response.model_dump())
        return get_proxy_error_response(error_response)

    except OperationException as e:
        error_response = ErrorResponse(message=str(e), code=404, metadata={"correlation_id": correlation_id})
        log.warning("Returning 404 response", details=error_response.model_dump())
        return get_proxy_error_response(error_response)

    except UnauthorizedException as e:
        error_response = ErrorResponse(message=str(e), code=401, metadata={"correlation_id": correlation_id})
        log.warning("Authentication failed", details=error_response.model_dump())
        return get_proxy_error_response(error_response)

    except Exception as e:
        error_response = ErrorResponse(
            code=500,
            message="Internal server error",
            metadata={"correlation_id": log.get_correlation_id(), "error": str(e)},
        )
        log.error("Unexpected error in API handler", details=error_response.model_dump())
        return get_proxy_error_response(error_response)

    finally:
        try:
            aws_helper.clear_user_context()
            log.debug("Cleared user context at request end")
        except Exception as e:
            log.warning("Error clearing user context", details={"error": str(e)})
