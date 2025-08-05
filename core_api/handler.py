"""Main Lambda function handler with intelligent request routing.

This module provides the primary entry point for AWS Lambda function execution,
automatically detecting the request source and routing to the appropriate handler
based on the event structure. It supports both API Gateway proxy integration
and direct Lambda invocation patterns.

The handler implements a dual-mode architecture:

1. **API Gateway Mode**: For HTTP requests via AWS API Gateway or local emulator
2. **Direct Invocation Mode**: For CLI tools, scheduled tasks, and other Lambda invocations

Example:
    AWS Lambda deployment::

        # serverless.yml or SAM template
        Functions:
          CoreAPI:
            Handler: core_api.handler.handler
            Runtime: python3.11

    Local testing::

        from core_api.handler import handler

        # API Gateway event
        api_event = {
            "resource": "/users/{id}",
            "httpMethod": "GET",
            "pathParameters": {"id": "123"}
        }
        response = handler(api_event, context)

        # Direct invocation event
        direct_event = {
            "action": "portfolio:create",
            "data": {"name": "My Portfolio"}
        }
        response = handler(direct_event, context)
"""

from typing import Any

import core_logging as log
import core_framework as util

from .direct import handler as direct_handler
from .proxy import handler as proxy_handler


def handler(event: Any, context: Any | None = None) -> dict:
    """Main Lambda function handler with intelligent request routing.

    This is the primary entry point for all Lambda function invocations. It analyzes
    the incoming event structure to determine the request source and routes to the
    appropriate specialized handler for processing.

    **Request Source Detection:**

    The handler uses event structure analysis to determine routing:

    - **API Gateway Events**: Contain ``resource`` and ``httpMethod`` fields
    - **Direct Invocation Events**: Contain ``action`` field for command routing
    - **Invalid Events**: Missing required fields or wrong data types

    **Method 1 - Direct Lambda Invocation**

    Used by CLI tools, scheduled tasks, and other AWS services that invoke
    Lambda functions directly. The event follows a simplified action-based format:

    .. code-block:: python

        # Direct invocation event structure
        event = {
            "action": "portfolio:create",
            "data": {
                "name": "My Portfolio",
                "description": "Portfolio description"
            },
            "auth": {
                "user_id": "123",
                "role": "admin"
            }
        }

    Direct invocation responses use a standardized format:

    .. code-block:: python

        # Direct invocation response structure
        response = {
            "status": "ok",           # "ok" or "error"
            "code": 200,              # HTTP status code
            "data": {                 # Response payload
                "id": "portfolio-123",
                "name": "My Portfolio"
            },
            "message": "Portfolio created successfully",
            "timestamp": "2024-01-01T00:00:00Z"
        }

    **Method 2 - API Gateway Proxy Integration**

    Used when requests come through AWS API Gateway or the local API Gateway
    emulator. Events follow the AWS API Gateway proxy integration format:

    .. code-block:: python

        # API Gateway proxy event structure
        event = {
            "resource": "/api/v1/portfolios/{id}",
            "httpMethod": "GET",
            "path": "/api/v1/portfolios/123",
            "pathParameters": {
                "id": "123"
            },
            "queryStringParameters": {
                "include": "apps"
            },
            "headers": {
                "Authorization": "Bearer eyJ0eXAi...",
                "Content-Type": "application/json"
            },
            "body": "{\"name\": \"Updated Portfolio\"}",
            "requestContext": {
                "requestId": "550e8400-e29b-41d4-a716-446655440000",
                "identity": {...}
            }
        }

    API Gateway responses follow AWS Lambda proxy integration format:

    .. code-block:: python

        # API Gateway proxy response structure
        response = {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "multiValueHeaders": {},
            "body": "{\"id\": \"123\", \"name\": \"My Portfolio\"}"
        }

    Args:
        event (Any): Event data from AWS Lambda runtime. Structure varies by source:

            - Dict with "action" key for direct invocations
            - Dict with "resource" + "httpMethod" keys for API Gateway
            - Must be a dictionary type for valid processing

        context (Any, optional): AWS Lambda context object with runtime information.
            Contains execution metadata like request ID, remaining time, etc.
            Defaults to None for local testing environments.

    Returns:
        Dict[str, Any]: Response dictionary with format determined by event source:

            - **Direct invocation**: ``{status, code, data, message, timestamp}``
            - **API Gateway**: ``{statusCode, headers, body, isBase64Encoded}``
            - **Error response**: ``{statusCode, body}`` with error details

    Raises:
        TypeError: If event is not a dictionary (handled gracefully with error response).
        KeyError: If required event fields are missing (handled gracefully).
        Exception: Any handler-specific exceptions are caught and logged.

    Note:
        - The function is designed to never raise exceptions, always returning
          a valid response dictionary suitable for AWS Lambda runtime
        - All errors are logged for debugging while returning user-friendly responses
        - Context object is optional for compatibility with local testing

    Example:
        Direct invocation usage::

            # CLI tool invocation
            event = {
                "action": "facts:list",
                "data": {"environment": "prod"}
            }
            response = handler(event, lambda_context)

            if response["status"] == "ok":
                facts = response["data"]
                print(f"Found {len(facts)} facts")

        API Gateway usage::

            # HTTP API request
            event = {
                "resource": "/portfolios",
                "httpMethod": "POST",
                "body": "{\"name\": \"New Portfolio\"}"
            }
            response = handler(event, lambda_context)

            if response["statusCode"] == 201:
                print("Portfolio created successfully")

        Error handling::

            # Invalid event type
            response = handler("not-a-dict", lambda_context)
            # Returns: {"statusCode": 400, "body": "{\"message\": \"...\"}"}

            # Missing required fields
            response = handler({}, lambda_context)
            # Returns: {"statusCode": 400, "body": "{\"message\": \"...\"}"}
    """
    try:
        if not isinstance(event, dict):
            return {
                "statusCode": 400,
                "body": util.to_json({"message": "Event must be a dictionary"}),
            }

        if "action" in event:
            return direct_handler(event, context)

        elif "resource" in event and "httpMethod" in event:
            return proxy_handler(event, context)

        else:
            log.error("Unsupported event structure", details={"event": event})
            return {
                "statusCode": 400,
                "body": util.to_json({"message": "Unsupported event", "event": event}),
            }

    except Exception as e:
        log.error("Handler error", details={"error": str(e), "event": event})
        return {
            "statusCode": 500,
            "body": util.to_json({"message": "Internal server error", "error": str(e)}),
        }
