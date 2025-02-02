from typing import Any

import json

from .direct import handler as direct_handler
from .proxy import handler as proxy_handler


def handler(event: Any, context: Any | None = None) -> dict:
    """
    This is the main lambda handler.  It routes the request to the appropriate handler
    based on the request method.

    **Method 1 - Lambda Invoker**

    The invoker will call the API with a specific API.  See the request format is

    .. clode-block:: python

        event: dict = {
            "action": "action_name",
            "data": "{\"key\": \"value\"}"
        }

    When received an "action" in the event, we route to the legacy handler.

    The response object is a dictionary with the following keys:

    .. clode-block:: python

        response: dict = {
            "status": "ok | error",
            "code": 200,
            "data": "{\"key\": \"value\"}",
            "timestamp": "2024-01-01T00:00:00Z"
        }

    **Method 2 - API Gateway**

    When received a "resource" in the event, we route to the gateway handler.  This interface is defined
    by clicking the "Integration Request" in the API Gateway console and setting the content type to
    "application/json".

    .. code-block:: python

        event = {
            "resource": "/api/v1/client/{client}",
            "httpMethod": "GET",
            "pathParameters": {
                "client": "example"
            },
            "queryStringParameters": {
                "key": "value"
            },
            "body": "{\"key\": \"value\"}"
        }

    Once processed, the response is what is expected by AWS API Gateway.  This interface is defined
    by clicking the "Integration Request" in the API Gateway console and setting the content type to
    "application/json".

    .. code-block:: python

        response = {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": "{\"key\": \"value\"}"
        }

    Args:
        event (dict): from AWS API Gateway or Invoker
        context (dict, optional): Typically Cognito Authorization/Identificatoin Defaults to None.

    Returns:
        dict: A dictionary with the response for AWS API Gateway or Invoker
    """
    if not isinstance(event, dict):
        return {
            "statusCode": 400,
            "body": json.dumps({"message": "Event must be a dictionary"}),
        }

    if "action" in event:
        return direct_handler(event, context)
    elif "resource" in event and "httpMethod" in event:
        return proxy_handler(event, context)
    else:
        return {
            "statusCode": 400,
            "body": json.dumps({"message": "Unsupported event", "event": event}),
        }
