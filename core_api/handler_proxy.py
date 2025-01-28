from typing import Any

import uuid
import core_logging as log

import core_framework as util

from core_db.response import ErrorResponse, Response
from core_db.exceptions import NotFoundException, UnauthorizedException

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

from .request import ProxyEvent, ActionHandlerRoutes

from .facts.facter import facts_actions

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
    """return plain dict as lambda response"""

    def __init__(self, response: Response, correlation_id: str | None = None):

        self["statusCode"] = response.code
        self["headers"] = {HDR_CONTENT_TYPE: "application/json"}
        if correlation_id:
            self["headers"][HDR_X_CORRELATION_ID] = correlation_id
        self["body"] = response.model_dump_json()
        self["isBase64Encoded"] = False


def get_correlation_id(request: ProxyEvent) -> str:
    """
    Get the correlation ID from the request headers or create a new one
    """
    # If there are haeders, the correlation ID is in the headers, use it
    _, correlation_id = get_header(request.headers, HDR_X_CORRELATION_ID)
    if not correlation_id:
        if request.requestContext.requestId:
            correlation_id = request.requestContext.requestId
        else:
            correlation_id = str(uuid.uuid4())
        request.headers[HDR_X_CORRELATION_ID] = correlation_id

    return correlation_id


def check_if_user_authorised(event: ProxyEvent) -> dict:
    """Sets up the session credentials for this thread for the user as
    the user must have API read/write credentials to use the API"""

    headers = event.headers
    if not headers:
        raise UnauthorizedException("No headers in request context")

    _, bearer = get_header(headers, HDR_AUTHORIZATION)
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

    method = event.httpMethod

    # Lambda functions are in the automation account
    account = util.get_automation_account()

    if not account:
        raise ValueError("No Automation Account secified in the environment")

    # Read role for "get", Write role for "post", "put", "delete", "patch"
    role = util.get_automation_api_role_arn(account, method.lower() != "get")

    # Get the ideantity will be from "Assume Role".  So, we're good with the thread's session store.
    # This will return a CognitoIdentity pydantic BaseModel.
    identity = get_user_information(token, role)

    if not identity:
        raise ValueError("User is not authorized")

    # we only are interested in populated values.
    return identity.model_dump(exclude_none=True)


# The following function is the lambda handler to receive requests from AWS API Gateway
def handler_proxy(event: Any, context: Any | None = None) -> dict:
    """
    This is a router for registered API reource paths.  It examines the lambda event
    data looking for "resource".  This is what you would get from AWS API Gatewqy.

    When it finds the reasource, it calles the registered function with the event as a parameter.

    Event Example (from AWS API Gateway):

    event = {
        "httpMethod": "GET",
        "resource": "/api/v1/client/{client}",
        "heaaers": {
            "Content-Type": "application/json",
            "Authorization": "Bearer <aws STS session token>",
        },
        "pathParameters": {
            "client": "example"
        },
        "queryStringParameters": {
            "key": "value"
        },
        "body": '{"key": "value"}'
    }

    Example Response (back to AWS API Gateway):
        dict({
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': '{"key": "value"}'  # JSON encoded data
        })

    Args:
        event (dict): The "Lambda Event" from AWS API Gateway.  See sck-mod-core for a sample generator
        context (dict): lambda context (Ex: cognito, SQS, SNS, etc). This is where you can get, for example,
                        the lambda runtime lifetime, memory, etc. so you know how long the lambda can run.
                        This is helpful if you have long-running actions and the lambda function will terminate.

                        Better use step functions when running long-running actions.

    Returns:
        dict: A dictionary with the response.

    """
    try:

        if not isinstance(event, dict):
            raise ValueError("Event is not a dictionary")

        # Validate incoming request
        request = ProxyEvent(**event)

        # We STRONGLY recommend that you output correlation Id in
        # all LOG files and messges and that you send this value
        # to downstream services.  This will help you trace the request
        correlation_id = get_correlation_id(request)

        # Check if the user is authorized to use the API.  Throws an exception if not.
        check_if_user_authorised(request)

        route_key = request.route_key
        action_handler = api_paths.get(route_key, None)
        if not action_handler:
            raise NotFoundException(f"Unsupported resource API: {route_key}")

        log.info(
            "Executing action",
            details={"action": route_key, "correlation_id": correlation_id},
        )

        # actions handler expects **kwargs

        # TODO: change signature of actions_handler to accept ProxyEvent
        result = action_handler(**request.model_dump())

        log.info(
            "Action complete",
            details={
                "action": route_key,
                "correlation_id": correlation_id,
                "result": result.model_dump(),
            },
        )

        return ProxyResponse(result, correlation_id)

    except Exception as e:
        return ProxyResponse(ErrorResponse(e))
