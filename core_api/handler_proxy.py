from typing import Any

import uuid
import core_logging as log

from core_db.response import ErrorResponse, Response
from core_db.exceptions import NotFoundException

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

from .request import ProxyEvent, EventRequestContext, ActionHandlerRoutes

from .facts.facter import facts_actions


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
        self["headers"] = {"Content-Type": "application/json"}
        if correlation_id:
            self["headers"]["X-Correlation-ID"] = correlation_id
        self["body"] = response.model_dump_json()
        self["isBase64Encoded"] = False


def get_correlation_id(request: ProxyEvent) -> str:
    """
    Get the correlation ID from the request headers
    """
    # if there are no headers, then create a new header
    if request.headers is None:
        request.headers = {}

    # If there are haeders, the correlation ID is in the headers, use it
    correlation_id = request.headers.get("X-Correlation-ID", None)
    if not correlation_id:
        if request.requestContext and request.requestContext.requestId:
            correlation_id = request.requestContext.requestId
        else:
            correlation_id = str(uuid.uuid4())
        request.headers["X-Correlation-ID"] = correlation_id

    return correlation_id


def check_if_user_authorised(context: EventRequestContext | None) -> bool:

    return True

    # FIXME - Later, we will add the logic to check if the user is authorised

    # if not context:
    #     raise UnauthorizedException("No request context")

    # identity = context.identity
    # if not identity:
    #     raise UnauthorizedException("No identity in request context")

    # AccountId = identity.accountId
    # UserId = identity.user
    # AccessKey = identity.accessKey

    # return True


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
        route_key = request.route_key

        # We STRONGLY recommend that you output correlation Id in
        # all LOG files and messges and that you send this value
        # to downstream services.  This will help you trace the request
        correlation_id = get_correlation_id(request)

        check_if_user_authorised(request.requestContext)

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
