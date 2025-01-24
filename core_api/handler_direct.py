from typing import Any, Callable

import core_logging as log

import core_helper.aws as aws

from core_framework.constants import CORE_AUTOMATION_API_WRITE_ROLE

from core_db.response import ErrorResponse, Response
from core_db.exceptions import BadRequestException, UnauthorizedException

# Actions to track all deployments and PRN data
from .item.portfolio import ApiPortfolioActions
from .item.app import ApiAppActions
from .item.branch import ApiBranchActions
from .item.build import ApiBuildActions
from .item.component import ApiComponentActions

# Event actions and routes (status events and other log messages in dynamodb)
from .event.event import ApiEventActions

# Registry facts actions and routes
from .registry.client import ApiRegClientActions
from .registry.portfolio import ApiRegPortfolioActions
from .registry.app import ApiRegAppActions
from .registry.zone import ApiRegZoneActions

# Facter actions - Get the facts.  Nothing but the facts.
from .facts.facter import ApiFactsActions

from .request import (
    Request,
    RequestType,
    RequestRoutesType,
)

actions_routes: RequestRoutesType = {
    RequestType.PORTFOLIO: ApiPortfolioActions,
    RequestType.APP: ApiAppActions,
    RequestType.BRANCH: ApiBranchActions,
    RequestType.BUILD: ApiBuildActions,
    RequestType.COMPONENT: ApiComponentActions,
    RequestType.EVENT: ApiEventActions,
    RequestType.FACTS: ApiFactsActions,
    RequestType.REG_CLIENT: ApiRegClientActions,
    RequestType.REG_PORTFOLIO: ApiRegPortfolioActions,
    RequestType.REG_APP: ApiRegAppActions,
    RequestType.REG_ZONE: ApiRegZoneActions,
}


def __get_action_handler(action: str) -> Callable:

    # if action is "module:class:method" then we only want the module and cleass for the key.
    # but if in the form of "class:mothod" then we only want the class for the key.
    parts = action.split(":")
    action_key = parts[0] if len(parts) <= 2 else ":".join(parts[:-1])
    method = parts[-1]

    # Convert action_key to RequestType enum if possible
    try:
        action_key_enum = RequestType(action_key)
    except ValueError:
        raise BadRequestException(f"Unsupported action '{action}'")

    result = getattr(actions_routes.get(action_key_enum, None), method, None)
    if result:
        return result

    raise BadRequestException(f"Unsupported action '{action}'")


def process_request(request: Request) -> Response:
    """
    Process a request and return a response

    Args:
        request (Request): The request object

    Returns:
        Response: The response object
    """
    data = request.data
    auth = request.auth
    action = request.action

    log.info(
        "Executing action",
        details={"action": action, "data": data, "auth": auth},
    )

    if not aws.check_if_user_authorised(auth, CORE_AUTOMATION_API_WRITE_ROLE):
        raise UnauthorizedException("User is not authorised to perform this action")

    # Get the action handler or raise an exception
    action_handler = __get_action_handler(action)

    # Call the handler
    response = action_handler(**data)

    return response


# This is the geneeric lamda handler that will be used to route all requests to the appropriate action
def handler_direct(event: dict, context: Any | None = None) -> dict:
    """
    This is the legacy action handler.  It's a custom core-automation API

    event: {
        'action': 'portfolio:create',
        'data': {
            'name': 'example'
        },
        'auth': {
            'user': 'example'
        }
    }

    Returns whatever the handling function returns

    Returns:
        dict: A dictionary with the response.  There is no JSON encoding here.
    """
    try:
        log.set_identity("core_api_handler_direct")

        # At the moment this really doesn't do anything except validate the event
        request = Request(**event)
        response = process_request(request)

        if not isinstance(response, Response):
            raise TypeError(
                f"Handler returned type {type(response)}, expected Response object"
            )

        # We expect a "Response" object to be returned, we simply need to dump it
        lambda_response = response.model_dump()

        log.info(
            "Action complete",
            details={
                "action": request.action,
                "data": request.data,
                "auth": request.auth,
                "result": lambda_response,
            },
        )

        return lambda_response

    except Exception as e:
        return ErrorResponse(e).model_dump()
