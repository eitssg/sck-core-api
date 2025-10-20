# pylint: disable=unused-argument
from collections import ChainMap

from core_db.event.actions import EventActions
from core_db.exceptions import BadRequestException, NotFoundException, ConflictException, ForbiddenException

from ..security import EnhancedSecurityContext, Permission
from ..actions import ApiActions
from ..request import RouteEndpoint
from ..response import Response, SuccessResponse, ErrorResponse


class ApiEventActions(ApiActions, EventActions):

    pass


def action_get_event_list(*, query_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    """
    returns the event for the given prn and timestamp.  Because you
    may leav timestamp blank, there may be more than one event for the prn,
    so, this fuction will always return a list.

    From the query parametrs, you can specify the prn and the earliest_time and latest_time

    Ex:
      event = {
        "queryStringParameters": {
            "prn": "client:portfolio:app:branch:build:component",
            "earliest_time": "2021-01-01T00:00:00",
            "latest_time": "2021-01-02T00:00:00",
            "sort": "ascending",
            "limit": 100,
            "data_paginator": None
      }

    Args:
        event (dict): the event form an http request (lambda event)

    Returns:
        SuccessResponse: a list of all the responses in the SuccessResponse body.
    """
    try:
        results, paginator = ApiEventActions.list(client=security.client, **dict(ChainMap(body, query_params)))
        data = [item.model_dump(by_alias=False, mode="json") for item in results]
        return SuccessResponse(data=data, metadata=paginator.get_metadata())
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def action_create_event(*, query_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    """
    creates a new event

    Ex:
      evnet = {
        "body": {
            "prn": "client:portfolio:app:branch:build:component",
            "timestamp": "2021-01-01T00:00:00",
            "event_type": "status",
            "status": "success",
            "message": "Build success"
        }
      }

    Args:
        event (dict): The event to create from REST API
    """
    try:
        data = ApiEventActions.create(client=security.client, **dict(ChainMap(body, query_params)))
        return SuccessResponse(data=data.model_dump(by_alias=False, mode="json"), code=201)
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def action_delete_event(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    """
    deletes the event for the given prn in the parameters

    Ex:
        event = {
            "queryStringParameters": {
                "prn": "client:portfolio:app:branch:build:component"
            }
        }

    Args:
        event (dict): The lambda event
    """
    try:
        ApiEventActions.delete(client=security.client, **dict(ChainMap(body, path_params, query_params)))
        return SuccessResponse(code=204)
    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


event_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/events": RouteEndpoint(
        action_get_event_list,
        permissions=[Permission.EVENT_READ],
        client_isolated=True,
    ),
    "PUT:/api/v1/event": RouteEndpoint(
        action_create_event,
        permissions=[Permission.EVENT_CREATE],
        client_isolated=True,
    ),
    "DELETE:/api/v1/event": RouteEndpoint(
        action_delete_event,
        permissions=[Permission.EVENT_ADMIN],
        client_isolated=True,
    ),
}
