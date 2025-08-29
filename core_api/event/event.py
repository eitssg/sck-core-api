# pylint: disable=unused-argument
from collections import ChainMap


from core_db.event.actions import EventActions
from core_db.response import Response

from ..actions import ApiActions
from ..request import RouteEndpoint


class ApiEventActions(ApiActions, EventActions):

    pass


def action_get_event_list(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
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
        SeccessResponse: a list of all the respones in the SuccessRepsonse body.
    """
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiEventActions.list(**dict(ChainMap(body, pp, qsp)))


def action_create_event(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
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
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiEventActions.create(**dict(ChainMap(body, pp, qsp)))


def action_delete_event(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
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
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiEventActions.delete(**dict(ChainMap(body, pp, qsp)))


event_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/events": RouteEndpoint(action_get_event_list, permissions=["read:events"]),
    "PUT:/api/v1/event": RouteEndpoint(action_create_event, permissions=["create:event"]),
    "DELETE:/api/v1/event": RouteEndpoint(action_delete_event, permissions=["delete:event"]),
}
