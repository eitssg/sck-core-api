from collections import ChainMap
from core_db.response import Response
from core_db.item.component.actions import ComponentActions

from ..request import RouteEndpoint

from ..actions import ApiActions


class ApiComponentActions(ApiActions, ComponentActions):
    pass


def get_component_list_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiComponentActions.list(**dict(ChainMap(body, pp, qsp)))


def get_component_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiComponentActions.get(**dict(ChainMap(body, pp, qsp)))


def create_component_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiComponentActions.create(**dict(ChainMap(body, pp, qsp)))


def update_component_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiComponentActions.update(**dict(ChainMap(body, pp, qsp)))


def delete_component_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiComponentActions.delete(**dict(ChainMap(body, pp, qsp)))


# API Gateway Lambda Proxy Integration routes
item_component_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/items/components": RouteEndpoint(get_component_list_action, permissions=["read:components"]),
    "GET:/api/v1/items/component": RouteEndpoint(get_component_action, permissions=["read:component"]),
    "POST:/api/v1/items/component": RouteEndpoint(create_component_action, permissions=["create:component"]),
    "PUT:/api/v1/items/component": RouteEndpoint(update_component_action, permissions=["update:component"]),
    "DELETE:/api/v1/items/component": RouteEndpoint(delete_component_action, permissions=["delete:component"]),
}
