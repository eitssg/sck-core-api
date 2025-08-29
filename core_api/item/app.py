from collections import ChainMap

from core_db.item.app.actions import AppActions
from core_db.response import Response


from ..request import RouteEndpoint
from ..actions import ApiActions


class ApiAppActions(ApiActions, AppActions):

    pass


def get_app_list_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiAppActions.list(**dict(ChainMap(body, pp, qsp)))


def get_app_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiAppActions.get(**dict(ChainMap(body, pp, qsp)))


def create_app_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiAppActions.create(**dict(ChainMap(body, pp, qsp)))


def delete_app_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiAppActions.delete(**dict(ChainMap(body, pp, qsp)))


def update_app_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiAppActions.update(**dict(ChainMap(body, pp, qsp)))


# API Gateway Lambda Proxy Integration routes
item_app_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/items/apps": RouteEndpoint(get_app_list_action, permissions=["read:apps"]),
    "GET:/api/v1/items/app": RouteEndpoint(get_app_action, permissions=["read:app"]),
    "POST:/api/v1/items/app": RouteEndpoint(create_app_action, permissions=["create:app"]),
    "DELETE:/api/v1/items/app": RouteEndpoint(delete_app_action, permissions=["delete:app"]),
    "PUT:/api/v1/items/app": RouteEndpoint(update_app_action, permissions=["update:app"]),
}
