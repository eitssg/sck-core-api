# pylint: disable=unused-argument

from collections import ChainMap

from core_db.response import Response
from core_db.registry.app.actions import AppActions

from core_api.oauth.auth_client import RouteEndpoint
from core_api.security import Permission


from ..actions import ApiActions


class ApiRegAppActions(ApiActions, AppActions):

    pass


def list_app_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegAppActions.list(**dict(ChainMap(body, pp, qsp)))


def get_app_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegAppActions.get(**dict(ChainMap(body, pp, qsp)))


def create_app_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegAppActions.create(**dict(ChainMap(body, pp, qsp)))


def update_app_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegAppActions.update(**dict(ChainMap(body, pp, qsp)))


def patch_app_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegAppActions.patch(**dict(ChainMap(body, pp, qsp)))


def delete_app_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegAppActions.delete(**dict(ChainMap(body, pp, qsp)))


registry_app_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/registry/{client}/{portfolio}/apps": RouteEndpoint(list_app_action, required_permissions={Permission.DATA_READ}),
    "POST:/api/v1/registry/{client}/{portfolio}/app": RouteEndpoint(
        create_app_action, required_permissions={Permission.DATA_WRITE}
    ),
    "PUT:/api/v1/registry/{client}/{portfolio}/app": RouteEndpoint(update_app_action, required_permissions={Permission.DATA_WRITE}),
    "DELETE:/api/v1/registry/{client}/{portfolio}/app": RouteEndpoint(
        delete_app_action, required_permissions={Permission.DATA_WRITE}
    ),
    "PATCH:/api/v1/registry/{client}/{portfolio}/app": RouteEndpoint(
        patch_app_action, required_permissions={Permission.DATA_WRITE}
    ),
}
