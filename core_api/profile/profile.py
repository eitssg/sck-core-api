from collections import ChainMap

from core_db.response import Response
from core_db.profile.actions import ProfileActions

from ..security import Permission

from ..request import RouteEndpoint

from ..actions import ApiActions


class ApiProfileActions(ApiActions, ProfileActions):

    pass


def list_profile_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiProfileActions.list(**dict(ChainMap(body, pp, qsp)))


def get_profile_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiProfileActions.get(**dict(ChainMap(body, pp, qsp)))


def create_profile_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiProfileActions.create(**dict(ChainMap(body, pp, qsp)))


def update_profile_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiProfileActions.update(**dict(ChainMap(body, pp, qsp)))


def patch_profile_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiProfileActions.patch(**dict(ChainMap(body, pp, qsp)))


def delete_profile_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiProfileActions.delete(**dict(ChainMap(body, pp, qsp)))


registry_profile_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/profiles/{client}/{portfolio}/apps": RouteEndpoint(
        list_profile_action, required_permissions={Permission.DATA_READ}
    ),
    "GET:/api/v1/profiles/{client}/{portfolio}/app": RouteEndpoint(get_profile_action, required_permissions={Permission.DATA_READ}),
    "POST:/api/v1/profiles/{client}/{portfolio}/app": RouteEndpoint(
        create_profile_action, required_permissions={Permission.DATA_WRITE}
    ),
    "PUT:/api/v1/profiles/{client}/{portfolio}/app": RouteEndpoint(
        update_profile_action, required_permissions={Permission.DATA_WRITE}
    ),
    "DELETE:/api/v1/profiles/{client}/{portfolio}/app": RouteEndpoint(
        delete_profile_action, required_permissions={Permission.DATA_WRITE}
    ),
    "PATCH:/api/v1/profiles/{client}/{portfolio}/app": RouteEndpoint(
        patch_profile_action, required_permissions={Permission.DATA_WRITE}
    ),
}
