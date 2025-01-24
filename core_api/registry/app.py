from collections import ChainMap

from core_db.response import Response
from core_db.registry.app.actions import AppActions

from ..constants import (
    QUERY_STRING_PARAMETERS,
    PATH_PARAMETERS,
    BODY_PARAMETER,
)

from ..request import ActionHandlerRoutes

from ..actions import ApiActions


class ApiRegAppActions(ApiActions, AppActions):

    pass


def list_app_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegAppActions.list(**dict(ChainMap(body, pp, qsp)))


def get_app_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegAppActions.get(**dict(ChainMap(body, pp, qsp)))


def create_app_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegAppActions.create(**dict(ChainMap(body, pp, qsp)))


def update_app_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegAppActions.update(**dict(ChainMap(body, pp, qsp)))


def patch_app_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegAppActions.patch(**dict(ChainMap(body, pp, qsp)))


def delete_app_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegAppActions.delete(**dict(ChainMap(body, pp, qsp)))


registry_app_actions: ActionHandlerRoutes = {
    "GET:/api/v1/registry/{client}/{portfolio}/apps": list_app_action,
    "POST:/api/v1/registry/{client}/{portfolio}/app": create_app_action,
    "PUT:/api/v1/registry/{client}/{portfolio}/app": update_app_action,
    "DELETE:/api/v1/registry/{client}/{portfolio}/app": delete_app_action,
    "PATCH:/api/v1/registry/{client}/{portfolio}/app": patch_app_action,
}
