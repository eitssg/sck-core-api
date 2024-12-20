from collections import ChainMap

from ..constants import (
    QUERY_STRING_PARAMETERS,
    PATH_PARAMETERS,
    BODY_PARAMETER,
)

from ..types import ActionHandlerRoutes

from core_db.item.app.actions import AppActions
from core_db.response import Response

from ..actions import ApiActions


class ApiAppActions(ApiActions, AppActions):

    pass


def get_app_list_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiAppActions.list(**dict(ChainMap(body, pp, qsp)))


def get_app_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiAppActions.get(**dict(ChainMap(body, pp, qsp)))


def create_app_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiAppActions.create(**dict(ChainMap(body, pp, qsp)))


def delete_app_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiAppActions.delete(**dict(ChainMap(body, pp, qsp)))


def update_app_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiAppActions.update(**dict(ChainMap(body, pp, qsp)))


# API Gateway Lambda Proxy Integration routes
item_app_actions: ActionHandlerRoutes = {
    "GET:/api/v1/items/apps": get_app_list_action,
    "GET:/api/v1/items/app": get_app_action,
    "POST:/api/v1/items/app": create_app_action,
    "DELETE:/api/v1/items/app": delete_app_action,
    "PUT:/api/v1/items/app": update_app_action,
}
