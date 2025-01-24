from collections import ChainMap
from core_db.response import Response
from core_db.item.component.actions import ComponentActions

from ..constants import QUERY_STRING_PARAMETERS, PATH_PARAMETERS, BODY_PARAMETER

from ..request import ActionHandlerRoutes

from ..actions import ApiActions


class ApiComponentActions(ApiActions, ComponentActions):

    pass


def get_component_list_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiComponentActions.list(**dict(ChainMap(body, pp, qsp)))


def get_component_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiComponentActions.get(**dict(ChainMap(body, pp, qsp)))


def create_component_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiComponentActions.create(**dict(ChainMap(body, pp, qsp)))


def update_component_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiComponentActions.update(**dict(ChainMap(body, pp, qsp)))


def delete_component_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiComponentActions.delete(**dict(ChainMap(body, pp, qsp)))


# API Gateway Lambda Proxy Integration routes
item_component_actions: ActionHandlerRoutes = {
    "GET:/api/v1/items/components": get_component_list_action,
    "GET:/api/v1/items/component": get_component_action,
    "POST:/api/v1/items/component": create_component_action,
    "PUT:/api/v1/items/component": update_component_action,
    "DELETE:/api/v1/items/component": delete_component_action,
}
