from core_db.response import Response
from core_db.item.component.actions import ComponentActions

from ..constants import QUERY_STRING_PARAMETERS, BODY_PARAMETER
from ..types import ActionHandlerRoutes

from ..actions import ApiActions


class ApiComponentActions(ApiActions, ComponentActions):

    pass


def get_component_list_action(**kwargs) -> Response:
    return ApiComponentActions.list(**kwargs.get(QUERY_STRING_PARAMETERS, {}))


def get_component_action(**kwargs) -> Response:
    return ApiComponentActions.get(**kwargs.get(QUERY_STRING_PARAMETERS, {}))


def create_component_action(**kwargs) -> Response:
    return ApiComponentActions.create(**kwargs.get(BODY_PARAMETER, {}))


def update_component_action(**kwargs) -> Response:
    return ApiComponentActions.update(
        **kwargs.get(BODY_PARAMETER, {}), **kwargs.get(QUERY_STRING_PARAMETERS, {})
    )


def delete_component_action(**kwargs) -> Response:
    return ApiComponentActions.delete(**kwargs.get(QUERY_STRING_PARAMETERS, {}))


# API Gateway Lambda Proxy Integration routes
item_component_actions: ActionHandlerRoutes = {
    "GET:/api/v1/items/components": get_component_list_action,
    "GET:/api/v1/items/component": get_component_action,
    "POST:/api/v1/items/component": create_component_action,
    "PUT:/api/v1/items/component": update_component_action,
    "DELETE:/api/v1/items/component": delete_component_action,
}
