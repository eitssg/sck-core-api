from ..constants import (
    QUERY_STRING_PARAMETERS,
    BODY_PARAMETER,
)

from ..types import ActionHandlerRoutes

from core_db.item.app.actions import AppActions
from core_db.response import Response

from ..actions import ApiActions


class ApiAppActions(ApiActions, AppActions):

    pass


def get_app_list_action(**kwargs) -> Response:
    return ApiAppActions.list(**kwargs.get(QUERY_STRING_PARAMETERS, {}))


def get_app_action(**kwargs) -> Response:
    return ApiAppActions.get(**kwargs.get(QUERY_STRING_PARAMETERS, {}))


def create_app_action(**kwargs) -> Response:
    return ApiAppActions.create(**kwargs.get(BODY_PARAMETER, {}))


def delete_app_action(**kwargs) -> Response:
    return ApiAppActions.delete(**kwargs.get(QUERY_STRING_PARAMETERS, {}))


def update_app_action(**kwargs) -> Response:
    return ApiAppActions.update(
        **kwargs.get(BODY_PARAMETER, {}),
        **kwargs.get(QUERY_STRING_PARAMETERS, {}),
    )


# API Gateway Lambda Proxy Integration routes
item_app_actions: ActionHandlerRoutes = {
    "GET:/api/v1/items/apps": get_app_list_action,
    "GET:/api/v1/items/app": get_app_action,
    "POST:/api/v1/items/app": create_app_action,
    "DELETE:/api/v1/items/app": delete_app_action,
    "PUT:/api/v1/items/app": update_app_action,
}
