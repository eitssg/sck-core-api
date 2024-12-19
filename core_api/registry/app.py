from core_db.response import Response
from core_db.registry.app.actions import AppActions

from ..constants import (
    QUERY_STRING_PARAMETERS,
    PATH_PARAMETERS,
    BODY_PARAMETER,
)

from ..types import ActionHandlerRoutes

from ..actions import ApiActions


class ApiRegAppActions(ApiActions, AppActions):

    pass


def list_app_action(**kwargs) -> Response:
    return ApiRegAppActions.list(**kwargs.get(QUERY_STRING_PARAMETERS, {}))


def get_app_action(**kwargs) -> Response:
    return ApiRegAppActions.get(
        **kwargs.get(PATH_PARAMETERS, {}), **kwargs.get(QUERY_STRING_PARAMETERS, {})
    )


def create_app_action(**kwargs) -> Response:
    return ApiRegAppActions.create(
        **kwargs.get(PATH_PARAMETERS, {}), **kwargs.get(BODY_PARAMETER, {})
    )


def update_app_action(**kwargs) -> Response:
    return ApiRegAppActions.update(
        **kwargs.get(PATH_PARAMETERS, {}), **kwargs.get(BODY_PARAMETER, {})
    )


def patch_app_action(**kwargs) -> Response:
    return ApiRegAppActions.patch(
        **kwargs.get(PATH_PARAMETERS, {}), **kwargs.get("body", {})
    )


def delete_app_action(**kwargs) -> Response:
    return ApiRegAppActions.delete(
        **kwargs.get(PATH_PARAMETERS, {}), **kwargs.get(QUERY_STRING_PARAMETERS, {})
    )


registry_app_actions: ActionHandlerRoutes = {
    "GET:/api/v1/registry/{client}/{portfolio}/apps": list_app_action,
    "POST:/api/v1/registry/{client}/{portfolio}/app": create_app_action,
    "PUT:/api/v1/registry/{client}/{portfolio}/app": update_app_action,
    "DELETE:/api/v1/registry/{client}/{portfolio}/app": delete_app_action,
    "PATCH:/api/v1/registry/{client}/{portfolio}/app": patch_app_action,
}
