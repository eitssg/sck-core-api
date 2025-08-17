from collections import ChainMap

from core_db.response import Response
from core_db.profile.actions import ProfileActions

from ..constants import (
    QUERY_STRING_PARAMETERS,
    PATH_PARAMETERS,
    BODY_PARAMETER,
)

from ..request import ActionHandlerRoutes

from ..actions import ApiActions


class ApiProfileActions(ApiActions, ProfileActions):

    pass


def list_profile_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiProfileActions.list(**dict(ChainMap(body, pp, qsp)))


def get_profile_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiProfileActions.get(**dict(ChainMap(body, pp, qsp)))


def create_profile_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiProfileActions.create(**dict(ChainMap(body, pp, qsp)))


def update_profile_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiProfileActions.update(**dict(ChainMap(body, pp, qsp)))


def patch_profile_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiProfileActions.patch(**dict(ChainMap(body, pp, qsp)))


def delete_profile_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiProfileActions.delete(**dict(ChainMap(body, pp, qsp)))


registry_profile_actions: ActionHandlerRoutes = {
    "GET:/api/v1/profiles/{client}/{portfolio}/apps": list_profile_action,
    "GET:/api/v1/profiles/{client}/{portfolio}/apps": get_profile_action,
    "POST:/api/v1/profiles/{client}/{portfolio}/app": create_profile_action,
    "PUT:/api/v1/profiles/{client}/{portfolio}/app": update_profile_action,
    "DELETE:/api/v1/profiles/{client}/{portfolio}/app": delete_profile_action,
    "PATCH:/api/v1/profiles/{client}/{portfolio}/app": patch_profile_action,
}
