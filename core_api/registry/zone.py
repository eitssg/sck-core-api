from collections import ChainMap

from core_db.response import Response
from core_db.registry.zone.actions import ZoneActions

from ..constants import PATH_PARAMETERS, BODY_PARAMETER, QUERY_STRING_PARAMETERS

from ..request import ActionHandlerRoutes

from ..actions import ApiActions


class ApiRegZoneActions(ApiActions, ZoneActions):

    pass


def list_zones_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegZoneActions.list(**dict(ChainMap(body, pp, qsp)))


def get_zone_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegZoneActions.get(**dict(ChainMap(body, pp, qsp)))


def create_zones_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegZoneActions.create(**dict(ChainMap(body, pp, qsp)))


def update_zones_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegZoneActions.update(**dict(ChainMap(body, pp, qsp)))


def patch_zones_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegZoneActions.patch(**dict(ChainMap(body, pp, qsp)))


def delete_zones_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegZoneActions.delete(**dict(ChainMap(body, pp, qsp)))


registry_zone_actions: ActionHandlerRoutes = {
    "GET:/api/v1/registry/{client}/zones": list_zones_action,
    "POST:/api/v1/registry/{client}/zone": create_zones_action,
    "GET:/api/v1/registry/{client}/zone/{zone}": get_zone_action,
    "PUT:/api/v1/registry/{client}/zone/{zone}": update_zones_action,
    "DELETE:/api/v1/registry/{client}/zone/{zone}": delete_zones_action,
    "PATCH:/api/v1/registry/{client}/zone/{zone}": patch_zones_action,
}
