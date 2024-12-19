from core_db.response import Response
from core_db.registry.zone.actions import ZoneActions

from ..constants import PATH_PARAMETERS, BODY_PARAMETER

from ..types import ActionHandlerRoutes

from ..actions import ApiActions


class ApiRegZoneActions(ApiActions, ZoneActions):

    pass


def list_zones_action(**kwargs) -> Response:
    return ApiRegZoneActions.list(**kwargs.get(PATH_PARAMETERS, {}))


def get_zone_action(**kwargs) -> Response:
    return ApiRegZoneActions.get(**kwargs.get(PATH_PARAMETERS, {}))


def create_zones_action(**kwargs) -> Response:
    return ApiRegZoneActions.create(
        **kwargs.get(PATH_PARAMETERS, {}),
        **kwargs.get(BODY_PARAMETER, {}),
    )


def update_zones_action(**kwargs) -> Response:
    return ApiRegZoneActions.update(
        **kwargs.get(PATH_PARAMETERS, {}),
        **kwargs.get(BODY_PARAMETER, {}),
    )


def patch_zones_action(**kwargs) -> Response:
    return ApiRegZoneActions.patch(
        **kwargs.get(PATH_PARAMETERS, {}),
        **kwargs.get(BODY_PARAMETER, {}),
    )


def delete_zones_action(**kwargs) -> Response:
    return ApiRegZoneActions.delete(**kwargs.get(PATH_PARAMETERS, {}))


registry_zone_actions: ActionHandlerRoutes = {
    "GET:/api/v1/registry/{client}/{portfolio}/zones": list_zones_action,
    "POST:/api/v1/registry/{client}/{portfolio}/zone": create_zones_action,
    "GET:/api/v1/registry/{client}/{portfolio}/zone/{zone}": get_zone_action,
    "PUT:/api/v1/registry/{client}/{portfolio}/zone/{zone}": update_zones_action,
    "DELETE:/api/v1/registry/{client}/{portfolio}/zone/{zone}": delete_zones_action,
    "PATCH:/api/v1/registry/{client}/{portfolio}/zone/{zone}": patch_zones_action,
}
