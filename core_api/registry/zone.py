from collections import ChainMap

import core_logging as log

from core_db.response import ErrorResponse, Response, SuccessResponse
from core_db.registry.zone import ZoneActions, ZoneFact
from core_db.exceptions import NotFoundException, ConflictException

from ..request import ActionHandlerRoutes, RouteEndpoint

from ..actions import ApiActions

from ..security import Permission


class ApiRegZoneActions(ApiActions, ZoneActions):

    pass


def _merge_map(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> dict:
    pp = path_params or {}
    body = body or {}
    qsp = query_params or {}
    return dict(ChainMap(body, pp, qsp))


def list_zones_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    try:
        client = path_params.get("client")

        log.debug(f"Listing zones for client '{client}'", details={"params": merged})

        result = ApiRegZoneActions.list(client=client, **merged)

        # The DB returns data in PascalCase, but we want to return in snake_case
        data = [ZoneFact(**item).model_dump(by_alias=False) for item in result.data]

        log.debug(f"Listed {len(data)} zones for client '{client}'", details={"zones": data})

        return SuccessResponse(data=data, metadata=result.metadata)

    except Exception as e:
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def get_zone_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    try:
        client = path_params.get("client")
        zone = path_params.get("zone")

        log.debug(f"Getting zone for client '{client}' zone '{zone}'", details={"params": merged})

        result = ApiRegZoneActions.get(client=client, zone=zone, **merged)

        # The DB returns data in PascalCase, but we want to return in snake_case
        data = ZoneFact(**result.data).model_dump(by_alias=False)

        log.debug(f"Got zone for client '{client}' zone '{zone}'", details=data)

        return SuccessResponse(data=data)

    except NotFoundException as e:
        return ErrorResponse(code=404, message="Zone not found", exception=e)
    except Exception as e:
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def create_zones_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    try:
        client = path_params.get("client")

        log.debug(f"Creating zone for client '{client}'", details={"params": merged})

        result = ApiRegZoneActions.create(client=client, **merged)

        # The DB returns data in PascalCase, but we want to return in snake_case
        data = ZoneFact(**result).model_dump(by_alias=False)

        log.debug(f"Created zone for client '{client}'", details=data)

        return SuccessResponse(data=data)

    except ConflictException as e:
        return ErrorResponse(code=409, message="Conflict error", exception=e)
    except Exception as e:
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def update_zones_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    try:
        client = path_params.get("client")
        if "client" in merged:
            del merged["client"]
        zone = path_params.get("zone")
        if "zone" in merged:
            del merged["zone"]

        log.debug(f"Updating zone for client '{client}' zone '{zone}'", details={"params": merged})

        result = ApiRegZoneActions.update(client=client, zone=zone, **merged)

        # The DB returns data in PascalCase, but we want to return in snake_case
        data = ZoneFact(**result.data).model_dump(by_alias=False)

        log.debug(f"Updated zone for client '{client}'", details=data)

        return SuccessResponse(data=data)

    except NotFoundException as e:
        return ErrorResponse(code=404, message="Zone not found", exception=e)
    except ConflictException as e:
        return ErrorResponse(code=409, message="Conflict error", exception=e)
    except Exception as e:
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def patch_zones_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    try:
        client = path_params.get("client")
        zone = path_params.get("zone")

        log.debug(f"Patching zone for client '{client}' zone '{zone}'", details={"params": merged})

        result = ApiRegZoneActions.patch(client=client, zone=zone, **merged)

        # The DB returns data in PascalCase, but we want to return in snake_case
        data = ZoneFact(**result.data).model_dump(by_alias=False)

        log.debug(f"Patched zone for client '{client}'", details=data)

        return SuccessResponse(data=data)

    except NotFoundException as e:
        return ErrorResponse(code=404, message="Zone not found", exception=e)
    except ConflictException as e:
        return ErrorResponse(code=409, message="Conflict error", exception=e)
    except Exception as e:
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def delete_zones_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    try:
        client = path_params.get("client")
        zone = path_params.get("zone")

        log.debug(f"Deleting zone for client '{client}' zone '{zone}'", details={"params": merged})

        ApiRegZoneActions.delete(client=client, zone=zone, **merged)

        log.debug(f"Deleted zone for client '{client}' zone '{zone}'")

        return SuccessResponse(code=204, message="Zone deleted")

    except NotFoundException as e:
        return ErrorResponse(code=204)
    except Exception as e:
        return ErrorResponse(code=500, message="Internal server error", exception=e)


registry_zone_actions: ActionHandlerRoutes = {
    "GET:/api/v1/registry/clients/{client}/zones": RouteEndpoint(
        list_zones_action,
        client_isolation=True,
        required_permissions={Permission.DATA_READ},
    ),
    "POST:/api/v1/registry/clients/{client}/zones": RouteEndpoint(
        create_zones_action,
        client_isolation=True,
        required_permissions={Permission.CLIENT_MANAGE},
    ),
    "GET:/api/v1/registry/clients/{client}/zones/{zone}": RouteEndpoint(
        get_zone_action,
        client_isolation=True,
        required_permissions={Permission.DATA_READ},
    ),
    "PUT:/api/v1/registry/clients/{client}/zones/{zone}": RouteEndpoint(
        update_zones_action,
        client_isolation=True,
        required_permissions={Permission.CLIENT_WRITE},
    ),
    "DELETE:/api/v1/registry/clients/{client}/zones/{zone}": RouteEndpoint(
        delete_zones_action,
        client_isolation=True,
        required_permissions={Permission.CLIENT_MANAGE},
    ),
    "PATCH:/api/v1/registry/clients/{client}/zones/{zone}": RouteEndpoint(
        patch_zones_action,
        client_isolation=True,
        required_permissions={Permission.CLIENT_WRITE},
    ),
}
