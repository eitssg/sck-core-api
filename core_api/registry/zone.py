from collections import ChainMap

import core_logging as log

from core_db.registry.zone import ZoneActions, ZoneFact
from core_db.exceptions import NotFoundException, ConflictException, BadRequestException, ForbiddenException

from ..request import ActionHandlerRoutes, RouteEndpoint
from ..actions import ApiActions
from ..response import ErrorResponse, Response, SuccessResponse
from ..security import EnhancedSecurityContext, Permission


class ApiRegZoneActions(ApiActions, ZoneActions):

    pass


def _merge_map(*, query_params: dict, path_params: dict, body: dict, **kwargs) -> dict:
    return dict(ChainMap(body, path_params, query_params))


def list_zones_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:

    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = path_params.get("client")

    if not client or client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client mismatch or missing")

    if "client" in merged:
        del merged["client"]

    try:

        log.debug(f"Listing zones for client '{client}'", details={"params": merged})

        results, paginator = ApiRegZoneActions.list(client=client, **merged)

        # The DB returns data in PascalCase, but we want to return in snake_case
        data = [item.model_dump(by_alias=False, mode="json") for item in results]

        log.debug(f"Listed {len(data)} zones for client '{client}'", details={"zones": data})

        return SuccessResponse(data=data, metadata=paginator.get_metadata())

    except BadRequestException as e:
        return ErrorResponse(code=400, message=f"Bad request: {str(e)}")

    except Exception as e:
        return ErrorResponse(code=500, message=f"Internal server error: {str(e)}", exception=e)


def get_zone_action(*, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = path_params.get("client")

    if not client or client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client or zone mismatch or missing or unauthorized")

    if "client" in merged:
        del merged["client"]

    try:
        zone = path_params.get("zone")

        if not zone:
            return ErrorResponse(code=400, message="Bad request: Missing zone parameter")

        if "zone" in merged:
            del merged["zone"]

        log.debug(f"Getting zone for client '{client}' zone '{zone}'", details={"params": merged})

        result = ApiRegZoneActions.get(client=client, zone=zone, **merged)

        # The DB returns data in PascalCase, but we want to return in snake_case
        data = result.model_dump(by_alias=False, mode="json")

        log.debug(f"Got zone for client '{client}' zone '{zone}'", details=data)

        return SuccessResponse(data=data)

    except NotFoundException as e:
        return ErrorResponse(code=404, message="Zone not found")

    except BadRequestException as e:
        return ErrorResponse(code=400, message="Bad request")

    except Exception as e:
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def create_zones_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = path_params.get("client")

    if not client or client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client mismatch or missing or unauthorized")

    if "client" in merged:
        del merged["client"]

    try:

        log.debug(f"Creating zone for client '{client}'", details={"params": merged})

        result = ApiRegZoneActions.create(client=client, **merged)

        # The DB returns data in PascalCase, but we want to return in snake_case
        data = result.model_dump(by_alias=False, mode="json")

        log.debug(f"Created zone for client '{client}'", details=data)

        return SuccessResponse(data=data)

    except ConflictException as e:
        return ErrorResponse(code=409, message="Conflict error", exception=e)
    except Exception as e:
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def update_zones_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = path_params.get("client")

    if "client" in merged:
        del merged["client"]

    if not client or client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client mismatch or missing or unauthorized")

    try:
        zone = path_params.get("zone")

        if not zone:
            return ErrorResponse(code=400, message="Bad request: Missing zone parameter")

        if "zone" in merged:
            del merged["zone"]

        log.debug(f"Updating zone for client '{client}' zone '{zone}'", details={"params": merged})

        result = ApiRegZoneActions.update(client=client, zone=zone, **merged)

        # The DB returns data in PascalCase, but we want to return in snake_case
        data = result.model_dump(by_alias=False, mode="json")

        log.debug(f"Updated zone for client '{client}'", details=data)

        return SuccessResponse(data=data)

    except NotFoundException as e:
        return ErrorResponse(code=404, message=f"Zone not found: {str(e)}")

    except ConflictException as e:
        return ErrorResponse(code=409, message=f"Conflict error: {str(e)}")

    except Exception as e:
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def patch_zones_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = path_params.get("client")

    if not client or client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client mismatch or missing or unauthorized")

    if "client" in merged:
        del merged["client"]

    try:
        zone = path_params.get("zone")

        if not zone:
            return ErrorResponse(code=400, message="Bad request: Missing zone parameter")

        if "zone" in merged:
            del merged["zone"]

        log.debug(f"Patching zone for client '{client}' zone '{zone}'", details={"params": merged})

        result = ApiRegZoneActions.patch(client=client, zone=zone, **merged)

        # The DB returns data in PascalCase, but we want to return in snake_case
        data = result.model_dump(by_alias=False, mode="json")

        log.debug(f"Patched zone for client '{client}'", details=data)

        return SuccessResponse(data=data)

    except NotFoundException as e:
        return ErrorResponse(code=404, message=f"Zone not found: {str(e)}")

    except ConflictException as e:
        return ErrorResponse(code=409, message=f"Conflict error: {str(e)}")

    except Exception as e:
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def delete_zones_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = path_params.get("client")

    if not client or client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client mismatch or missing or unauthorized")

    if "client" in merged:
        del merged["client"]

    try:
        zone = path_params.get("zone")

        if not zone:
            return ErrorResponse(code=400, message="Bad request: Missing zone parameter")

        if "zone" in merged:
            del merged["zone"]

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
        required_permissions={Permission.REGISTRY_ZONE_READ},
    ),
    "POST:/api/v1/registry/clients/{client}/zones": RouteEndpoint(
        create_zones_action,
        client_isolation=True,
        required_permissions={Permission.REGISTRY_ZONE_ADMIN},
    ),
    "GET:/api/v1/registry/clients/{client}/zones/{zone}": RouteEndpoint(
        get_zone_action,
        client_isolation=True,
        required_permissions={Permission.REGISTRY_ZONE_READ},
    ),
    "PUT:/api/v1/registry/clients/{client}/zones/{zone}": RouteEndpoint(
        update_zones_action,
        client_isolation=True,
        required_permissions={Permission.REGISTRY_ZONE_WRITE},
    ),
    "DELETE:/api/v1/registry/clients/{client}/zones/{zone}": RouteEndpoint(
        delete_zones_action,
        client_isolation=True,
        required_permissions={Permission.REGISTRY_ZONE_ADMIN},
    ),
    "PATCH:/api/v1/registry/clients/{client}/zones/{zone}": RouteEndpoint(
        patch_zones_action,
        client_isolation=True,
        required_permissions={Permission.REGISTRY_ZONE_WRITE},
    ),
}
