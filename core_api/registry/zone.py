from collections import ChainMap

from botocore import args
import core_logging as log

from core_db.registry.zone import ZoneActions, ZoneFact
from core_db.exceptions import NotFoundException, ConflictException, BadRequestException, ForbiddenException

from ..request import ActionHandlerRoutes, RouteEndpoint
from ..actions import ApiActions
from ..response import ErrorResponse, Response, SuccessResponse
from ..security import EnhancedSecurityContext, Permission


class ApiRegZoneActions(ApiActions, ZoneActions):

    pass


def _merged(query_params: dict, path_params: dict, body: dict, skip: list[str] = None) -> dict:
    args = dict(ChainMap(path_params, query_params, body))
    if skip:
        for key in skip:
            if key in args: 
                del args[key]
    return args

def list_zones_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:

    client = path_params.get("client")

    args = _merged(query_params, path_params, body, skip=["client"])

    if not client or client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client mismatch or missing")

    try:

        log.debug(f"Listing zones for client '{client}'", details={"params": args})

        results, paginator = ApiRegZoneActions.list(client=client, **args)

        # The DB returns data in PascalCase, but we want to return in snake_case
        data = [item.model_dump(by_alias=False, mode="json") for item in results]

        log.debug(f"Listed {len(data)} zones for client '{client}'", details={"zones": data})

        return SuccessResponse(data=data, metadata=paginator.get_metadata())

    except BadRequestException as e:
        return ErrorResponse(code=400, message=f"Bad request: {str(e)}")

    except Exception as e:
        return ErrorResponse(code=500, message=f"Internal server error: {str(e)}", exception=e)


def get_zone_action(*, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:

    client = path_params.get("client")
    zone = path_params.get("zone")

    args = _merged(query_params, path_params, body, skip=["client", "zone"])

    if not client or client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client or zone mismatch or missing or unauthorized")

    if not zone:
        return ErrorResponse(code=400, message="Bad request: Missing zone parameter")

    try:
        log.debug(f"Getting zone for client '{client}' zone '{zone}'", details={"params": args})

        result = ApiRegZoneActions.get(client=client, zone=zone, **args)

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
    
    client = path_params.get("client")

    args = _merged(query_params, path_params, body, skip=["client"])
    
    if not client or client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client mismatch or missing or unauthorized")
    try:

        log.debug(f"Creating zone for client '{client}'", details={"params": args})

        result = ApiRegZoneActions.create(client=client, **args)

        # The DB returns data in PascalCase, but we want to return in snake_case
        data = result.model_dump(by_alias=False, mode="json")

        log.debug(f"Created zone for client '{client}'", details=data)

        return SuccessResponse(code=201, data=data)

    except ConflictException as e:
        return ErrorResponse(code=409, message=f"Conflict error: {str(e)}")
    
    except BadRequestException as e:
        return ErrorResponse(code=400, message=f"Bad request: {str(e)}")
    
    except Exception as e:
        return ErrorResponse(code=500, message=f"Internal server error: {str(e)}", exception=e)


def update_zones_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    client = path_params.get("client")
    zone = path_params.get("zone")

    args = _merged(query_params, path_params, body, skip=["client", "zone"])

    if not client or client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client mismatch or missing or unauthorized")

    if not zone:
        return ErrorResponse(code=400, message="Bad request: Missing zone parameter")

    try:

        log.debug(f"Updating zone for client '{client}' zone '{zone}'", details={"params": args})

        result = ApiRegZoneActions.update(client=client, zone=zone, **args)

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
    client = path_params.get("client")
    zone = path_params.get("zone")

    args = _merged(query_params, path_params, body, skip=["client", "zone"])

    if not client or client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client mismatch or missing or unauthorized")

    if not zone:
        return ErrorResponse(code=400, message="Bad request: Missing zone parameter")

    try:
        log.debug(f"Patching zone for client '{client}' zone '{zone}'", details={"params": args})

        result = ApiRegZoneActions.patch(client=client, zone=zone, **args)

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
    client = path_params.get("client")
    zone = path_params.get("zone")

    args = _merged(query_params, path_params, body, skip=["client", "zone"])

    if not client or client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client mismatch or missing or unauthorized")

    if not zone:
        return ErrorResponse(code=400, message="Bad request: Missing zone parameter")

    try:

        log.debug(f"Deleting zone for client '{client}' zone '{zone}'", details={"params": args})

        ApiRegZoneActions.delete(client=client, zone=zone, **args)

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
