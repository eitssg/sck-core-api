from collections import ChainMap
from time import perf_counter
import os

import core_logging as log

from core_db.exceptions import NotFoundException
from core_db.registry.client import ClientActions, ClientFact

from core_api.security import Permission

from ..request import RouteEndpoint
from ..security import EnhancedSecurityContext, Permission
from ..response import SuccessResponse, ErrorResponse, Response
from ..actions import ApiActions


class ApiRegClientActions(ApiActions, ClientActions):

    pass


def get_client_list_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    """
    Handler for GET /api/v1/clients endpoint.
    Lists all clients in the platform.

    Args:
        event (dict): Lambda event object containing queryStringParameters

    Returns:
        Response: list of client names
    """

    start = perf_counter()
    log.debug("registry.clients.list.start", extra={"query_params": query_params})

    try:
        client_id = security.client_id

        results, paginator = ApiRegClientActions.list(client_id=client_id, **dict(ChainMap(body, path_params, query_params)))
        include_fields = {
            "client",
            "client_id",
            "client_name",
            "organization_name",
            "organization_account",
            "client_description",
        }

        data = [r.model_dump(by_alias=False, mode="json", include=include_fields) for r in results]

        duration = (perf_counter() - start) * 1000
        log.info(
            "registry.clients.list.success",
            extra={"count": len(data), "duration_ms": round(duration, 2)},
        )

        return SuccessResponse(data=data, metadata=paginator.get_metadata())

    except Exception as e:  # noqa: BLE001
        duration = (perf_counter() - start) * 1000
        log.error(
            "registry.clients.list.error",
            extra={"error": str(e), "duration_ms": round(duration, 2)},
        )
        return ErrorResponse(code=500, message=f"Failed to list clients: {str(e)}", exception=e)


def get_client_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    """Get a single client.

    Path: GET /api/v1/registry/clients/{client}
    """

    start = perf_counter()

    log.debug("registry.client.get.start", extra={"path_params": path_params})

    try:
        client = path_params.get("client")
        client_id = security.client_id

        if not client or not client_id:
            return ErrorResponse(message="Unauthorized to access this client", code=403)

        result = ApiRegClientActions.get(client_id=client_id, client=client)

        exclude_fields = {"client_secret", "credentials"}

        data = result.model_dump(by_alias=False, mode="json", exclude=exclude_fields)

        duration = (perf_counter() - start) * 1000
        log.info("registry.client.get.success", extra={"client": data.get("client"), "duration_ms": round(duration, 2)})

        return SuccessResponse(data=data, message="Client retrieved successfully")

    except Exception as e:  # noqa: BLE001
        duration = (perf_counter() - start) * 1000
        log.warning(
            "registry.client.get.error",
            extra={"error": str(e), "path_params": path_params, "duration_ms": round(duration, 2)},
        )
        return ErrorResponse(code=500, message=f"Client not found: {str(e)}", exception=e)


def create_client_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    """
    Handler for POST /api/v1/client endpoint.
    Creates a new client.

    Args:
        event (dict): Lambda event object containing body with client details

    Returns:
        Response: Created client details or error if client exists
    """
    start = perf_counter()

    log.debug("registry.client.create.start", extra={"body_keys": list(body.keys())})

    try:

        if not security.client_id:
            return ErrorResponse(message="Unauthorized to create client", code=403)

        client_fact = ClientFact.model_validate(dict(ChainMap(body, path_params, query_params)))

        # any new client must belong to the caller's client_id (a.k.a client group ID.  Or a.k.a oauth client id)
        client_fact.client_id = security.client_id

        result = ApiRegClientActions.create(record=client_fact)

        exclude_fields = {"client_secret", "credentials"}

        data = result.model_dump(by_alias=False, mode="json", exclude=exclude_fields)

        duration = (perf_counter() - start) * 1000
        log.info("registry.client.create.success", extra={"client": data.get("client"), "duration_ms": round(duration, 2)})

        return SuccessResponse(data=data, message="Client created successfully")

    except Exception as e:  # noqa: BLE001
        duration = (perf_counter() - start) * 1000
        log.error(
            "registry.client.create.error",
            extra={"error": str(e), "body_keys": list(body.keys()), "duration_ms": round(duration, 2)},
        )
        return ErrorResponse(code=500, message=f"Failed to create client: {str(e)}", exception=e)


def update_client_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    """Full update (idempotent) of a client.

    Path: PUT /api/v1/registry/clients/{client}
    """
    start = perf_counter()
    log.debug("registry.client.update.start", extra={"path_params": path_params, "body_keys": list(body.keys())})
    try:

        client_fact = ClientFact.model_validate(dict(ChainMap(body, path_params, query_params)))

        result = ApiRegClientActions.update(record=client_fact)

        exclude_fields = {"client_secret", "credentials"}

        data = result.model_dump(by_alias=False, mode="json", exclude=exclude_fields)
        duration = (perf_counter() - start) * 1000
        log.info(
            "registry.client.update.success",
            extra={"client": data.get("client"), "duration_ms": round(duration, 2)},
        )
        return SuccessResponse(data=data)

    except NotFoundException as e:  # noqa: BLE001
        duration = (perf_counter() - start) * 1000
        log.warning(
            "registry.client.update.notfound",
            extra={"error": str(e), "path_params": path_params, "duration_ms": round(duration, 2)},
        )
        return ErrorResponse(message=f"Client not found for update: {str(e)}", code=404)
    except Exception as e:  # noqa: BLE001
        return ErrorResponse(message=f"Failed to update client: {str(e)}", code=500, exception=e)


def patch_client_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    """Partial update for a client.

    Path: PATCH /api/v1/registry/clients/{client}
    """
    start = perf_counter()

    log.debug("registry.client.patch.start", extra={"path_params": path_params, "body_keys": list(body.keys())})

    try:
        result = ApiRegClientActions.patch(**dict(ChainMap(body, path_params, query_params)))

        exclude_fields = {"client_secret", "credentials"}

        data = result.model_dump(by_alias=False, mode="json", exclude=exclude_fields)

        duration = (perf_counter() - start) * 1000
        log.info(
            "registry.client.patch.success",
            extra={"client": data.get("client"), "duration_ms": round(duration, 2)},
        )

        return SuccessResponse(data=data)

    except NotFoundException as e:  # noqa: BLE001
        duration = (perf_counter() - start) * 1000
        log.warning(
            "registry.client.patch.notfound",
            extra={"error": str(e), "path_params": path_params, "duration_ms": round(duration, 2)},
        )
        return ErrorResponse(message=f"Client not found for patch: {str(e)}", code=404)
    except Exception as e:  # noqa: BLE001
        return ErrorResponse(message=f"Failed to patch client: {str(e)}", code=500, exception=e)


def delete_client_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    """Delete a client.

    Path: DELETE /api/v1/registry/clients/{client}
    """
    start = perf_counter()

    log.debug("registry.client.delete.start", extra={"path_params": path_params})
    try:

        client = path_params.get("client")
        client_id = security.client_id

        if not client or not client_id:
            return ErrorResponse(message="Client identifier is required for deletion", code=400)

        ApiRegClientActions.delete(client_id=client_id, client=client)

        duration = (perf_counter() - start) * 1000
        log.info("registry.client.delete.success", extra={"path_params": path_params, "duration_ms": round(duration, 2)})

        return SuccessResponse(message="Client deleted successfully")

    except Exception as e:  # noqa: BLE001
        duration = (perf_counter() - start) * 1000
        log.error(
            "registry.client.delete.error",
            extra={"error": str(e), "path_params": path_params, "duration_ms": round(duration, 2)},
        )
        return ErrorResponse(message=f"Failed to delete client: {str(e)}", code=500, exception=e)


registry_client_actions: dict[str, RouteEndpoint] = {
    # Collection endpoints
    "GET:/api/v1/registry/clients": RouteEndpoint(
        get_client_list_action,
        required_permissions={Permission.REGISTRY_CLIENT_READ},
    ),
    "POST:/api/v1/registry/clients": RouteEndpoint(
        create_client_action,
        required_permissions={Permission.REGISTRY_CLIENT_ADMIN},
    ),
    "GET:/api/v1/registry/clients/{client}": RouteEndpoint(
        get_client_action,
        required_permissions={Permission.REGISTRY_CLIENT_READ},
    ),
    "PUT:/api/v1/registry/clients/{client}": RouteEndpoint(
        update_client_action,
        required_permissions={Permission.REGISTRY_CLIENT_WRITE},
    ),
    "DELETE:/api/v1/registry/clients/{client}": RouteEndpoint(
        delete_client_action,
        required_permissions={Permission.REGISTRY_CLIENT_ADMIN},
    ),
    "PATCH:/api/v1/registry/clients/{client}": RouteEndpoint(
        patch_client_action,
        required_permissions={Permission.REGISTRY_CLIENT_WRITE},
    ),
}
