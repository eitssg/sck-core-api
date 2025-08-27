from collections import ChainMap

from core_db.response import Response
from core_db.registry.client.actions import ClientActions

from core_api.security import Permission

from ..request import RouteEndpoint

from ..actions import ApiActions


class ApiRegClientActions(ApiActions, ClientActions):

    pass


def get_client_list_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    """
    Handler for GET /api/v1/clients endpoint.
    Lists all clients in the platform.

    Args:
        event (dict): Lambda event object containing queryStringParameters

    Returns:
        Response: list of client names
    """
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegClientActions.list(**dict(ChainMap(body, pp, qsp)))


def get_client_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    """
    Handler for GET /api/v1/client/{client} endpoint.
    Retrieves details for a specific client.

    Args:
        event (dict): Lambda event object containing pathParameters with client name

    Returns:
        Response: Client details or 404 if not found
    """
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegClientActions.get(**dict(ChainMap(body, pp, qsp)))


def create_client_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    """
    Handler for POST /api/v1/client endpoint.
    Creates a new client.

    Args:
        event (dict): Lambda event object containing body with client details

    Returns:
        Response: Created client details or error if client exists
    """
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegClientActions.create(**dict(ChainMap(body, pp, qsp)))


def update_client_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    """
    Handler for PUT /api/v1/client/{client} endpoint.
    Fully updates a client or creates if doesn't exist.

    Args:
        event (dict): Lambda event object containing pathParameters and body

    Returns:
        Response: Updated client details
    """
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegClientActions.update(**dict(ChainMap(body, pp, qsp)))


def patch_client_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    """
    Handler for PATCH /api/v1/client/{client} endpoint.
    Partially updates an existing client.

    Args:
        event (dict): Lambda event object containing pathParameters and body

    Returns:
        Response: Updated client details or 404 if not found
    """
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegClientActions.patch(**dict(ChainMap(body, pp, qsp)))


def delete_client_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    """
    Handler for DELETE /api/v1/client/{client} endpoint.
    Deletes a client if it exists.

    Args:
        event (dict): Lambda event object containing pathParameters with client name

    Returns:
        Response: 204 No Content on success
    """
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegClientActions.delete(**dict(ChainMap(body, pp, qsp)))


registry_client_actions: dict[str, RouteEndpoint] = {
    r"GET:/api/v1/registry/clients": RouteEndpoint(get_client_list_action, required_permissions={Permission.DATA_READ}),
    r"POST:/api/v1/registry/clients": RouteEndpoint(create_client_action, required_permissions={Permission.DATA_WRITE}),
    r"GET:/api/v1/registry/client/{client}": RouteEndpoint(get_client_action, required_permissions={Permission.DATA_READ}),
    r"PUT:/api/v1/registry/client/{client}": RouteEndpoint(update_client_action, required_permissions={Permission.DATA_WRITE}),
    r"DELETE:/api/v1/registry/client/{client}": RouteEndpoint(delete_client_action, required_permissions={Permission.DATA_WRITE}),
    r"PATCH:/api/v1/registry/client/{client}": RouteEndpoint(patch_client_action, required_permissions={Permission.DATA_WRITE}),
}
