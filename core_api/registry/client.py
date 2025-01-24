from collections import ChainMap

from core_db.response import Response
from core_db.registry.client.actions import ClientActions

from ..constants import BODY_PARAMETER, PATH_PARAMETERS, QUERY_STRING_PARAMETERS

from ..request import ActionHandlerRoutes

from ..actions import ApiActions


class ApiRegClientActions(ApiActions, ClientActions):

    pass


def get_client_list_action(**kwargs) -> Response:
    """
    Handler for GET /api/v1/clients endpoint.
    Lists all clients in the platform.

    Args:
        event (dict): Lambda event object containing queryStringParameters

    Returns:
        Response: list of client names
    """
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegClientActions.list(**dict(ChainMap(body, pp, qsp)))


def get_client_action(**kwargs) -> Response:
    """
    Handler for GET /api/v1/client/{client} endpoint.
    Retrieves details for a specific client.

    Args:
        event (dict): Lambda event object containing pathParameters with client name

    Returns:
        Response: Client details or 404 if not found
    """
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegClientActions.get(**dict(ChainMap(body, pp, qsp)))


def create_client_action(**kwargs) -> Response:
    """
    Handler for POST /api/v1/client endpoint.
    Creates a new client.

    Args:
        event (dict): Lambda event object containing body with client details

    Returns:
        Response: Created client details or error if client exists
    """
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegClientActions.create(**dict(ChainMap(body, pp, qsp)))


def update_client_action(**kwargs) -> Response:
    """
    Handler for PUT /api/v1/client/{client} endpoint.
    Fully updates a client or creates if doesn't exist.

    Args:
        event (dict): Lambda event object containing pathParameters and body

    Returns:
        Response: Updated client details
    """
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegClientActions.update(**dict(ChainMap(body, pp, qsp)))


def patch_client_action(**kwargs) -> Response:
    """
    Handler for PATCH /api/v1/client/{client} endpoint.
    Partially updates an existing client.

    Args:
        event (dict): Lambda event object containing pathParameters and body

    Returns:
        Response: Updated client details or 404 if not found
    """
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegClientActions.patch(**dict(ChainMap(body, pp, qsp)))


def delete_client_action(**kwargs) -> Response:
    """
    Handler for DELETE /api/v1/client/{client} endpoint.
    Deletes a client if it exists.

    Args:
        event (dict): Lambda event object containing pathParameters with client name

    Returns:
        Response: 204 No Content on success
    """
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegClientActions.delete(**dict(ChainMap(body, pp, qsp)))


registry_client_actions: ActionHandlerRoutes = {
    r"GET:/api/v1/registry/clients": get_client_list_action,
    r"POST:/api/v1/registry/clients": create_client_action,
    r"GET:/api/v1/registry/client/{client}": get_client_action,
    r"PUT:/api/v1/registry/client/{client}": update_client_action,
    r"DELETE:/api/v1/registry/client/{client}": delete_client_action,
    r"PATCH:/api/v1/registry/client/{client}": patch_client_action,
}
