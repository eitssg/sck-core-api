from collections import ChainMap

from core_db.item.component import ComponentActions
from core_db.exceptions import BadRequestException, NotFoundException, ConflictException, ForbiddenException

from ..request import RouteEndpoint
from ..security import EnhancedSecurityContext, Permission
from ..response import Response, SuccessResponse, ErrorResponse
from ..actions import ApiActions


class ApiComponentActions(ApiActions, ComponentActions):
    pass

def _merged(query_params: dict, path_params: dict, body: dict) -> dict:
    args = dict(ChainMap(path_params, query_params, body))
    if "client" in args:
        del args["client"]
    return args

def get_component_list_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:
        args = _merged(query_params, path_params, body)

        result, paginator = ApiComponentActions.list(client=security.client, **args)
        data = [item.model_dump(by_alias=False, mode="json") for item in result]
        return SuccessResponse(data=data, metadata=paginator.get_metadata())

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def get_component_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        result = ApiComponentActions.get(client=security.client, **args)
        data = result.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data)

    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def create_component_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:
    
        args = _merged(query_params, path_params, body)

        result = ApiComponentActions.create(client=security.client, **args)
        data = result.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data, code=201)
    
    except ConflictException as e:
        return ErrorResponse(code=409, message=str(e))
    
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def update_component_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        result = ApiComponentActions.update(client=security.client, **args)
        data = result.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data)

    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def delete_component_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        ApiComponentActions.delete(client=security.client, **args)
        return SuccessResponse(code=204)

    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


# API Gateway Lambda Proxy Integration routes
item_component_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/items/components": RouteEndpoint(
        get_component_list_action,
        required_permissions={Permission.ITEM_COMPONENT_READ},
    ),
    "GET:/api/v1/items/component": RouteEndpoint(
        get_component_action,
        required_permissions={Permission.ITEM_COMPONENT_READ},
    ),
    "POST:/api/v1/items/component": RouteEndpoint(
        create_component_action,
        required_permissions={Permission.ITEM_COMPONENT_WRITE},
    ),
    "PUT:/api/v1/items/component": RouteEndpoint(
        update_component_action,
        required_permissions={Permission.ITEM_COMPONENT_WRITE},
    ),
    "DELETE:/api/v1/items/component": RouteEndpoint(
        delete_component_action,
        required_permissions={Permission.ITEM_COMPONENT_ADMIN},
    ),
}
