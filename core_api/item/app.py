from collections import ChainMap

from core_db.item.app.actions import AppActions
from core_db.exceptions import BadRequestException, NotFoundException, ConflictException, ForbiddenException

from ..request import RouteEndpoint
from ..security import EnhancedSecurityContext, Permission
from ..response import Response, SuccessResponse, ErrorResponse
from ..actions import ApiActions


class ApiAppActions(ApiActions, AppActions):

    pass


def _merged(query_params: dict, path_params: dict, body: dict) -> dict:
    args = dict(ChainMap(path_params, query_params, body))
    if "client" in args:
        del args["client"]
    return args

def get_app_list_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:
        args = _merged(query_params, path_params, body)

        result, paginator = ApiAppActions.list(client=security.client, **args)
        data = [item.model_dump(by_alias=False, mode="json") for item in result]
        return SuccessResponse(data=data, metadata=paginator.get_metadata())

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def get_app_action(*, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        result = ApiAppActions.get(client=security.client, **args)
        data = result.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data)

    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def create_app_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        result = ApiAppActions.create(client=security.client, **args)
        data = result.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data, code=201)

    except ConflictException as e:
        return ErrorResponse(code=409, message=str(e))

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def delete_app_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        ApiAppActions.delete(client=security.client, **args)
        return SuccessResponse(code=204)

    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))

    except ForbiddenException as e:
        return ErrorResponse(code=403, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def update_app_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        result = ApiAppActions.update(client=security.client, **args)
        data = result.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data)

    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))

    except ForbiddenException as e:
        return ErrorResponse(code=403, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


# Define API Gateway routes
item_app_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/items/apps": RouteEndpoint(
        get_app_list_action,
        required_permissions={Permission.ITEM_APP_READ},
    ),
    "GET:/api/v1/items/app": RouteEndpoint(
        get_app_action,
        required_permissions={Permission.ITEM_APP_READ},
    ),
    "POST:/api/v1/items/app": RouteEndpoint(
        create_app_action,
        required_permissions={Permission.ITEM_APP_WRITE},
    ),
    "DELETE:/api/v1/items/app": RouteEndpoint(
        delete_app_action,
        required_permissions={Permission.ITEM_APP_ADMIN},
    ),
    "PUT:/api/v1/items/app": RouteEndpoint(
        update_app_action,
        required_permissions={Permission.ITEM_APP_WRITE},
    ),
}
