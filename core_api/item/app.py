from collections import ChainMap

from core_db.item.app.actions import AppActions
from core_db.exceptions import BadRequestException, NotFoundException, ConflictException, ForbiddenException

from ..request import RouteEndpoint
from ..security import EnhancedSecurityContext, Permission
from ..response import Response, SuccessResponse, ErrorResponse
from ..actions import ApiActions


class ApiAppActions(ApiActions, AppActions):

    pass


def get_app_list_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:
        result, paginator = ApiAppActions.list(client=security.client, **dict(ChainMap(body, query_params, path_params)))
        data = [item.model_dump(by_alias=False, mode="json") for item in result]
        return SuccessResponse(data=data, metadata=paginator.get_metadata())
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def get_app_action(*, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    try:
        result = ApiAppActions.get(client=security.client, **dict(ChainMap(body, path_params, query_params)))
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
        result = ApiAppActions.create(client=security.client, **dict(ChainMap(body, path_params, query_params)))
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
        ApiAppActions.delete(client=security.client, **dict(ChainMap(body, path_params, query_params)))
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
        result = ApiAppActions.update(client=security.client, **dict(ChainMap(body, path_params, query_params)))
        data = result.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data)
    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))
    except ForbiddenException as e:
        return ErrorResponse(code=403, message=str(e))
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


# API Gateway Lambda Proxy Integration routes
item_app_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/items/apps": RouteEndpoint(
        get_app_list_action,
        permissions=[Permission.ITEM_APP_READ],
    ),
    "GET:/api/v1/items/app": RouteEndpoint(
        get_app_action,
        permissions=[Permission.ITEM_APP_READ],
    ),
    "POST:/api/v1/items/app": RouteEndpoint(
        create_app_action,
        permissions=[Permission.ITEM_APP_WRITE],
    ),
    "DELETE:/api/v1/items/app": RouteEndpoint(
        delete_app_action,
        permissions=[Permission.ITEM_APP_ADMIN],
    ),
    "PUT:/api/v1/items/app": RouteEndpoint(
        update_app_action,
        permissions=[Permission.ITEM_APP_WRITE],
    ),
}
