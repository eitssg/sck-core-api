from collections import ChainMap

from core_db.item.branch.actions import BranchActions
from core_db.exceptions import BadRequestException, NotFoundException, ConflictException, ForbiddenException
from moto.awslambda.models import Permission

from ..request import RouteEndpoint
from ..security import EnhancedSecurityContext, Permission
from ..response import Response, SuccessResponse, ErrorResponse
from ..actions import ApiActions


class ApiBranchActions(ApiActions, BranchActions):

    pass


def _merged(query_params: dict, path_params: dict, body: dict) -> dict:
    args = dict(ChainMap(path_params, query_params, body))
    if "client" in args:
        del args["client"]
    return args

def get_branch_list_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        results, paginator = ApiBranchActions.list(client=security.client, **args)
        data = [item.model_dump(by_alias=False, mode="json") for item in results]
        return SuccessResponse(data=data, metadata=paginator.get_metadata())

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def get_branch_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        result = ApiBranchActions.get(client=security.client, **args)
        data = result.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data)

    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def post_branch_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        result = ApiBranchActions.create(client=security.client, **args)
        data = result.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data, code=201)

    except ConflictException as e:
        return ErrorResponse(code=409, message=str(e))

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def put_branch_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        result = ApiBranchActions.update(client=security.client, **args)
        data = result.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data)

    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def delete_branch_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        ApiBranchActions.delete(client=security.client, **args)
        return SuccessResponse(code=204)

    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


# API Gateway Lambda Proxy Integration routes
item_branch_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/item/branches": RouteEndpoint(
        get_branch_list_action,
        required_permissions={Permission.ITEM_BRANCH_READ},
    ),
    "GET:/api/v1/item/branch": RouteEndpoint(
        get_branch_action,
        required_permissions={Permission.ITEM_BRANCH_READ},
    ),
    "POST:/api/v1/item/branches": RouteEndpoint(
        post_branch_action,
        required_permissions={Permission.ITEM_BRANCH_WRITE},
    ),
    "PUT:/api/v1/item/branch": RouteEndpoint(
        put_branch_action,
        required_permissions={Permission.ITEM_BRANCH_WRITE},
    ),
    "DELETE:/api/v1/item/branch": RouteEndpoint(
        delete_branch_action,
        required_permissions={Permission.ITEM_BRANCH_ADMIN},
    ),
}
