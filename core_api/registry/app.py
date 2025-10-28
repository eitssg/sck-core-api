# pylint: disable=unused-argument

from calendar import c
from collections import ChainMap

from botocore import args
from core_db.registry.app import AppActions, AppFact
from core_db.exceptions import BadRequestException, NotFoundException, ConflictException, ForbiddenException

from ..auth.auth_client import RouteEndpoint

from ..actions import ApiActions
from ..security import EnhancedSecurityContext, Permission
from ..response import Response, SuccessResponse, ErrorResponse


class ApiRegAppActions(ApiActions, AppActions):

    pass


def _merged(query_params: dict, path_params: dict, body: dict, skip: list[str] = None) -> dict:
    args = dict(ChainMap(path_params, query_params, body))
    if skip:
        for key in skip:
            if key in args: 
                del args[key]
    return args


def list_app_action(*, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    
    client = path_params.get("client")
    portfolio = path_params.get("portfolio")

    args = _merged(query_params, path_params, body, skip=["client", "portfolio"])

    if not client or not portfolio:
        return ErrorResponse(code=400, message="Bad request: Missing required path parameters")

    if client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client mismatch or unauthorized")

    try:
        response, paginator = ApiRegAppActions.list(client=client, portfolio=portfolio, **args)

        exclude_fields = {
            "image_aliases",
            "tags",
            "metadata",
        }

        # The database responds in PascalCase, but we want to return in snake_case
        data = [item.model_dump(by_alias=False, mode="json", exclude=exclude_fields) for item in response]

        # metadata preserved (e.g. for pagination and filters)
        return SuccessResponse(data=data, metadata=paginator.get_metadata())  # code 200 implied

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def create_app_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    
    client = path_params.get("client")
    portfolio = path_params.get("portfolio")

    args = _merged(query_params, path_params, body, skip=["client", "portfolio"])

    if not client or not portfolio:
        return ErrorResponse(code=400, message="Bad request: Missing required path parameters")

    if client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client mismatch or unauthorized")

    try:
        response = ApiRegAppActions.create(client=client, portfolio=portfolio, **args)

        # The database responds in PascalCase, but we want to return in snake_case
        data = response.model_dump(by_alias=False, mode="json")

        # returns the fully created object
        return SuccessResponse(code=201, data=data)  # 201 Created

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except ConflictException as e:
        return ErrorResponse(code=409, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def get_app_action(*, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:

    client = path_params.get("client")
    portfolio = path_params.get("portfolio")
    app = path_params.get("app")

    args = _merged(query_params, path_params, body, skip=["client", "portfolio", "app"])

    if not client or not portfolio or not app:
        return ErrorResponse(code=400, message="Bad request: Missing required path parameters")

    if client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client mismatch or unauthorized")

    try:

        response = ApiRegAppActions.get(client=client, portfolio=portfolio, app=app, **args)

        # The database responds in PascalCase, but we want to return in snake_case
        data = response.model_dump(by_alias=False, mode="json")

        return SuccessResponse(data=data)

    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def update_app_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    
    client = path_params.get("client")
    portfolio = path_params.get("portfolio")
    app = path_params.get("app")

    args = _merged(query_params, path_params, body, skip=["client", "portfolio", "app"])

    if not client or not portfolio or not app:
        return ErrorResponse(code=400, message="Bad request: Missing required path parameters")

    if client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client mismatch or unauthorized")

    try:

        response = ApiRegAppActions.update(client=client, portfolio=portfolio, app=app, **args)
        data = response.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data)

    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except ConflictException as e:
        return ErrorResponse(code=409, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def patch_app_action(*, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    client = path_params.get("client")
    portfolio = path_params.get("portfolio")
    app = path_params.get("app")

    args = _merged(query_params, path_params, body, skip=["client", "portfolio", "app"])

    if not client or not portfolio or not app:
        return ErrorResponse(code=400, message="Bad request: Missing required path parameters")

    if client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client mismatch or unauthorized")

    try:

        response = ApiRegAppActions.patch(client=client, portfolio=portfolio, app=app, **args)
        data = response.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data)

    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except ConflictException as e:
        return ErrorResponse(code=409, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def delete_app_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:

    client = path_params.get("client")
    portfolio = path_params.get("portfolio")
    app = path_params.get("app")

    args = _merged(query_params, path_params, body, skip=["client", "portfolio", "app"])

    if not client or not portfolio or not app:
        return ErrorResponse(code=400, message="Bad request: Missing required parameters")

    if client != security.client:
        return ErrorResponse(code=403, message="Forbidden: Client mismatch or unauthorized")

    try:
        ApiRegAppActions.delete(client=client, portfolio=portfolio, app=app, **args)
        return SuccessResponse(code=204)

    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except ConflictException as e:
        return ErrorResponse(code=409, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


registry_app_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/registry/clients/{client}/portfolios/{portfolio}/apps": RouteEndpoint(
        list_app_action,
        required_permissions={Permission.REGISTRY_APP_READ},
    ),
    "POST:/api/v1/registry/clients/{client}/portfolios/{portfolio}/apps": RouteEndpoint(
        create_app_action,
        required_permissions={Permission.REGISTRY_APP_WRITE},
    ),
    "GET:/api/v1/registry/clients/{client}/portfolios/{portfolio}/apps/{app}": RouteEndpoint(
        get_app_action,
        required_permissions={Permission.REGISTRY_APP_READ},
    ),
    "PUT:/api/v1/registry/clients/{client}/portfolios/{portfolio}/apps/{app}": RouteEndpoint(
        update_app_action,
        required_permissions={Permission.REGISTRY_APP_WRITE},
    ),
    "DELETE:/api/v1/registry/clients/{client}/portfolios/{portfolio}/apps/{app}": RouteEndpoint(
        delete_app_action,
        required_permissions={Permission.REGISTRY_APP_WRITE},
    ),
    "PATCH:/api/v1/registry/clients/{client}/portfolios/{portfolio}/apps/{app}": RouteEndpoint(
        patch_app_action,
        required_permissions={Permission.REGISTRY_APP_WRITE},
    ),
}
