# pylint: disable=unused-argument

from collections import ChainMap

from core_db.response import Response, SuccessResponse, ErrorResponse
from core_db.registry.app import AppActions, AppFact

from core_api.item import app
from core_api.auth.auth_client import RouteEndpoint
from core_api.security import Permission

from ..actions import ApiActions


class ApiRegAppActions(ApiActions, AppActions):

    pass


def _merge_params(query_params: dict = None, path_params: dict = None, body: dict = None) -> dict:
    qsp = query_params or {}
    body = body or {}
    return dict(ChainMap(body, qsp))


def list_app_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_params(query_params, path_params, body)

    client = path_params.get("client")
    portfolio = path_params.get("portfolio")

    if "client" in merged:
        del merged["client"]
    if "portfolio" in merged:
        del merged["portfolio"]

    try:
        response = ApiRegAppActions.list(client=client, portfolio=portfolio, **merged)

        exclude_fields = {
            "image_aliases",
            "tags",
            "metadata",
        }

        # The database responds in PascalCase, but we want to return in snake_case
        data = [AppFact(**item).model_dump(by_alias=False, mode="json", exclude=exclude_fields) for item in response.data]

        # metadata preserved (e.g. for pagination and filters)
        return SuccessResponse(data=data, metadata=response.metadata)  # code 200 implied

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def create_app_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_params(query_params, path_params, body)

    client = path_params.get("client")
    portfolio = path_params.get("portfolio")

    if "client" in merged:
        del merged["client"]
    if "portfolio" in merged:
        del merged["portfolio"]

    try:
        response = ApiRegAppActions.create(client=client, portfolio=portfolio, **merged)

        # The database responds in PascalCase, but we want to return in snake_case
        data = AppFact(**response.data).model_dump(by_alias=False, mode="json")

        # returns the fully created object
        return SuccessResponse(code=201, data=data)  # 201 Created

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def get_app_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_params(query_params, path_params, body)

    client = path_params.get("client")
    portfolio = path_params.get("portfolio")
    app = path_params.get("app")

    if "client" in merged:
        del merged["client"]
    if "portfolio" in merged:
        del merged["portfolio"]
    if "app" in merged:
        del merged["app"]

    try:

        response = ApiRegAppActions.get(client=client, portfolio=portfolio, app=app, **merged)

        # The database responds in PascalCase, but we want to return in snake_case
        data = AppFact(**response.data).model_dump(by_alias=False, mode="json")

        return SuccessResponse(data=data)

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def update_app_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_params(query_params, path_params, body)

    client = path_params.get("client")
    portfolio = path_params.get("portfolio")
    app = path_params.get("app")

    if "client" in merged:
        del merged["client"]
    if "portfolio" in merged:
        del merged["portfolio"]
    if "app" in merged:
        del merged["app"]

    try:
        response = ApiRegAppActions.update(client=client, portfolio=portfolio, app=app, **merged)
        data = AppFact(**response.data).model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data)
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def patch_app_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_params(query_params, path_params, body)

    client = path_params.get("client")
    portfolio = path_params.get("portfolio")
    app = path_params.get("app")

    if "client" in merged:
        del merged["client"]
    if "portfolio" in merged:
        del merged["portfolio"]
    if "app" in merged:
        del merged["app"]

    try:
        response = ApiRegAppActions.patch(client=client, portfolio=portfolio, app=app, **merged)
        data = AppFact(**response.data).model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data)
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def delete_app_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_params(query_params, path_params, body)

    client = path_params.get("client")
    portfolio = path_params.get("portfolio")
    app = path_params.get("app")

    if "client" in merged:
        del merged["client"]
    if "portfolio" in merged:
        del merged["portfolio"]
    if "app" in merged:
        del merged["app"]

    try:
        response = ApiRegAppActions.delete(client=client, portfolio=portfolio, app=app, **merged)
        data = AppFact(**response.data).model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data)
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


registry_app_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/registry/clients/{client}/portfolios/{portfolio}/apps": RouteEndpoint(
        list_app_action,
        required_permissions={Permission.DATA_READ},
    ),
    "POST:/api/v1/registry/clients/{client}/portfolios/{portfolio}/apps": RouteEndpoint(
        create_app_action,
        required_permissions={Permission.DATA_WRITE},
    ),
    "GET:/api/v1/registry/clients/{client}/portfolios/{portfolio}/apps/{app}": RouteEndpoint(
        get_app_action,
        required_permissions={Permission.DATA_READ},
    ),
    "PUT:/api/v1/registry/clients/{client}/portfolios/{portfolio}/apps/{app}": RouteEndpoint(
        update_app_action,
        required_permissions={Permission.DATA_WRITE},
    ),
    "DELETE:/api/v1/registry/clients/{client}/portfolios/{portfolio}/apps/{app}": RouteEndpoint(
        delete_app_action,
        required_permissions={Permission.DATA_WRITE},
    ),
    "PATCH:/api/v1/registry/clients/{client}/portfolios/{portfolio}/apps/{app}": RouteEndpoint(
        patch_app_action,
        required_permissions={Permission.DATA_WRITE},
    ),
}
