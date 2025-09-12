"""
This module contains the schemas for the core API for the APP Fact.

Each deployment will be conducted for a "client_portfolio" and will need to match
the regular expressions provided within the defintion.

typically the user will always perform action_get_list() to retrieve all the deployment defintions (There wont be many).

The user will then perform action_get_item() to retrieve the deployment definition for a specific app.

"""

from collections import ChainMap

import core_logging as log

from core_db.response import Response, SuccessResponse, ErrorResponse
from core_db.registry.portfolio import PortfolioActions, PortfolioFact

from ..security import Permission

from ..request import ActionHandlerRoutes, RouteEndpoint

from ..actions import ApiActions


class ApiRegPortfolioActions(ApiActions, PortfolioActions):
    pass


def _merge_map(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> dict:
    pp = path_params or {}
    body = body or {}
    qsp = query_params or {}
    return dict(ChainMap(body, pp, qsp))


def list_portfolios_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    """
    Returns a list of all portfolios for the client.

    Specify client as a path parameter.

    The cilent is a slug.

    Ex:
        event = {
            PATH_PARAMETERS: {
                "client": "the_client"
            }
        }

    Args:
        event (): Http Request Object from API Gateway to lambda (lambda event)

    Returns:
        Response: AWS Api Gateway Response
    """
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = (path_params or {}).get("client")
    if "client" in merged:
        del merged["client"]

    log.debug(
        "List portfolios request",
        details={
            "client": client,
            "filters": merged,
        },
    )

    try:
        result = ApiRegPortfolioActions.list(client=client, **merged)

        # Minimal fields for the list view (snake_case names from PortfolioFact)
        include_fields = {
            "portfolio",  # unique id/slug
            "name",  # display title
            "icon_url",  # icon for card/list
            "category",  # facet/category
            "labels",  # chips/facets
            "portfolio_version",  # optional version tag
            "lifecycle_status",  # status pill
            "business_owner",  # owner summary
            "technical_owner",  # owner summary
            "domain",  # optional domain
        }

        # The DB returns data in PascalCase, but we want to return in snake_case
        data = [PortfolioFact(**item).model_dump(by_alias=False, include=include_fields, mode="json") for item in result.data]

        log.debug(
            f"Listed {len(data)} portfolios",
            details={
                "client": client,
                "count": len(data),
                "include_fields": sorted(include_fields),
            },
        )

        return SuccessResponse(data=data, metadata=result.metadata)

    except Exception as e:
        log.error("List portfolios failed", details={"client": client, "error": str(e)}, exc_info=True)
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def get_portfolio_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    """
    Returns a portfolio for the client.
    """
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = (path_params or {}).get("client")
    portfolio = (path_params or {}).get("portfolio")

    if "client" in merged:
        del merged["client"]
    if "portfolio" in merged:
        del merged["portfolio"]

    try:
        log.debug(
            "Get portfolio request",
            details={"client": client, "portfolio": portfolio, "filters": merged},
        )
        result = ApiRegPortfolioActions.get(client=client, portfolio=portfolio, **merged)

        data = PortfolioFact(**result.data).model_dump(by_alias=False)

        log.debug(
            "Get portfolio success",
            details={"client": client, "portfolio": portfolio},
        )
        return SuccessResponse(data=data)
    except Exception as e:
        log.error(
            "Get portfolio failed",
            details={"client": client, "portfolio": portfolio, "error": str(e)},
            exc_info=True,
        )
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def create_portfolio_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = (path_params or {}).get("client")

    if "client" in merged:
        del merged["client"]

    try:
        log.debug("Create portfolio request", details={"client": client, "payload": merged})
        result = ApiRegPortfolioActions.create(client=client, **merged)

        data = PortfolioFact(**result.data).model_dump(by_alias=False)

        log.debug("Create portfolio success", details={"client": client, "portfolio": data.get("portfolio")})
        return SuccessResponse(data=data)
    except Exception as e:
        log.error("Create portfolio failed", details={"client": client, "error": str(e)}, exc_info=True)
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def update_portfolio_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = (path_params or {}).get("client")
    portfolio = (path_params or {}).get("portfolio")

    if "client" in merged:
        del merged["client"]
    if "portfolio" in merged:
        del merged["portfolio"]

    try:
        log.debug(
            "Update portfolio request",
            details={"client": client, "portfolio": portfolio, "payload": merged},
        )
        result = ApiRegPortfolioActions.update(client=client, portfolio=portfolio, **merged)

        data = PortfolioFact(**result.data).model_dump(by_alias=False)

        log.debug("Update portfolio success", details={"client": client, "portfolio": portfolio})
        return SuccessResponse(data=data)
    except Exception as e:
        log.error(
            "Update portfolio failed",
            details={"client": client, "portfolio": portfolio, "error": str(e)},
            exc_info=True,
        )
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def patch_portfolio_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = (path_params or {}).get("client")
    portfolio = (path_params or {}).get("portfolio")

    if "client" in merged:
        del merged["client"]
    if "portfolio" in merged:
        del merged["portfolio"]

    try:
        log.debug(
            "Patch portfolio request",
            details={"client": client, "portfolio": portfolio, "payload": merged},
        )
        result = ApiRegPortfolioActions.patch(client=client, portfolio=portfolio, **merged)

        data = PortfolioFact(**result.data).model_dump(by_alias=False)

        log.debug("Patch portfolio success", details={"client": client, "portfolio": portfolio})
        return SuccessResponse(data=data)

    except Exception as e:
        log.error(
            "Patch portfolio failed",
            details={"client": client, "portfolio": portfolio, "error": str(e)},
            exc_info=True,
        )
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def delete_portfolio_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = (path_params or {}).get("client")
    portfolio = (path_params or {}).get("portfolio")

    if "client" in merged:
        del merged["client"]
    if "portfolio" in merged:
        del merged["portfolio"]

    try:
        log.debug(
            "Delete portfolio request",
            details={"client": client, "portfolio": portfolio},
        )

        ApiRegPortfolioActions.delete(client=client, portfolio=portfolio, **merged)

        log.debug("Delete portfolio success", details={"client": client, "portfolio": portfolio})
        return SuccessResponse(message="Portfolio deleted successfully")

    except Exception as e:
        log.error(
            "Delete portfolio failed",
            details={"client": client, "portfolio": portfolio, "error": str(e)},
            exc_info=True,
        )
        return ErrorResponse(code=500, message="Internal server error", exception=e)


registry_portfolio_actions: ActionHandlerRoutes = {
    "GET:/api/v1/registry/clients/{client}/portfolios": RouteEndpoint(
        list_portfolios_action,
        required_permissions={Permission.DATA_READ},
    ),
    "POST:/api/v1/registry/clients/{client}/portfolios": RouteEndpoint(
        create_portfolio_action,
        required_permissions={Permission.DATA_WRITE},
    ),
    "GET:/api/v1/registry/clients/{client}/portfolios/{portfolio}": RouteEndpoint(
        get_portfolio_action,
        required_permissions={Permission.DATA_READ},
    ),
    "PUT:/api/v1/registry/clients/{client}/portfolios/{portfolio}": RouteEndpoint(
        update_portfolio_action,
        required_permissions={Permission.DATA_WRITE},
    ),
    "DELETE:/api/v1/registry/clients/{client}/portfolios/{portfolio}": RouteEndpoint(
        delete_portfolio_action,
        required_permissions={Permission.DATA_WRITE},
    ),
    "PATCH:/api/v1/registry/clients/{client}/portfolios/{portfolio}": RouteEndpoint(
        patch_portfolio_action,
        required_permissions={Permission.DATA_WRITE},
    ),
}
