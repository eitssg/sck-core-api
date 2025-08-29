"""
This module contains the schemas for the core API for the APP Fact.

Each deployment will be conducted for a "client_portfolio" and will need to match
the regular expressions provided within the defintion.

typically the user will always perform action_get_list() to retrieve all the deployment defintions (There wont be many).

The user will then perform action_get_item() to retrieve the deployment definition for a specific app.

"""

from collections import ChainMap

from core_db.response import Response
from core_db.registry.portfolio.actions import PortfolioActions

from ..security import Permission

from ..request import ActionHandlerRoutes, RouteEndpoint

from ..actions import ApiActions


class ApiRegPortfolioActions(ApiActions, PortfolioActions):
    pass


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
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegPortfolioActions.list(**dict(ChainMap(body, pp, qsp)))


def get_portfolio_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    """
    Returns a portfolio for the client.
    """
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegPortfolioActions.get(**dict(ChainMap(body, pp, qsp)))


def create_portfolio_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegPortfolioActions.create(**dict(ChainMap(body, pp, qsp)))


def update_portfolio_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegPortfolioActions.update(**dict(ChainMap(body, pp, qsp)))


def patch_portfolio_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegPortfolioActions.patch(**dict(ChainMap(body, pp, qsp)))


def delete_portfolio_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiRegPortfolioActions.delete(**dict(ChainMap(body, pp, qsp)))


registry_portfolio_actions: ActionHandlerRoutes = {
    "GET:/api/v1/registry/{client}/portfolios": RouteEndpoint(list_portfolios_action, required_permissions={Permission.DATA_READ}),
    "POST:/api/v1/registry/{client}/portfolios": RouteEndpoint(
        create_portfolio_action, required_permissions={Permission.DATA_WRITE}
    ),
    "GET:/api/v1/registry/{client}/portfolio/{portfolio}": RouteEndpoint(
        get_portfolio_action, required_permissions={Permission.DATA_READ}
    ),
    "PUT:/api/v1/registry/{client}/portfolio/{portfolio}": RouteEndpoint(
        update_portfolio_action, required_permissions={Permission.DATA_WRITE}
    ),
    "DELETE:/api/v1/registry/{client}/portfolio/{portfolio}": RouteEndpoint(
        delete_portfolio_action, required_permissions={Permission.DATA_WRITE}
    ),
    "PATCH:/api/v1/registry/{client}/portfolio/{portfolio}": RouteEndpoint(
        patch_portfolio_action, required_permissions={Permission.DATA_WRITE}
    ),
}
