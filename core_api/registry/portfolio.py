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

from ..constants import PATH_PARAMETERS, QUERY_STRING_PARAMETERS, BODY_PARAMETER

from ..request import ActionHandlerRoutes

from ..actions import ApiActions


class ApiRegPortfolioActions(ApiActions, PortfolioActions):
    pass


def list_portfolios_action(**kwargs) -> Response:
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
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegPortfolioActions.list(**dict(ChainMap(body, pp, qsp)))


def get_portfolio_action(**kwargs) -> Response:
    """
    Returns a portfolio for the client.
    """
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegPortfolioActions.get(**dict(ChainMap(body, pp, qsp)))


def create_portfolio_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegPortfolioActions.create(**dict(ChainMap(body, pp, qsp)))


def update_portfolio_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegPortfolioActions.update(**dict(ChainMap(body, pp, qsp)))


def patch_portfolio_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegPortfolioActions.patch(**dict(ChainMap(body, pp, qsp)))


def delete_portfolio_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiRegPortfolioActions.delete(**dict(ChainMap(body, pp, qsp)))


registry_portfolio_actions: ActionHandlerRoutes = {
    "GET:/api/v1/registry/{client}/portfolios": list_portfolios_action,
    "POST:/api/v1/registry/{client}/portfolios": create_portfolio_action,
    "GET:/api/v1/registry/{client}/portfolio/{portfolio}": get_portfolio_action,
    "PUT:/api/v1/registry/{client}/portfolio/{portfolio}": update_portfolio_action,
    "DELETE:/api/v1/registry/{client}/portfolio/{portfolio}": delete_portfolio_action,
    "PATCH:/api/v1/registry/{client}/portfolio/{portfolio}": patch_portfolio_action,
}
