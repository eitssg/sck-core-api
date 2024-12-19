"""
This module contains the schemas for the core API for the APP Fact.

Each deployment will be conducted for a "client_portfolio" and will need to match
the regular expressions provided within the defintion.

typically the user will always perform action_get_list() to retrieve all the deployment defintions (There wont be many).

The user will then perform action_get_item() to retrieve the deployment definition for a specific app.

"""

from core_db.response import Response
from core_db.registry.portfolio.actions import PortfolioActions

from ..constants import PATH_PARAMETERS

from ..types import ActionHandlerRoutes

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
    return ApiRegPortfolioActions.list(**kwargs.get(PATH_PARAMETERS, {}))


def get_portfolio_action(**kwargs) -> Response:
    """
    Returns a portfolio for the client.
    """
    return ApiRegPortfolioActions.get(**kwargs.get(PATH_PARAMETERS, {}))


def create_portfolio_action(**kwargs) -> Response:
    return ApiRegPortfolioActions.create(
        **kwargs.get("body", {}), **kwargs.get(PATH_PARAMETERS, {})
    )


def update_portfolio_action(**kwargs) -> Response:
    return ApiRegPortfolioActions.update(
        **kwargs.get("body", {}), **kwargs.get(PATH_PARAMETERS, {})
    )


def patch_portfolio_action(**kwargs) -> Response:
    return ApiRegPortfolioActions.patch(
        **kwargs.get("body", {}), **kwargs.get(PATH_PARAMETERS, {})
    )


def delete_portfolio_action(**kwargs) -> Response:
    return ApiRegPortfolioActions.delete(**kwargs.get(PATH_PARAMETERS, {}))


registry_portfolio_actions: ActionHandlerRoutes = {
    "GET:/api/v1/registry/{client}/portfolios": list_portfolios_action,
    "POST:/api/v1/registry/{client}/portfolios": create_portfolio_action,
    "GET:/api/v1/registry/{client}/portfolio/{portfolio}": get_portfolio_action,
    "PUT:/api/v1/registry/{client}/portfolio/{portfolio}": update_portfolio_action,
    "DELETE:/api/v1/registry/{client}/portfolio/{portfolio}": delete_portfolio_action,
    "PATCH:/api/v1/registry/{client}/portfolio/{portfolio}": patch_portfolio_action,
}
