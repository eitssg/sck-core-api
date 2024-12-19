"""
This module contains the actions for the core API for the Portfolio ITEM Actions
"""

from core_db.response import Response
from core_db.item.portfolio.actions import PortfolioActions

from ..constants import (
    QUERY_STRING_PARAMETERS,
    BODY_PARAMETER,
)
from ..types import ActionHandlerRoutes

from ..actions import ApiActions


class ApiPortfolioActions(ApiActions, PortfolioActions):
    pass


def get_portfolio_list_action(**kwargs) -> Response:
    return ApiPortfolioActions.list(**kwargs.get(QUERY_STRING_PARAMETERS, {}))


def get_portfolio_action(**kwargs) -> Response:
    return ApiPortfolioActions.get(**kwargs.get(QUERY_STRING_PARAMETERS, {}))


def update_portfolio_action(**kwargs) -> Response:
    return ApiPortfolioActions.update(**kwargs.get(BODY_PARAMETER, {}))


def create_portfolio_action(**kwargs) -> Response:
    return ApiPortfolioActions.create(**kwargs.get(BODY_PARAMETER, {}))


def delete_portfolio_action(**kwargs) -> Response:
    return ApiPortfolioActions.delete(**kwargs.get(QUERY_STRING_PARAMETERS, {}))


# API Gateway Lambda Proxy Integration routes
item_portfolio_actions: ActionHandlerRoutes = {
    "GET:/api/v1/item/portfolios": get_portfolio_list_action,
    "GET:/api/v1/item/portfolio": get_portfolio_action,
    "PUT:/api/v1/item/portfolio": update_portfolio_action,
    "POST:/api/v1/item/portfolio": create_portfolio_action,
    "DELETE:/api/v1/item/portfolio": delete_portfolio_action,
}
