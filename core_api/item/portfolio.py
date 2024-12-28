"""
This module contains the actions for the core API for the Portfolio ITEM Actions
"""

from collections import ChainMap
from core_db.response import Response
from core_db.item.portfolio.actions import PortfolioActions

from ..constants import (
    QUERY_STRING_PARAMETERS,
    PATH_PARAMETERS,
    BODY_PARAMETER,
)
from ..types import ActionHandlerRoutes

from ..actions import ApiActions


class ApiPortfolioActions(ApiActions, PortfolioActions):
    pass


def get_portfolio_list_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiPortfolioActions.list(**dict(ChainMap(body, pp, qsp)))


def get_portfolio_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiPortfolioActions.get(**dict(ChainMap(body, pp, qsp)))


def update_portfolio_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiPortfolioActions.update(**dict(ChainMap(body, pp, qsp)))


def create_portfolio_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiPortfolioActions.create(**dict(ChainMap(body, pp, qsp)))


def delete_portfolio_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiPortfolioActions.delete(**dict(ChainMap(body, pp, qsp)))


# API Gateway Lambda Proxy Integration routes
item_portfolio_actions: ActionHandlerRoutes = {
    "GET:/api/v1/item/portfolios": get_portfolio_list_action,
    "GET:/api/v1/item/portfolio": get_portfolio_action,
    "PUT:/api/v1/item/portfolio": update_portfolio_action,
    "POST:/api/v1/item/portfolio": create_portfolio_action,
    "DELETE:/api/v1/item/portfolio": delete_portfolio_action,
}
