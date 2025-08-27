"""
This module contains the actions for the core API for the Portfolio ITEM Actions
"""

from collections import ChainMap
from core_db.response import Response
from core_db.item.portfolio.actions import PortfolioActions

from ..request import RouteEndpoint

from ..actions import ApiActions


class ApiPortfolioActions(ApiActions, PortfolioActions):
    pass


def get_portfolio_list_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiPortfolioActions.list(**dict(ChainMap(body, pp, qsp)))


def get_portfolio_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiPortfolioActions.get(**dict(ChainMap(body, pp, qsp)))


def update_portfolio_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiPortfolioActions.update(**dict(ChainMap(body, pp, qsp)))


def create_portfolio_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiPortfolioActions.create(**dict(ChainMap(body, pp, qsp)))


def delete_portfolio_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiPortfolioActions.delete(**dict(ChainMap(body, pp, qsp)))


# API Gateway Lambda Proxy Integration routes
item_portfolio_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/item/portfolios": RouteEndpoint(get_portfolio_list_action, permissions=["read:portfolios"]),
    "GET:/api/v1/item/portfolio": RouteEndpoint(get_portfolio_action, permissions=["read:portfolio"]),
    "PUT:/api/v1/item/portfolio": RouteEndpoint(update_portfolio_action, permissions=["update:portfolio"]),
    "POST:/api/v1/item/portfolio": RouteEndpoint(create_portfolio_action, permissions=["create:portfolio"]),
    "DELETE:/api/v1/item/portfolio": RouteEndpoint(delete_portfolio_action, permissions=["delete:portfolio"]),
}
