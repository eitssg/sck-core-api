"""
This module contains the actions for the core API for the Portfolio ITEM Actions
"""

from collections import ChainMap

from core_db.item.portfolio.actions import PortfolioActions
from core_db.exceptions import BadRequestException, NotFoundException, ConflictException, ForbiddenException

from ..request import RouteEndpoint
from ..security import EnhancedSecurityContext, Permission
from ..response import Response, SuccessResponse, ErrorResponse
from ..actions import ApiActions


class ApiPortfolioActions(ApiActions, PortfolioActions):
    pass


def get_portfolio_list_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:
        results, paginator = ApiPortfolioActions.list(client=security.client, **dict(ChainMap(body, path_params, query_params)))
        data = [item.model_dump(by_alias=False, mode="json") for item in results]
        return SuccessResponse(data=data, metadata=paginator.get_metadata())
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def get_portfolio_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:
        data = ApiPortfolioActions.get(client=security.client, **dict(ChainMap(body, path_params, query_params)))
        return SuccessResponse(data=data.model_dump(by_alias=False, mode="json"))
    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def update_portfolio_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:
        results = ApiPortfolioActions.update(client=security.client, **dict(ChainMap(body, path_params, query_params)))
        data = results.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data)
    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))
    except ConflictException as e:
        return ErrorResponse(code=409, message=str(e))
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def create_portfolio_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:
        result = ApiPortfolioActions.create(client=security.client, **dict(ChainMap(body, path_params, query_params)))
        data = result.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data, code=201)
    except ConflictException as e:
        return ErrorResponse(code=409, message=str(e))
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def delete_portfolio_action(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    try:
        ApiPortfolioActions.delete(client=security.client, **dict(ChainMap(body, path_params, query_params)))
        return SuccessResponse(code=204)
    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


# API Gateway Lambda Proxy Integration routes
item_portfolio_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/item/portfolios": RouteEndpoint(
        get_portfolio_list_action,
        permissions=[Permission.ITEM_PORTFOLIO_READ],
    ),
    "GET:/api/v1/item/portfolio": RouteEndpoint(
        get_portfolio_action,
        permissions=[Permission.ITEM_PORTFOLIO_READ],
    ),
    "PUT:/api/v1/item/portfolio": RouteEndpoint(
        update_portfolio_action,
        permissions=[Permission.ITEM_PORTFOLIO_WRITE],
    ),
    "POST:/api/v1/item/portfolio": RouteEndpoint(
        create_portfolio_action,
        permissions=[Permission.ITEM_PORTFOLIO_WRITE],
    ),
    "DELETE:/api/v1/item/portfolio": RouteEndpoint(
        delete_portfolio_action,
        permissions=[Permission.ITEM_PORTFOLIO_ADMIN],
    ),
}
