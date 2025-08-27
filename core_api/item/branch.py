from collections import ChainMap

from core_db.response import Response

from core_db.item.branch.actions import BranchActions

from ..constants import QUERY_STRING_PARAMETERS, PATH_PARAMETERS, BODY_PARAMETER

from ..request import ActionHandlerRoutes, RouteEndpoint
from ..actions import ApiActions


class ApiBranchActions(ApiActions, BranchActions):

    pass


def get_branch_list_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiBranchActions.list(**dict(ChainMap(body, pp, qsp)))


def get_branch_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiBranchActions.get(**dict(ChainMap(body, pp, qsp)))


def post_branch_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiBranchActions.create(**dict(ChainMap(body, pp, qsp)))


def put_branch_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiBranchActions.update(**dict(ChainMap(body, pp, qsp)))


def delete_branch_action(*, cookies: dict, headers: dict, query_params: dict, path_params: dict, body: dict) -> Response:
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiBranchActions.delete(**dict(ChainMap(body, pp, qsp)))


# API Gateway Lambda Proxy Integration routes
item_branch_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/item/branches": RouteEndpoint(get_branch_list_action, permissions=["read:branches"]),
    "GET:/api/v1/item/branch": RouteEndpoint(get_branch_action, permissions=["read:branch"]),
    "POST:/api/v1/item/branches": RouteEndpoint(post_branch_action, permissions=["create:branches"]),
    "PUT:/api/v1/item/branch": RouteEndpoint(put_branch_action, permissions=["update:branch"]),
    "DELETE:/api/v1/item/branch": RouteEndpoint(delete_branch_action, permissions=["delete:branch"]),
}
