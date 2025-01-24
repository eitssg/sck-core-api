from collections import ChainMap

from core_db.response import Response

from core_db.item.branch.actions import BranchActions

from ..constants import QUERY_STRING_PARAMETERS, PATH_PARAMETERS, BODY_PARAMETER

from ..request import ActionHandlerRoutes
from ..actions import ApiActions


class ApiBranchActions(ApiActions, BranchActions):

    pass


def get_branch_list_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiBranchActions.list(**dict(ChainMap(body, pp, qsp)))


def get_branch_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiBranchActions.get(**dict(ChainMap(body, pp, qsp)))


def post_branch_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiBranchActions.create(**dict(ChainMap(body, pp, qsp)))


def put_branch_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiBranchActions.update(**dict(ChainMap(body, pp, qsp)))


def delete_branch_action(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiBranchActions.delete(**dict(ChainMap(body, pp, qsp)))


# API Gateway Lambda Proxy Integration routes
item_branch_actions: ActionHandlerRoutes = {
    "GET:/api/v1/item/branches": get_branch_list_action,
    "GET:/api/v1/item/branch": get_branch_action,
    "POST:/api/v1/item/branches": post_branch_action,
    "PUT:/api/v1/item/branch": put_branch_action,
    "DELETE:/api/v1/item/branch": delete_branch_action,
}
