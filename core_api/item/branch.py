from ..constants import QUERY_STRING_PARAMETERS, BODY_PARAMETER

from ..types import ActionHandlerRoutes
from core_db.response import Response

from core_db.item.branch.actions import BranchActions

from ..actions import ApiActions


class ApiBranchActions(ApiActions, BranchActions):

    pass


def get_branch_list_action(**kwargs) -> Response:
    return ApiBranchActions.list(**kwargs.get(QUERY_STRING_PARAMETERS, {}))


def get_branch_action(**kwargs) -> Response:
    return ApiBranchActions.get(**kwargs.get(QUERY_STRING_PARAMETERS, {}))


def post_branch_action(**kwargs) -> Response:
    return ApiBranchActions.create(**kwargs.get(BODY_PARAMETER, {}))


def put_branch_action(**kwargs) -> Response:
    return ApiBranchActions.update(**kwargs.get(BODY_PARAMETER, {}))


def delete_branch_action(**kwargs) -> Response:
    return ApiBranchActions.delete(**kwargs.get(QUERY_STRING_PARAMETERS, {}))


# API Gateway Lambda Proxy Integration routes
item_branch_actions: ActionHandlerRoutes = {
    "GET:/api/v1/item/branches": get_branch_list_action,
    "GET:/api/v1/item/branch": get_branch_action,
    "POST:/api/v1/item/branches": post_branch_action,
    "PUT:/api/v1/item/branch": put_branch_action,
    "DELETE:/api/v1/item/branch": delete_branch_action,
}
