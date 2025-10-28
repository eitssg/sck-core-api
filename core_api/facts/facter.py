"""
The Factor object is the "FACTS" database.  This object is DEPRECATED and should not be used.
This FACTS database should come from DynamoDB.  Not 'accounts.yaml' and 'apps.yaml' files.

(In re-rewrite.  We need to use DynamoDB instead of FACTS YAML files)
"""

from core_db.facter.actions import FactsActions
from core_db.exceptions import ConflictException, NotFoundException, BadRequestException

from ..request import RouteEndpoint
from ..response import Response, SuccessResponse, ErrorResponse
from ..security import EnhancedSecurityContext, Permission
from ..actions import ApiActions


class ApiFactsActions(ApiActions, FactsActions):
    pass


def get_facts_action(*, query_params: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    """
    Returns FACTS information for the given PRN. FACTS are provided as context to the compilers
    used in Jinja2 templates throughout the system.
    """
    try:

        args = {"client_id": security.client_id, "client": security.client, "prn": query_params.get("prn", "")}
        data = ApiFactsActions.get(**args)
        return SuccessResponse(data=data)

    except NotFoundException as e:
        return ErrorResponse(message=str(e), code=404)

    except BadRequestException as e:
        return ErrorResponse(message=str(e), code=400)

    except ConflictException as e:
        return ErrorResponse(message=str(e), code=500, exception=e)


# Define API Gateway routes
facts_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/facts": RouteEndpoint(
        get_facts_action, 
        required_permissions={Permission.REGISTRY_READ}
    ),
}
