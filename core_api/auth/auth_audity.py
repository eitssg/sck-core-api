from tkinter import N
from core_db.exceptions import NotFoundException, ConflictException
from core_db.audit.audit import AuthAuditSchemas, AuthAuditActions
from core_db.response import ErrorResponse, SuccessResponse

from tests.test_auth import get_authenticated_user

from ..request import RouteEndpoint


def create_audit_record(
    *, cookies: dict | None = None, path_params: dict | None = None, body: dict | None = None, **kwargs
) -> SuccessResponse:
    """Create a new audit record for user authorization changes.

    This function creates an audit record in the database to log changes made to user
    permissions and roles. It captures details such as the actor making the change,
    the type of change, before and after states, and any additions or removals of roles
    and grants.

    Args:
        cookies (dict, optional): The cookies from the request, used for authentication.
        path_params (dict, optional): The path parameters from the request, including
                                      the client identifier.
        body (dict, optional): The request body containing the audit record details.

    Returns:
        SuccessResponse: A response object indicating success and containing the created
                         audit record data.
        ErrorResponse: A response object indicating failure, with an appropriate error
                       message and status code.

    """
    try:
        jwt_payload, _ = get_authenticated_user(cookies=cookies)
        if not jwt_payload:
            return ErrorResponse(code=401, message="Unauthorized: No valid session token")

        client = path_params.get("client")
        record = AuthAuditSchemas(**body or {})

        # Create the audit record in the database
        record = AuthAuditActions.create(client=client, record=record)

        return SuccessResponse(data=record.model_dump(by_alias=False, mode="json"))
    except ConflictException as e:
        return ErrorResponse(code=409, message=str(e), exception=e)
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def get_audit_record(*, cookies: dict | None = None, path_params: dict | None = None, **kwargs) -> SuccessResponse:
    """Retrieve an existing audit record.

    This function retrieves an audit record from the database based on the provided
    primary key (pk) and sort key (sk). It is used to view details of past changes
    made to user permissions and roles.

    Args:
        cookies (dict, optional): The cookies from the request, used for authentication.
        path_params (dict, optional): The path parameters from the request, including
                                      the client identifier.

    Returns:
        SuccessResponse: A response object containing the requested audit record data.
        ErrorResponse: A response object indicating failure, with an appropriate error
                       message and status code.
    """
    try:
        jwt_payload, _ = get_authenticated_user(cookies=cookies)
        if not jwt_payload:
            return ErrorResponse(code=401, message="Unauthorized: No valid session token")

        client = path_params.get("client")
        pk = path_params.get("pk")
        sk = path_params.get("sk")

        record = AuthAuditActions.get(client=client, pk=pk, sk=sk)

        return SuccessResponse(data=record.model_dump(by_alias=False, mode="json"))

    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e), exception=e)
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def delete_audit_record(*, cookies: dict | None = None, path_params: dict | None = None, **kwargs) -> SuccessResponse:
    """Delete an existing audit record.

    This function deletes an audit record from the database based on the provided
    primary key (pk) and sort key (sk). It is used to remove audit records that are
    no longer needed or were created in error.

    Args:
        cookies (dict, optional): The cookies from the request, used for authentication.
        path_params (dict, optional): The path parameters from the request, including
                                      the client identifier.

    Returns:
        SuccessResponse: A response object indicating success and confirming deletion.
        ErrorResponse: A response object indicating failure, with an appropriate error
                       message and status code.
    """
    try:
        jwt_payload, _ = get_authenticated_user(cookies=cookies)
        if not jwt_payload:
            return ErrorResponse(code=401, message="Unauthorized: No valid session token")

        client = path_params.get("client")
        pk = path_params.get("pk")
        sk = path_params.get("sk")

        AuthAuditActions.delete(client=client, pk=pk, sk=sk)

        return SuccessResponse(code=204)

    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e), exception=e)
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


audit_endpoints = {
    "POST:/auth/v1/clients/{client}/audit": RouteEndpoint(
        create_audit_record,
        allow_anonymous=False,
        token_type="session",
        client_isolated=True,
    ),
    "DELETE:/auth/v1/clients/{client}/audit/{pk}/{sk}": RouteEndpoint(
        delete_audit_record,
        allow_anonymous=False,
        token_type="session",
        client_isolated=True,
    ),
    "GET:/auth/v1/clients/{client}/audit/{pk}/{sk}": RouteEndpoint(
        get_audit_record,
        allow_anonymous=False,
        token_type="session",
        client_isolated=True,
    ),
}
