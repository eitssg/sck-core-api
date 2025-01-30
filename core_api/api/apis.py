"""FastAPI router and request handling for core API.

Provides routing configuration, request authorization, and Lambda function integration
for the API Gateway implementation.
"""

import core_framework as util

import core_helper.aws as aws

from fastapi import Request, APIRouter
from fastapi.responses import Response
from fastapi.routing import APIRoute

from ..handler_proxy import api_paths, handler_proxy
from ..request import ProxyEvent
from .tools import (
    ProxyContext,
    CognitoIdentity,
    generate_proxy_event,
    generate_proxy_context,
    get_user_information,
    get_header,
)

MEDIA_TYPE = "application/json"
STATUS_CODE = "statusCode"
BODY = "body"


class RouterSingtleton:
    """Singleton class for managing FastAPI router instance.

    Ensures only one router is created and reused across the application.
    """

    _router: APIRouter | None = None

    @classmethod
    def get_router(cls) -> APIRouter:
        """Get or create the FastAPI router instance.

        Returns:
            APIRouter: Singleton router instance with configured API routes
        """
        if cls._router is None:
            cls._router = APIRouter()
            for method_resource in api_paths.keys():
                method, resource = method_resource.split(":")
                cls._router.add_api_route(
                    resource,
                    endpoint=proxy_forward,
                    methods=[method],
                    response_class=Response,
                )
        return cls._router


async def authorize_request(request: Request, role: str) -> CognitoIdentity:
    """
    Authorize the request by validating the token in the Authorization header

    Args:
        request (Request): The FastAPI Request object

    Returns:
        dict: The identity of the user
    """
    headers = request.headers
    _, bearer = get_header(headers, "Authorization")
    if bearer:
        if not bearer.startswith("Bearer"):
            raise ValueError("Authorization header is not in the correct format")
        parts = bearer.split(" ")
        if len(parts) != 2:
            raise ValueError("Authorization header is not in the correct format")
        token = parts[1]
    else:
        token = None

    if not token:
        raise ValueError("No Authorization token provided")

    identity = get_user_information(token, role)

    if not identity:
        raise ValueError("User is not authorized")

    # This is a stub.  We need to implement the actual authorization logic
    return identity


async def generate_event_context(
    request: Request, identity: CognitoIdentity
) -> tuple[ProxyEvent, ProxyContext]:
    """Generate Lambda event and context from FastAPI request.

    Args:
        request: FastAPI request object
        identity: Cognito identity information

    Returns:
        tuple: (API Gateway event, Lambda context)
    """
    query_params = dict(request.query_params)
    path_params = dict(request.path_params)
    headers = dict(request.headers)
    body = await request.body()
    body_data: str = body.decode("utf-8")

    router: APIRoute = request.scope.get("route", None)
    resource = router.path_format

    event: ProxyEvent = generate_proxy_event(
        protocol=request.url.scheme,
        identity=identity,
        method=request.method,
        resource=resource,
        path=request.url.path,
        path_params=path_params,
        query_params=query_params,
        body=body_data,
        headers=headers,
    )

    context = generate_proxy_context(event)

    return event, context


async def generate_response_from_lamnba(result: dict) -> Response:
    """
    The response from the lambda is a dict with a status code and a body.  We need to convert this to a FastAPI Response
    object with the approprate boday, status code and media type.

    The response object from the lambda is a dict with the following:

        ```python
        response = {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {
                "Content-Type": 'application/json'
            },
            "body": '{"key": "value"}'  # JSON
        }
        ```

    Since the response.body is already assumed to ba a JSON string, we can set it directly into the content

    Args:
        result (dict): The response object from the core_api_handler or lambda

    Returns:
        Response: FastAPI Response object
    """

    status_code = result.get(STATUS_CODE, 200)
    content = result.get(BODY, "{}")

    return Response(content=content, status_code=status_code, media_type=MEDIA_TYPE)


async def proxy_forward(request: Request) -> Response:
    """Forward API requests to AWS Lambda function.

    Args:
        request: FastAPI request object

    Returns:
        Response: Lambda function response wrapped in FastAPI Response

    Raises:
        ValueError: If automation account not configured or authorization fails
    """
    # Lambda functions are in the automation account
    account = util.get_automation_account()

    if not account:
        raise ValueError("No Automation Account secified in the environment")

    # Read role for "get", Write role for "post", "put", "delete", "patch"
    role = util.get_automation_api_role_arn(account, request.method.lower() != "get")

    # We need to determine if we acutally have permission to invoke the lambda function.
    identity = await authorize_request(request, role)

    lambda_event, context = await generate_event_context(request, identity)

    event = lambda_event.model_dump()

    # Note:  This is what we call "local mode".  otherwise, we call lambda invoke.
    # We will authorize the user in the lambda function with the Authorization header Bearer token.
    # To invoke the lambda function, we don't need to be a specific 'role'.
    if util.is_local_mode():
        result = handler_proxy(event, context)
    else:
        arn = util.get_api_lambda_arn()
        # This should use the role credentials as already received in "authorize_request" above.  So, it shouldn't assume_role again.
        result = aws.invoke_lambda(arn, event, role=role)

    return await generate_response_from_lamnba(result)


def get_fast_api_router() -> APIRouter:
    """
    Create a FastAPI Router with all of the proxy endpoints of the core_api_handler

    Returns:
        APIRouter: The Fast API APIRouter instance
    """
    return RouterSingtleton.get_router()
