import core_framework as util

import core_helper.aws as aws

from fastapi import Request, APIRouter
from fastapi.responses import Response
from fastapi.routing import APIRoute

from ..handler import handler as core_api_handler
from ..handler_proxy import api_paths

from .tools import generate_event_and_context

__router: APIRouter | None = None

MEDIA_TYPE = "application/json"
STATUS_CODE = "statusCode"
BODY = "body"


async def generate_event_context_for_lambda(request: Request):

    query_params = dict(request.query_params)
    path_params = dict(request.path_params)
    headers = dict(request.headers)
    body = await request.body()
    body_data: str = body.decode("utf-8")

    router: APIRoute = request.scope.get("route", None)
    resource = router.path_format

    event, context = generate_event_and_context(
        request.method,
        resource,
        request.url.path,
        query_params=query_params,
        path_params=path_params,
        body=body_data,
        headers=headers,
    )

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

    event, context = await generate_event_context_for_lambda(request)

    # Note:  This is what we call"local mode".  otherwise, we call lambda invoke.
    if util.is_local_mode():
        result = core_api_handler(event, context)
    else:
        arn = util.common.get_api_lambda_arn()
        result = aws.invoke_lambda(arn, event, role="CoreAutmationApiRole")

    return await generate_response_from_lamnba(result)


def get_fast_api_router() -> APIRouter:
    """
    Create a FastAPI Router with all of the proxy endpoints of the core_api_handler

    Returns:
        APIRouter: The Fast API APIRouter instance
    """
    # setup a global singleton so we ensure we do this only once
    global __router

    if __router:
        return __router

    __router = APIRouter()

    for method_resource in api_paths.keys():
        method, resource = method_resource.split(":")
        __router.add_api_route(
            resource, endpoint=proxy_forward, methods=[method], response_class=Response
        )

    return __router
