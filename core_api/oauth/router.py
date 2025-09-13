from core_db.response import ErrorResponse
from fastapi import APIRouter, Request, Response

import core_framework as util
import core_logging as log
import core_helper.aws as aws

from core_api.response import get_proxy_response

from ..api.apis import generate_event_context, generate_response_from_lambda, authorize_request
from .handler import endpoints, handler


async def auth_handler(request: Request) -> Response:
    """FastAPI authentication and authorization endpoint router.

    NIOTICE:  This is a bridge between FastAPI and AWS Lambda style handlers.
    It emulates the API Gateway + Lambda proxy integration.

    This will NOT be used in production. and is intended for local development
    and testing only.

    """

    try:
        # In our gateway emulator, we are going to generate the context identity
        # from the JWT token we used to login, or 'anonymous' if not available.
        identity = await authorize_request(request)

        event, context = await generate_event_context(request, identity)
        # Up to 3,583 bytes of base64-encoded data about the invoking client to
        # pass to the function in the context object. Lambda passes the ClientContext
        # object to your function for synchronous invocations only.

        if util.is_local_mode():
            result = handler(event.model_dump(), context=context)
        else:
            arn = util.get_auth_lambda_arn()

            result = aws.invoke_lambda(arn, event.model_dump(), context=context)
    except Exception as e:
        log.error(f"Error occurred while processing request: {e}")
        result = get_proxy_response(
            ErrorResponse(
                status="error",
                code=500,
                message="Internal server error",
                exception=e,
            )
        ).model_dump()
    return await generate_response_from_lambda(result)


def get_auth_router() -> APIRouter:
    router = APIRouter()
    for key in endpoints.keys():
        method, route = key.split(":")
        route = route[5:]  # strip /auth from the front
        router.add_api_route(
            route,
            auth_handler,
            methods=[method],
            response_class=Response,
        )
    return router
