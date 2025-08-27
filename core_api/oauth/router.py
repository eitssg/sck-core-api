from botocore import auth
from fastapi import APIRouter, Request, Response

import core_framework as util
import core_logging as log
import core_helper.aws as aws
from jwcrypto.jwt import JWT_expect_type
import jwt

from ..api.apis import generate_event_context, generate_response_from_lambda, authorize_request
from .tools import get_authenticated_user, decrypt_creds
from .handler import endpoints, handler


async def auth_handler(request: Request) -> Response:

    # Generate and AWS API Gateway event (ProxyEvent) and context
    is_write_operation = request.method.lower() != "get"

    role = util.get_automation_api_role_arn(account, is_write_operation)

    identity = await authorize_request(request, role)

    event, context = await generate_event_context(request, identity)

    account = util.get_automation_account()

    is_write_operation = request.method.lower() != "get"
    role = util.get_automation_api_role_arn(account, is_write_operation)

    if util.is_local_mode():
        result = handler(event=event, context=context)
    else:
        arn = util.get_auth_lambda_arn()

        result = aws.invoke_lambda(arn=arn, event=event, role=role, context=context)

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
