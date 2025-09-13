from fastapi import APIRouter, Request, Response

import core_framework as util
import core_logging as log
import core_helper.aws as aws

from .apis import (
    generate_event_context,
    generate_response_from_lambda,
    authorize_request,
)

from .handler import api_endpoints, handler


async def proxy_forward(request: Request) -> Response:
    """Forward API requests to AWS Lambda function or local handler.

    NIOTICE:  This is a bridge between FastAPI and AWS Lambda style handlers.
    It emulates the API Gateway + Lambda proxy integration.

    This will NOT be used in production. and is intended for local development
    and testing only.

    """

    # Read role for "get", Write role for other methods
    is_write_operation = request.method.lower() != "get"
    role = util.get_automation_api_role_arn(write=is_write_operation)

    log.debug("Using IAM Role for operation: %s", role)

    # Authorize the user for this operation
    cognito_identity = await authorize_request(request)
    lambda_event, context = await generate_event_context(request, cognito_identity)

    # Convert event to dict for Lambda invocation
    event = lambda_event.model_dump(exclude_none=True)

    # Execute in local mode or invoke AWS Lambda
    if util.is_local_mode():
        # Local mode: invoke handler directly
        result = handler(event, context)
    else:
        # Remote mode: invoke AWS Lambda function
        arn = util.get_api_lambda_arn()
        result = aws.invoke_lambda(arn, event, role=role)

    return await generate_response_from_lambda(result)


def get_api_router() -> APIRouter:
    """Get or create the FastAPI router instance.

    Creates a new router if one doesn't exist, automatically adding all API routes
    from the proxy configuration. Each route is configured to forward requests
    to the ``proxy_forward`` endpoint.

    """
    router = APIRouter()
    for method_resource in api_endpoints.keys():
        method, resource = method_resource.split(":")
        # strip "/api" prefix if present
        if resource.startswith("/api"):
            resource = resource[4:]
        router.add_api_route(
            resource,
            endpoint=proxy_forward,
            methods=[method],
            response_class=Response,
        )
    return router
