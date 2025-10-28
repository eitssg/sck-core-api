from collections import ChainMap
import re

from botocore import args
from botocore.exceptions import ClientError
from pynamodb.exceptions import DoesNotExist

import core_framework as util

import core_logging as log

from core_framework.constants import TR_RESPONSE

from core_framework.status import RELEASE_REQUESTED, TEARDOWN_REQUESTED, BuildStatus
from core_framework.models import (
    TaskPayload,
    DeploymentDetails,
    PackageDetails,
)

import core_helper.aws as aws

from core_db.exceptions import BadRequestException, NotFoundException, ConflictException, ForbiddenException

from core_db.item.build.models import BuildItem
from core_db.item.build.actions import BuildActions
from core_db.item.branch.models import BranchItem
from core_db.item.branch.actions import BranchActions

from core_invoker.handler import handler as invoker_handler

from ..request import RouteEndpoint
from ..security import EnhancedSecurityContext, Permission
from ..response import Response, SuccessResponse, ErrorResponse
from ..actions import ApiActions


class ApiBuildActions(ApiActions, BuildActions):

    @classmethod
    def __invoker_action_request(cls, action: str, client: str, build: BuildItem) -> dict:

        dd = DeploymentDetails.model_validate(
            {
                "Client": client,
                "Portfolio": util.extract_portfolio(build),
                "App": util.extract_app(build),
                "Branch": util.extract_branch(build),
                "Build": build.name,
            }
        )

        pd = PackageDetails.model_validate(
            {
                "BucketName": util.get_bucket_name(),
                "BucketRegion": util.get_bucket_region(),
            }
        )

        # The release and teardown actions do not require a "Package" definition.
        payload = TaskPayload(Task=action, DeploymentDetails=dd, Package=pd)

        try:

            if util.is_local_mode():
                response = invoker_handler(payload.model_dump())
            else:
                arn = util.get_invoker_lambda_arn()
                response = aws.invoke_lambda(arn, payload.model_dump())

            if TR_RESPONSE not in response:
                raise BadRequestException(f"Invalid invoker response: {response}")

            return response[TR_RESPONSE]
        
        except ClientError as e:
            raise BadRequestException(f"Invoker invocation failed: {str(e)}") from e

    @classmethod
    def release(cls, client: str, **kwargs) -> BuildItem:

        item: BuildItem = BuildActions.get(client=client, **kwargs)
            
        if not BuildStatus(item.status).is_allowed_to_release():
            raise BadRequestException(f"Build {item.prn} is not allowed to be released: {item.status}")

        item.status = RELEASE_REQUESTED

        resuponse = BuildActions.update(client=client, **item.model_dump())

        log.info("Build status updated: RELEASE_REQUESTED")

        # It can be released, so let's do it
        release_response = cls.__invoker_action_request("release", client, item)
        
        if not release_response:
            raise BadRequestException(f"Invalid release response: {release_response}")

        log.info(f"Build {item.prn} release response: ", details=release_response)

        return resuponse

    @classmethod
    def teardown(cls, client: str, **kwargs) -> BuildItem:

        item: BuildItem = BuildActions.get(client=client, **kwargs)
      
        if not BuildStatus(item.status).is_allowed_to_teardown():
            raise BadRequestException(f"Build {item.prn} is not allowed to be teared down: {item.status}")

        item.status = TEARDOWN_REQUESTED

        response = BuildActions.update(client=client, **item.model_dump())

        log.info("Build status updated: TEARDOWN_REQUESTED")

        teardown_response = cls.__invoker_action_request("teardown", client, item)

        if not teardown_response:
            raise BadRequestException(f"Invalid teardown response: {teardown_response}")

        log.info(f"Build {item.prn} teardown response: ", details=teardown_response)

        return response

def _merged(query_params: dict, path_params: dict, body: dict) -> dict:
    args = dict(ChainMap(path_params, query_params, body))
    if "client" in args:
        del args["client"]
    return args


def get_builds(*, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        results, paginator = ApiBuildActions.list(client=security.client, **args)
        data = [item.model_dump(by_alias=False, mode="json") for item in results]
        return SuccessResponse(data=data, metadata=paginator.get_metadata())
    
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def get_build(*, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        result = ApiBuildActions.get(client=security.client, **args)
        data = result.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data)
    
    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))
    
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def create_build(*, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        result = ApiBuildActions.create(client=security.client, **args)
        data = result.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data, code=201)
    
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def update_build(*, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        result = ApiBuildActions.update(client=security.client, **args)
        data = result.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data)
    
    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))
    
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def delete_build(*, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        ApiBuildActions.delete(client=security.client, **args)
        return SuccessResponse(code=204)
    
    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))
    
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def release_build(*, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        item = ApiBuildActions.release(client=security.client, **args)
        return SuccessResponse(code=202, message=f"Build release requested: {item.prn}")
    
    except NotFoundException as e:
    
        return ErrorResponse(code=404, message=str(e))
    
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def teardown_build(*, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    try:

        args = _merged(query_params, path_params, body)

        item = ApiBuildActions.teardown(client=security.client, **args)
        return SuccessResponse(code=202, message=f"Build teardown requested: {item.prn}")

    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))
    
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


# API Gateway Lambda Proxy Integration routes
item_build_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/item/builds": RouteEndpoint(
        get_builds,
        required_permissions={Permission.ITEM_BUILD_READ},
    ),
    "GET:/api/v1/item/build": RouteEndpoint(
        get_build,
        required_permissions={Permission.ITEM_BUILD_READ},
    ),
    "PUT:/api/v1/item/build": RouteEndpoint(
        update_build,
        required_permissions={Permission.ITEM_BUILD_WRITE},
    ),
    "DELETE:/api/v1/item/build": RouteEndpoint(
        delete_build,
        required_permissions={Permission.ITEM_BUILD_ADMIN},
    ),
    "POST:/api/v1/item/build": RouteEndpoint(
        create_build,
        required_permissions={Permission.ITEM_BUILD_WRITE},
    ),
    "POST:/api/v1/item/build/teardown": RouteEndpoint(
        teardown_build,
        required_permissions={Permission.ITEM_BUILD_ADMIN},
    ),
    "POST:/api/v1/item/build/release": RouteEndpoint(
        release_build,
        required_permissions={Permission.ITEM_BUILD_ADMIN},
    ),
}
