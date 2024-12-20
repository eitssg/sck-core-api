from collections import ChainMap

from botocore.exceptions import ClientError
from pynamodb.exceptions import DoesNotExist

import core_framework as util

import core_logging as log

from core_framework.constants import TR_RESPONSE

from core_framework.status import RELEASE_REQUESTED, TEARDOWN_REQUESTED, BuildStatus

import core_helper.aws as aws

from core_invoker.handler import handler as invoker_handler

from ..types import ActionHandlerRoutes

from ..constants import QUERY_STRING_PARAMETERS, BODY_PARAMETER, PATH_PARAMETERS
from core_db.response import Response, SuccessResponse

from core_db.exceptions import (
    BadRequestException,
    NotFoundException,
)
from core_db.item.branch.models import BranchModel
from core_db.item.build.actions import BuildActions
from core_db.item.build.models import BuildModel

from ..actions import ApiActions

from core_framework.models import (
    TaskPayload,
    DeploymentDetails as DeploymentDetailsClass,
    PackageDetails,
)


class ApiBuildActions(ApiActions, BuildActions):

    @classmethod
    def __invoker_action_request(cls, action: str, build: BuildModel) -> dict:

        # Retrieve the branch Parent for this build
        try:
            branch = BranchModel.get(build.parent_prn)
        except DoesNotExist:
            raise NotFoundException(
                f"Build {build.prn}: Branch not found: {build.parent_prn}"
            )

        # The release and teardown actions do not require a "Package" definition.
        payload = TaskPayload(
            Task=action,
            DeploymentDetails=DeploymentDetailsClass(
                Portfolio=util.extract_portfolio(build) or "",
                App=util.extract_app(build),
                Branch=branch.name,
                BranchShortName=branch.short_name,
                Build=build.name,
            ),
            Package=PackageDetails(
                BucketName=util.get_bucket_name(), BucketRegion=util.get_bucket_region()
            ),
        )

        if util.is_local_mode():
            return invoker_handler(payload.model_dump())

        arn = util.get_invoker_lambda_arn()
        response = aws.invoke_lambda(arn, payload.model_dump())
        if TR_RESPONSE not in response:
            raise BadRequestException(f"Invalid invoker response: {response}")
        return response[TR_RESPONSE]

    @classmethod
    def release(cls, **kwargs) -> Response:

        response = BuildActions.get(**kwargs)

        if not response or not response.data or not isinstance(response.data, dict):
            raise NotFoundException(f"Cannot find build {kwargs}:")

        build = BuildModel(**response.data)

        if not BuildStatus(build.status).is_allowed_to_release():
            raise BadRequestException(
                f"Build {build.prn} is not allowed to be released: {build.status}"
            )

        build.status = RELEASE_REQUESTED

        response = BuildActions.update(**build.to_simple_dict())

        log.info("Build status updated: RELEASE_REQUESTED")

        # It can be released, so let's do it
        try:
            # Trigger the release
            release_response = cls.__invoker_action_request("release", build)
        except ClientError as e:
            raise BadRequestException(
                f"AWS Client Error requesting bu8ild releasing: {e}"
            )

        if not release_response:
            raise BadRequestException(f"Invalid release response: {release_response}")

        log.info(f"Build {build.prn} release response: ", details=release_response)

        return SuccessResponse(f"Build {build.prn} release requested")

    @classmethod
    def teardown(cls, **kwargs) -> Response:

        response = BuildActions.get(**kwargs)

        if not response or not response.data or not isinstance(response.data, dict):
            raise NotFoundException(f"Cannot find build {kwargs}:")

        build = BuildModel(**response.data)

        if not BuildStatus(build.status).is_allowed_to_teardown():
            raise BadRequestException(
                f"Build {build.prn} is not allowed to be teared down: {build.status}"
            )

        build.status = TEARDOWN_REQUESTED

        response = BuildActions.update(**build.to_simple_dict())

        log.info("Build status updated: TEARDOWN_REQUESTED")

        try:
            # Trigger the teardown
            teardown_response = cls.__invoker_action_request("teardown", build)
        except ClientError as e:
            raise BadRequestException(
                f"AWS Client Error requesting build teardown: {e}"
            )

        if not teardown_response:
            raise BadRequestException(f"Invalid teardown response: {teardown_response}")

        log.info(f"Build {build.prn} teardown response: ", details=teardown_response)

        log.trace("Build teardown response", details=response)

        return SuccessResponse(f"Build {build.prn} teardown requested")


def get_builds(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiBuildActions.list(**dict(ChainMap(body, pp, qsp)))


def get_build(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiBuildActions.get(**dict(ChainMap(body, pp, qsp)))


def create_build(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiBuildActions.create(**dict(ChainMap(body, pp, qsp)))


def update_build(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiBuildActions.update(**dict(ChainMap(body, pp, qsp)))


def delete_build(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiBuildActions.delete(**dict(ChainMap(body, pp, qsp)))


def release_build(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiBuildActions.release(**dict(ChainMap(body, pp, qsp)))


def teardown_build(**kwargs) -> Response:
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiBuildActions.teardown(**dict(ChainMap(body, pp, qsp)))


# API Gateway Lambda Proxy Integration routes
item_build_actions: ActionHandlerRoutes = {
    "GET:/api/v1/item/builds": get_builds,
    "GET:/api/v1/item/build": get_build,
    "PUT:/api/v1/item/build": update_build,
    "DELETE:/api/vi/item/build": delete_build,
    "POST:/api/v1/item/build": create_build,
    "POST:/api/v1/item/build/teardown": teardown_build,
    "POST:/api/v1/item/build/release": release_build,
}
