from botocore.exceptions import ClientError
from pynamodb.exceptions import DoesNotExist

import core_framework as util

from core_framework.constants import TR_RESPONSE

from core_framework.status import RELEASE_REQUESTED, TEARDOWN_REQUESTED, BuildStatus

import core_helper.aws as aws

from core_invoker.handler import handler as invoker_handler

from ..types import ActionHandlerRoutes

from ..constants import (
    QUERY_STRING_PARAMETERS,
    BODY_PARAMETER,
    PATH_PARAMETERS,
)
from core_db.response import Response

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

        payload = TaskPayload(
            Task=action,
            DeploymentDetails=DeploymentDetailsClass(
                Portfolio=util.extract_portfolio(build) or "",
                App=util.extract_app(build),
                Branch=branch.name,
                BranchShortName=branch.short_name,
                Build=build.name,
            ),
        )

        if util.is_local_mode():
            response = invoker_handler(payload.model_dump())
        else:
            arn = util.get_invoker_lambda_arn()
            invoker_result = aws.invoke_lambda(arn, payload.model_dump())
            response = invoker_result.get(TR_RESPONSE, {})

        return response

    @classmethod
    def release(cls, **kwargs) -> Response:

        response = BuildActions.get(**kwargs)

        if not response.data or not isinstance(response.data, dict):
            raise NotFoundException(f"Build not found: {kwargs}")

        build = BuildModel(**response.data)

        if not BuildStatus(build.status).is_allowed_to_release():
            raise BadRequestException(
                f"Build {build.prn} is not allowed to be released: {build.status}"
            )

        # It can be released, so let's do it
        try:
            # Trigger the release
            cls.__invoker_action_request("release", build)
        except ClientError as e:
            raise BadRequestException(
                f"AWS Client Error requesting bu8ild releasing: {e}"
            )

        build.status = RELEASE_REQUESTED

        response = BuildActions.update(**build.to_simple_dict())

        return response

    @classmethod
    def teardown(cls, **kwargs) -> Response:

        response = BuildActions.get(**kwargs)

        if not response.data or not isinstance(response.data, dict):
            raise NotFoundException(f"Build not found: {kwargs}")

        build = BuildModel(**response.data)

        if not BuildStatus(build.status).is_allowed_to_teardown():
            raise BadRequestException(
                f"Build {build.prn} is not allowed to be teared down: {build.status}"
            )

        try:
            # Trigger the teardown
            cls.__invoker_action_request("teardown", build)
        except ClientError as e:
            raise BadRequestException(
                f"AWS Client Error requesting build teardown: {e}"
            )

        build.status = TEARDOWN_REQUESTED

        response = BuildModel.update(**build.to_simple_dict())

        return response


def get_builds(**kwargs) -> Response:
    return ApiBuildActions.list(**kwargs.get(QUERY_STRING_PARAMETERS, {}))


def get_build(**kwargs) -> Response:
    return ApiBuildActions.get(**kwargs.get(PATH_PARAMETERS, {}))


def create_build(**kwargs) -> Response:
    return ApiBuildActions.create(
        **kwargs.get(PATH_PARAMETERS, {}),
    )


def update_build(**kwargs) -> Response:
    return ApiBuildActions.update(**kwargs.get(BODY_PARAMETER, {}))


def delete_build(**kwargs) -> Response:
    return ApiBuildActions.delete(**kwargs.get(PATH_PARAMETERS, {}))


def release_build(**kwargs) -> Response:
    return ApiBuildActions.release(**kwargs.get(QUERY_STRING_PARAMETERS, {}))


def teardown_build(**kwargs) -> Response:
    return ApiBuildActions.teardown(**kwargs.get(QUERY_STRING_PARAMETERS, {}))


# API Gateway Lambda Proxy Integration routes
item_build_actions: ActionHandlerRoutes = {
    "GET:/api/v1/item/builds": get_builds,
    "GET:/api/v1/item/build": get_build,
    "PUT:/api/v1//item/build": update_build,
    "DELETE:/api/vi/item/build": delete_build,
    "POST:/api/v1/item/build": create_build,
    "POST:/api/v1/item/build/teardown": teardown_build,
    "POST:/api/v1/item/build/release": release_build,
}
