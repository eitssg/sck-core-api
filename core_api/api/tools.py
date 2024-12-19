import sys
import platform
import locale
import uuid
import core_framework as util

import core_helper.aws as aws

from .._version import __version__

from datetime import datetime, timezone

api_lambda_name = "core-automation-api-master"


def event_headers(
    host: str | None = None, port: int | None = None, protocol: str | None = None
) -> dict:
    """
    Generate proxy forward headers

    Args:
        host (str, optional): The host IP of the caller. Defaults to None.

    Returns:
        dict: _description_
    """
    # Get the current hostname
    hostname = platform.node()

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Host": hostname,
        "User-Agent": "FastAPI/7.26.8",
    }
    if host:
        headers["X-Forwarded-For"] = host
    if port is not None and port > 0:
        headers["X-Forwarded-Port"] = str(port)
    if protocol:
        headers["X-Forwarded-Proto"] = protocol

    return headers


# There is also another paramter


def get_version_info() -> tuple[str, str, str]:
    system = platform.system()
    if system == "Windows":
        version = platform.version()
        release = platform.release()
        return "Windows", f"Version {version}", f"Release: {release}"
    elif system == "Linux":
        if hasattr(platform, "linux_distribution"):
            distro = platform.linux_distribution()
            return (
                f"Linux {distro[0]}",
                f"Version: {distro[1]}",
                f"Codename: {distro[2]}",
            )
        return "Linux", "Unknown Version", "Unknown Codename"
    elif system == "Darwin":
        release, _, machine = platform.mac_ver()
        return "macOS", f"Version: {release} ({machine})", ""
    else:
        return "Unsupported", "Unsupported Operating System", ""


def generate_user_agent(module_name, module_version):
    python_version = sys.version
    os_name, os_version, os_release = get_version_info()
    user_agent = f"{module_name}/{module_version} (Python/{python_version}; {os_name}/{os_version}/{os_release})"
    return user_agent


def generate_proxy_event(
    request_id: str,
    method: str,
    resource: str,
    path: str,
    path_params: dict | None = None,
    query_params: dict | None = None,
    body: str | None = None,
    headers: dict | None = None,
):
    if not headers:
        headers = event_headers()

    if "X-Correleation-Id" not in headers:
        headers["X-Correleation-Id"] = request_id

    host = platform.node()

    module_name = "core_api"

    identity = aws.get_identity()
    if identity:
        if "Account" in identity:
            aws_account = identity["Account"]
        if "UserId" in identity:
            user_id = identity["UserId"]
        if "Arn" in identity:
            user_arn = identity["Arn"]

    # get the current epoch
    request_time_epoch = int(datetime.now(timezone.utc).timestamp())

    # format the epock as iso8601
    request_time_iso = datetime.fromtimestamp(request_time_epoch).isoformat()

    user_agent = generate_user_agent(module_name, __version__)

    function_name = "core-automation-api-master"
    appId = __name__

    environment = util.get_environment()

    rv = {
        "resource": resource,
        "path": path,
        "httpMethod": method,
        "headers": headers,
        "requestContext": {
            "resourceId": "123456",
            "resourcePath": resource,
            "httpMethod": method,
            "extendedRequestId": request_id,
            "requestTime": request_time_iso,
            "path": path,
            "accountId": aws_account,
            "protocol": "HTTP/1.1",
            "stage": environment,
            "domainPrefix": "example.com",
            "requestTimeEpoch": request_time_epoch,
            "requestId": request_id,
            "identity": {
                "cognitoIdentityPoolId": None,
                "accountId": aws_account,
                "cognitoIdentityId": None,
                "caller": module_name,
                "sourceIp": host,
                "principalOrgId": None,
                "accessKey": None,
                "cognitoAuthenticationType": None,
                "cognitoAuthenticationProvider": None,
                "userArn": user_arn,
                "userAgent": user_agent,
                "user": user_id,
            },
            "domainName": f"{function_name}.execute-api.us-east-1.amazonaws.com",
            "apiId": appId,
        },
        "body": body,
        "isBase64Encoded": False,
    }

    if path_params:
        rv["pathParameters"] = path_params

    if query_params:
        rv["queryStringParameters"] = query_params

    return rv


def get_locale():
    # get the locale of the system
    return locale.getdefaultlocale()


def genearte_lambda_context(aws_request_id: str):
    return SimpleContext(aws_request_id)


class SimpleContext(dict):

    def __init__(self, aws_request_id: str):

        formatted_date = datetime.now().strftime("%Y/%m/%d")
        # get the OS name
        os_name, os_version, os_release = get_version_info()

        self["function_name"] = util.get_api_lambda_name()
        self["function_version"] = "$LATEST"
        self["invoked_function_arn"] = util.get_api_lambda_arn()
        self["memory_limit_in_mb"] = 128
        self["aws_request_id"] = aws_request_id
        self["log_group_name"] = f"/aws/lambda/{self['function_name']}"
        self["log_stream_name"] = f"{formatted_date}/[$LATEST]{aws_request_id}"
        self["identity"] = {
            "cognito_identity_id": None,
            "cognito_identity_pool_id": None,
        }
        self["client_context"] = {
            "client": {
                "installation_id": __version__,
                "app_title": "core-api",
                "app_version_name": __version__,
                "app_version_code": __version__,
                "app_package_name": "core_api.api",
            },
            "environment": {
                "platform": os_name,
                "model": sys.version,
                "make": "Python",
                "locale": get_locale(),
                "network_type": "direct",
                "os_version": os_version,
                "os_release": os_release,
            },
        }

    def get_remaining_time_in_millis(self) -> int:
        return self.get("remaniing_time", 10000)

    def set_remaining_time_in_millis(self, value: int):
        self["remaniing_time"] = value


def generate_event_and_context(
    method: str,
    resource: str,
    path: str,
    path_params: dict | None = None,
    query_params: dict | None = None,
    body: str | None = None,
    headers: dict | None = None,
) -> tuple[dict, dict]:

    request_id = str(uuid.uuid4())

    event = generate_proxy_event(
        request_id, method, resource, path, path_params, query_params, body, headers
    )

    context = genearte_lambda_context(request_id)

    return event, context
