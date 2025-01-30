from typing import Any
import sys
import socket
import platform
import locale
import uuid
import hashlib
from datetime import datetime

from pydantic import BaseModel, Field

import core_framework as util

import core_helper.aws as aws

from core_api import __version__
from core_api.request import ProxyEvent, RequestContext, CognitoIdentity


API_LAMBDA_NAME = "core-automation-api-master"

HDR_X_CORRELATION_ID = "X-Correlation-Id"
HDR_X_FORWARDED_FOR = "X-Forwarded-For"
HDR_X_FORWARDED_PROTO = "X-Forwarded-Proto"
HDR_AUTHORIZATION = "Authorization"
HDR_CONTENT_TYPE = "Content-Type"
HDR_ACCEPT = "Accept"
HDR_USER_AGENT = "User-Agent"


def get_ip_address() -> str:
    """Get the IP address of the current host."""
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address


def get_version_info() -> tuple[str, str, str]:
    """Get system version information.

    Returns:
        tuple: (system name, version, release info)
    """
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
    """Generate User-Agent string with system information.

    Args:
        module_name: Name of the module
        module_version: Version of the module

    Returns:
        str: Formatted User-Agent string
    """
    python_version = sys.version
    os_name, os_version, os_release = get_version_info()
    user_agent = f"{module_name}/{module_version} (Python/{python_version}; {os_name}/{os_version}/{os_release})"
    return user_agent


def get_header(headers, name, default=None) -> tuple[str, str]:
    """Get header value with case-insensitive lookup.

    Args:
        headers: Headers dictionary
        name: Header name to find
        default: Default value if not found

    Returns:
        tuple: (header name, header value)
    """
    for k, v in headers.items():
        if k.lower() == name.lower():
            return k, v
    return name, default


def event_headers(headers) -> dict:
    """Generate proxy forward headers.

    Args:
        headers: Original headers dictionary

    Returns:
        dict: Headers with added proxy information
    """

    # Append the ip_address to X_FORWARDED_FOR
    ip_address = get_ip_address()
    k, v = get_header(headers, HDR_X_FORWARDED_FOR, ip_address)
    if ip_address not in v:
        headers[k] = f"{v},{ip_address}"

    # Add headers if they don't exist
    headers.update([get_header(headers, HDR_X_CORRELATION_ID, str(uuid.uuid4()))])
    headers.update([get_header(headers, HDR_X_FORWARDED_PROTO, "https")])
    headers.update(
        [
            get_header(
                headers, HDR_USER_AGENT, generate_user_agent("core_api", __version__)
            )
        ]
    )

    return headers


def generate_resource_id(resource: str) -> str:
    """Generate a consistent hash for the resource ID."""
    return hashlib.md5(resource.encode()).hexdigest()[:12].lower()


def generate_proxy_event(
    protocol: str,
    identity: CognitoIdentity,
    method: str,
    resource: str,
    path: str,
    path_params: dict,
    query_params: dict,
    body: str,
    headers: dict,
) -> ProxyEvent:
    """Generate API Gateway proxy event.

    Args:
        protocol: HTTP protocol
        identity: Cognito identity information
        method: HTTP method
        resource: API resource path
        path: Request path
        path_params: Path parameters
        query_params: Query parameters
        body: Request body
        headers: Request headers

    Returns:
        ProxyEvent: Formatted proxy event
    """
    headers = event_headers(headers or {})

    # Generate resource ID
    resource_id = generate_resource_id(resource)

    # Retrieve extendedRequestId from headers
    _, request_id = get_header(headers, HDR_X_CORRELATION_ID)
    _, user_agent = get_header(headers, HDR_USER_AGENT)

    identity.userAgent = user_agent

    # Create the RequestContext model
    request_context = RequestContext(
        resourceId=resource_id,
        resourcePath=resource,
        httpMethod=method,
        path=path,
        accountId=identity.accountId,
        protocol=protocol,
        requestId=request_id,
        identity=identity,
    )

    rv = ProxyEvent(
        resource=resource,
        path=path,
        httpMethod=method,
        headers=headers,
        requestContext=request_context,
        pathParameters=path_params,
        queryStringParameters=query_params,
        body=body,
    )

    return rv


def get_user_information(token: str, role: str | None = None) -> CognitoIdentity | None:
    """Returns the temporary credentials and identity for the user with the specified Token.

    We need to assume a role to execute the lambda function
    """

    identity = aws.get_identity(token, role)

    if not identity:
        return None

    cognito_identity = CognitoIdentity(
        accountId=identity.get("Account"),
        user=identity.get("UserId"),
        userArn=identity.get("Arn"),
        caller=identity.get("caller", __name__),
        sourceIp=get_ip_address(),
        accessKey=identity.get("AccessKeyId"),
    )

    return cognito_identity


def get_locale():
    """Get the current system locale."""
    return locale.getlocale()


class ClientContext(BaseModel):
    """Client context information for Lambda execution."""

    client: dict[str, Any]
    environment: dict[str, Any]


class ProxyContext(BaseModel):
    """Proxy context for AWS Lambda execution environment."""

    function_name: str = Field(default_factory=util.get_api_lambda_name)
    function_version: str = "$LATEST"
    invoked_function_arn: str = Field(default_factory=util.get_api_lambda_arn)
    memory_limit_in_mb: int = 128
    aws_request_id: str
    log_group_name: str = Field(
        default_factory=lambda: f"/aws/lambda/{util.get_api_lambda_name()}"
    )
    log_stream_name: str = Field(
        default_factory=lambda: f"{datetime.now().strftime('%Y/%m/%d')}/[$LATEST]{uuid.uuid4()}"
    )
    identity: dict[str, Any] | None = None
    client_context: ClientContext = Field(
        default_factory=lambda: ClientContext(
            client={
                "installation_id": __version__,
                "app_title": "core-api",
                "app_version_name": __version__,
                "app_version_code": __version__,
                "app_package_name": "core_api.api",
            },
            environment={
                "platform": get_version_info()[0],
                "model": sys.version,
                "make": "Python",
                "locale": get_locale(),
                "network_type": "direct",
                "os_version": get_version_info()[1],
                "os_release": get_version_info()[2],
            },
        )
    )
    remaining_time: int = 10000

    def get_remaining_time_in_millis(self) -> int:
        """Get remaining execution time in milliseconds."""
        return self.remaining_time

    def set_remaining_time_in_millis(self, value: int):
        """Set remaining execution time in milliseconds.

        Args:
            value: Time in milliseconds
        """
        self.remaining_time = value


def generate_proxy_context(event: ProxyEvent) -> ProxyContext:
    """Generate a proxy context from an API Gateway event.

    Args:
        event: API Gateway proxy event

    Returns:
        ProxyContext: Context object for Lambda execution
    """
    aws_request_id = event.requestContext.requestId
    identity = event.requestContext.identity.model_dump()
    return ProxyContext(aws_request_id=aws_request_id, identity=identity)
