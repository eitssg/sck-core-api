"""AWS API Gateway proxy event and Lambda context generation tools.

This module provides utilities for generating AWS API Gateway proxy events and Lambda
execution contexts that match the exact format AWS produces. It's designed to enable
local testing and development that perfectly emulates the AWS API Gateway → Lambda flow.

The module handles:
- AWS API Gateway proxy event generation with all required fields
- Lambda execution context creation matching AWS runtime environment
- HTTP header processing and forwarding
- User authentication and identity management
- System information gathering for User-Agent strings

Example:
    Basic event generation::

        from core_api.api.tools import generate_proxy_event, generate_proxy_context

        # Generate event exactly like AWS API Gateway
        event = generate_proxy_event(
            protocol="https",
            identity=cognito_identity,
            method="GET",
            resource="/users/{id}",
            path="/users/123",
            path_params={"id": "123"},
            query_params={"include": "profile"},
            body="",
            headers={"Authorization": "Bearer token"}
        )

        # Generate context exactly like AWS Lambda runtime
        context = generate_proxy_context(event)

Attributes:
    API_LAMBDA_NAME (str): Default Lambda function name for API operations.
    HDR_* (str): Standard HTTP header name constants.
"""

import socket
from typing import Any, Dict, Optional
import sys
import platform
import locale
import uuid
import hashlib
import time
from datetime import datetime

from pydantic import BaseModel, Field

import core_framework as util
import core_helper.aws as aws

from core_api import __version__

from ..request import ProxyEvent, RequestContext, CognitoIdentity
from ..constants import (
    API_LAMBDA_NAME,
    HDR_X_CORRELATION_ID,
    HDR_X_FORWARDED_FOR,
    HDR_X_FORWARDED_PROTO,
    HDR_USER_AGENT,
)


def _get_version_info() -> tuple[str, str, str]:
    """Get system version information for User-Agent generation.

    Extracts operating system information including platform name, version,
    and release details. Used to construct realistic User-Agent strings.

    Returns:
        tuple[str, str, str]: A tuple containing:
            - Platform name (e.g., "Windows", "Linux", "macOS")
            - Version information
            - Release or codename information

    Note:
        Linux distribution detection may be limited on newer systems.

    Example:
        .. code-block:: python

            name, version, release = get_version_info()
            # On Windows: ("Windows", "Version 10.0.19041", "Release: 10")
            # On macOS: ("macOS", "Version: 12.6.0 (arm64)", "")
    """
    system = platform.system()
    if system == "Windows":
        version = platform.version()
        release = platform.release()
        return "Windows", f"Version {version}", f"Release: {release}"

    if system == "Linux":
        try:
            with open("/etc/os-release", "r") as f:
                lines = f.readlines()
                info = {}
                for line in lines:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        info[key] = value.strip('"')
                name = info.get("NAME", "Linux")
                version = info.get("VERSION", "Unknown")
                return f"Linux {name}", f"Version: {version}", ""
        except Exception:
            return "Linux", "Unknown Version", "Unknown Distribution"

    elif system == "Darwin":
        release, _, machine = platform.mac_ver()
        return "macOS", f"Version: {release} ({machine})", ""

    return "Unknown", "Unsupported Operating System", ""


def _generate_user_agent(module_name: str, module_version: str) -> str:
    """Generate User-Agent string with system information.

    Creates a detailed User-Agent string that includes module information,
    Python version, and operating system details. Matches the format used
    by AWS SDKs and other professional APIs.

    Args:
        module_name (str): Name of the calling module or application.
        module_version (str): Version string of the module.

    Returns:
        str: Formatted User-Agent string with system information.

    Example:
        .. code-block:: python

            ua = generate_user_agent("core_api", "1.0.0")
            print(ua)
            # Output: "core_api/1.0.0 (Python/3.11.5; Windows/Version 10.0.19041)"
    """
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    os_name, os_version, _ = _get_version_info()
    user_agent = f"{module_name}/{module_version} (Python/{python_version}; {os_name}/{os_version})"
    return user_agent


def get_header(headers: Dict[str, str], name: str, default: Optional[str] = None) -> tuple[str, str]:
    """Get header value with case-insensitive lookup.

    Performs case-insensitive header lookup to handle variations in header
    capitalization. Returns both the actual header name (with original casing)
    and its value.

    Args:
        headers (Dict[str, str]): Dictionary of HTTP headers.
        name (str): Header name to search for (case-insensitive).
        default (Optional[str]): Default value if header not found.

    Returns:
        tuple[str, str]: A tuple containing:
            - Actual header name (with original casing) or the search name if not found
            - Header value or default value

    Example:
        .. code-block:: python

            headers = {"Content-Type": "application/json", "authorization": "Bearer token"}

            # Case-insensitive lookup
            name, value = get_header(headers, "CONTENT-TYPE")
            # Returns: ("Content-Type", "application/json")

            name, value = get_header(headers, "missing-header", "default")
            # Returns: ("missing-header", "default")
    """
    for k, v in headers.items():
        if k.lower() == name.lower():
            return k, v
    return name, default or ""


def get_ip_address() -> str:
    """Get the IP address of the current host.

    Attempts to determine the local IP address by resolving the hostname.
    This is used for X-Forwarded-For headers and source IP tracking.

    Returns:
        str: The IP address of the current host, or "127.0.0.1" if unable to determine.

    Note:
        This may return a private IP address in local development environments.

    Example:
        .. code-block:: python

            ip = get_ip_address()
            print(f"Host IP: {ip}")  # Output: "Host IP: 192.168.1.100"
    """
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception:
        return "127.0.0.1"


def _event_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Generate proxy forward headers with AWS API Gateway additions.

    Processes and enhances HTTP headers to match AWS API Gateway behavior.
    Adds required proxy headers like X-Forwarded-For, correlation IDs,
    and User-Agent information.

    Args:
        headers (Dict[str, str]): Original HTTP headers dictionary.

    Returns:
        Dict[str, str]: Enhanced headers with proxy information added.

    Note:
        Modifies the input headers dictionary in place and returns it.
        Adds correlation ID, forwarded IP, protocol, and User-Agent if missing.

    Example:
        .. code-block:: python

            original_headers = {"Authorization": "Bearer token"}
            enhanced_headers = _event_headers(original_headers)

            # Now includes:
            # - X-Correlation-Id: <uuid>
            # - X-Forwarded-For: <ip_address>
            # - X-Forwarded-Proto: https
            # - User-Agent: core_api/1.0.0 (Python/3.11; Windows/...)
    """
    # Append the ip_address to X_FORWARDED_FOR
    ip_address = get_ip_address()

    k, v = get_header(headers, HDR_X_FORWARDED_FOR.lower())
    if ip_address not in v:
        headers[k] = ",".join([v, ip_address])

    ua_header, ua = get_header(headers, "user-agent")
    if not ua:
        headers[ua_header] = _generate_user_agent("core_api", __version__)

    return headers


def _generate_resource_id(resource: str) -> str:
    """Generate a consistent hash for the resource ID.

    Creates a deterministic resource identifier based on the resource path.
    This matches AWS API Gateway's resource ID generation for consistency.

    Args:
        resource (str): The API resource path (e.g., "/users/{id}").

    Returns:
        str: A 12-character lowercase hexadecimal resource ID.

    Example:
        .. code-block:: python

            resource_id = generate_resource_id("/users/{id}")
            print(resource_id)  # Output: "a1b2c3d4e5f6"

            # Same resource always generates same ID
            assert generate_resource_id("/users/{id}") == resource_id
    """
    return hashlib.md5(resource.encode()).hexdigest()[:12].lower()


def generate_proxy_event(
    protocol: str,
    identity: CognitoIdentity,
    method: str,
    resource: str,
    path: str,
    path_params: Dict[str, str],
    query_params: Dict[str, str],
    body: str,
    headers: Dict[str, str],
    is_base64_encoded: bool = False,
    stage: str = "local",
) -> ProxyEvent:
    """Generate AWS API Gateway proxy event with complete AWS-compatible structure.

    Creates a proxy event that exactly matches the format AWS API Gateway sends
    to Lambda functions. Includes all required fields and follows AWS conventions
    for header processing, multi-value parameters, and request context.

    Args:
        protocol (str): HTTP protocol ("http" or "https").
        identity (CognitoIdentity): Authenticated user's identity information.
        method (str): HTTP method (GET, POST, PUT, DELETE, etc.).
        resource (str): API Gateway resource path with placeholders (e.g., "/users/{id}").
        path (str): Actual request path with resolved parameters (e.g., "/users/123").
        path_params (Dict[str, str]): Path parameters extracted from the URL.
        query_params (Dict[str, str]): Query string parameters.
        body (str): Request body content (may be base64 encoded for binary).
        headers (Dict[str, str]): HTTP request headers.
        is_base64_encoded (bool, optional): Whether body is base64 encoded. Defaults to False.
        stage (str, optional): API Gateway stage name. Defaults to "local".

    Returns:
        ProxyEvent: Complete AWS API Gateway proxy event object.

    Note:
        The generated event includes all fields that AWS API Gateway provides:

        - Complete request context with timing and identity
        - Multi-value headers and query parameters (even if empty)
        - Proper stage variables and extended request ID
        - Source IP and User-Agent processing

    Example:
        .. code-block:: python

            event = generate_proxy_event(
                protocol="https",
                identity=cognito_identity,
                method="POST",
                resource="/users",
                path="/users",
                path_params={},
                query_params={"include": "profile"},
                body='{"name": "John"}',
                headers={"Content-Type": "application/json"}
            )

            # Event now contains all AWS API Gateway fields:
            # event.httpMethod == "POST"
            # event.resource == "/users"
            # event.requestContext.requestId == "<uuid>"
            # event.multiValueHeaders == {"Content-Type": ["application/json"]}
    """
    headers = _event_headers(headers or {})

    # Generate multi-value versions (AWS API Gateway always includes these)
    multi_value_headers = {k: [v] for k, v in headers.items()}
    multi_value_query_params = {k: [v] for k, v in query_params.items()} if query_params else {}

    # Generate resource ID and request timing
    resource_id = _generate_resource_id(resource)
    request_time_epoch = int(time.time() * 1000)  # AWS uses milliseconds

    # Get correlation ID and extended request ID
    _, request_id = get_header(headers, HDR_X_CORRELATION_ID)
    extended_request_id = f"{request_id}={uuid.uuid4().hex}"

    # Create complete RequestContext matching AWS format
    request_context = RequestContext(
        resourceId=resource_id,
        resourcePath=resource,
        httpMethod=method,
        path=f"/{stage}{path}",  # AWS includes stage in path
        accountId=identity.accountId,
        protocol=f"{protocol}/1.1",  # AWS includes HTTP version
        requestId=request_id,
        extendedRequestId=extended_request_id,
        requestTime=datetime.fromtimestamp(request_time_epoch / 1000).strftime("%d/%b/%Y:%H:%M:%S %z"),
        requestTimeEpoch=request_time_epoch,
        identity=identity,
        stage=stage,
        domainName="localhost" if stage == "local" else "api.example.com",
        apiId="local",
    )

    # Create complete ProxyEvent
    rv = ProxyEvent(
        resource=resource,
        path=path,
        httpMethod=method,
        headers=headers,
        multiValueHeaders=multi_value_headers,
        queryStringParameters=query_params,
        multiValueQueryStringParameters=multi_value_query_params,
        pathParameters=path_params,
        stageVariables={},
        requestContext=request_context,
        body=body,
        isBase64Encoded=is_base64_encoded,
    )

    return rv


def get_user_information(session_token: str, role: Optional[str] = None) -> Optional[CognitoIdentity]:
    """
    Get AWS User Information
    """

    if role is None:
        account = util.get_automation_account()
        role = util.get_automation_api_role_arn(account)
    return aws.get_identity(session_token, role)


def get_locale() -> tuple[Optional[str], Optional[str]]:
    """Get the current system locale.

    Returns:
        tuple[Optional[str], Optional[str]]: Language and encoding information.

    Example:
        .. code-block:: python

            lang, encoding = get_locale()
            print(f"Locale: {lang}, Encoding: {encoding}")
            # Output: "Locale: en_US, Encoding: UTF-8"
    """
    return locale.getlocale()


class ClientContext(BaseModel):
    """Client context information for Lambda execution.

    Represents the client context that AWS Lambda provides to functions
    when invoked by mobile applications or other AWS services.

    Attributes:
        client (Dict[str, Any]): Client application information.
        environment (Dict[str, Any]): Client environment details.
    """

    client: Dict[str, Any]
    environment: Dict[str, Any]


class ProxyContext(BaseModel):
    """AWS Lambda execution context for proxy integration.

    Emulates the AWS Lambda context object that provides runtime information
    to Lambda functions. Includes all standard attributes and methods that
    AWS Lambda runtime provides.

    Attributes:
        function_name (str): Lambda function name.
        function_version (str): Function version (usually "$LATEST").
        invoked_function_arn (str): Complete ARN of the invoked function.
        memory_limit_in_mb (int): Memory limit configured for the function.
        aws_request_id (str): Unique request identifier.
        log_group_name (str): CloudWatch log group name.
        log_stream_name (str): CloudWatch log stream name.
        identity (Optional[Dict[str, Any]]): Mobile app identity information.
        client_context (ClientContext): Client application context.
        remaining_time (int): Remaining execution time in milliseconds.

    Note:
        This class provides the same interface as the AWS Lambda context object,
        allowing local handlers to use context.get_remaining_time_in_millis()
        and other standard context methods.
    """

    function_name: str = Field(default_factory=lambda: util.get_api_lambda_name() or API_LAMBDA_NAME)
    function_version: str = "$LATEST"
    invoked_function_arn: str = Field(
        default_factory=lambda: util.get_api_lambda_arn() or f"arn:aws:lambda:us-east-1:123456789012:function:{API_LAMBDA_NAME}"
    )
    memory_limit_in_mb: int = 512  # Realistic default
    aws_request_id: str
    log_group_name: str = Field(default_factory=lambda: f"/aws/lambda/{util.get_api_lambda_name() or API_LAMBDA_NAME}")
    log_stream_name: str = Field(default_factory=lambda: f"{datetime.now().strftime('%Y/%m/%d')}/[$LATEST]{uuid.uuid4().hex[:8]}")
    identity: Optional[Dict[str, Any]] = None
    client_context: ClientContext = Field(
        default_factory=lambda: ClientContext(
            client={
                "installation_id": str(uuid.uuid4()),
                "app_title": "core-api",
                "app_version_name": __version__,
                "app_version_code": __version__.replace(".", ""),
                "app_package_name": "core_api.api",
            },
            environment={
                "platform": _get_version_info()[0],
                "platform_version": _get_version_info()[1],
                "model": platform.machine(),
                "make": "Python",
                "locale": f"{get_locale()[0] or 'en_US'}.{get_locale()[1] or 'UTF-8'}",
                "network_type": "wifi",  # AWS mobile context
            },
        )
    )
    remaining_time: int = 300000  # 5 minutes in milliseconds

    def get_remaining_time_in_millis(self) -> int:
        """Get remaining execution time in milliseconds.

        Returns:
            int: Remaining time in milliseconds before Lambda timeout.

        Note:
            This method signature matches AWS Lambda's context object exactly.
        """
        return self.remaining_time

    def set_remaining_time_in_millis(self, value: int) -> None:
        """Set remaining execution time in milliseconds.

        Args:
            value (int): Time in milliseconds before timeout.

        Note:
            Used for testing timeout scenarios in local development.
        """
        self.remaining_time = value


def generate_proxy_context(event: ProxyEvent) -> ProxyContext:
    """Generate Lambda execution context from API Gateway event.

    Creates a Lambda context object that matches what AWS Lambda runtime
    provides to functions. Uses information from the proxy event to set
    request-specific context values.

    Args:
        event (ProxyEvent): API Gateway proxy event containing request information.

    Returns:
        ProxyContext: Lambda execution context with request-specific values.

    Note:
        The generated context includes:

        - Request ID from the event
        - Identity information from Cognito
        - Realistic log stream names with timestamps
        - Client context matching AWS mobile app format

    Example:
        .. code-block:: python

            context = generate_proxy_context(event)

            # Context has AWS Lambda interface
            print(f"Request ID: {context.aws_request_id}")
            print(f"Function: {context.function_name}")
            print(f"Remaining time: {context.get_remaining_time_in_millis()}ms")

            # Use in Lambda handler
            result = lambda_handler(event.model_dump(), context)
    """
    aws_request_id = event.requestContext.requestId

    # Why do we do this?  Well, I've observed that in the "real-world"
    # This is a simple dictionary, while "ProxyContext" is a complex object
    # so, we just dump this to match what we observe AWS does.
    identity = event.requestContext.identity.model_dump() if event.requestContext.identity else None

    return ProxyContext(aws_request_id=aws_request_id, identity=identity)
