from typing import Dict, List, Optional, Any
from enum import Enum

import os
import json
import base64
import datetime
import traceback

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic import computed_field

from typing import Any, Literal, Self, Optional, Union, Dict
from datetime import timezone, datetime

from pydantic import BaseModel, Field, ConfigDict, model_validator
from pydantic import ValidationError

from core_framework.constants import (
    HTTP_OK,
    HTTP_INTERNAL_SERVER_ERROR,
    HTTP_NO_CONTENT,
    HTTP_CREATED,
)


class Response(BaseModel):
    """Base response model for all API responses.

    This object is returned by all database actions and can be serialized
    to JSON for API responses. It provides a consistent structure for both
    successful and error responses, with optional cookie support for OAuth
    and session management.

    Args:
        status (Literal["ok", "error"], optional): The status of the response, either "ok" for
            success or "error" for failures. Defaults to "ok".
        code (int, optional): The HTTP status code associated with the response.
            Defaults to 200 (HTTP_OK).
        data (dict | list | str | None, optional): The main response payload containing the
            requested data or operation result. Must be a dictionary, list, or string.
            Defaults to None.
        message (str, optional): Custom error message for convenience. This field is excluded
            from serialization but used to populate the data field. Defaults to None.
        links (list[dict] | None, optional): Links to related resources following REST API
            conventions. Defaults to None.
        metadata (dict | None, optional): Additional metadata about the response or operation.
            Defaults to None.
        cookies (list[str] | None, optional): Set-Cookie header values for browser session
            management. Excluded from JSON serialization. Defaults to None.

    Attributes:
        status (str): Response status indicator
        code (int): HTTP status code
        data (dict | list | str | None): Response payload
        links (list[dict] | None): Related resource links
        metadata (dict | None): Additional response metadata
        cookies (list[str] | None): Cookie header values (excluded from serialization)

    Properties:
        timestamp (str): ISO formatted timestamp of when the response was created

    Note:
        **For Invoker Handler**: This object is converted to a dictionary and returned directly.

        **For Gateway Handler**: This object is serialized to JSON and returned as the
        response body in a GatewayResponse object.

        **For OAuth Handler**: Cookies are extracted and converted to AWS API Gateway
        multi-value headers format.

        **Validation**: The data field must be a dictionary, list, or string. Other types
        will raise a ValueError during model validation.
    """

    model_config = ConfigDict(populate_by_name=True)

    status: Literal["ok", "error"] = Field(
        "ok",
        description="The status of the response: 'ok' for success, 'error' for failure",
    )
    code: int = Field(
        HTTP_OK,
        description="The HTTP status code",
    )
    data: dict | list | str | None = Field(
        None,
        description="The main response data (DynamoDB object or composite response)",
    )

    message: str | None = Field(
        default=None,
        description="Custom error message for convenience (excluded from serialization)",
    )

    links: list[dict] | None = Field(
        None,
        description="Links to related resources following REST API conventions",
    )

    metadata: dict | None = Field(
        None,
        description="Additional metadata about the response or operation",
    )

    # Add optional cookie support for OAuth/session endpoints
    cookies: list[str] | None = Field(
        None,
        description="Set-Cookie header values for browser session management",
        exclude=True,  # Exclude from JSON serialization to maintain API compatibility
    )

    headers: list[dict] | None = Field(
        None,
        description="Additional HTTP headers for the response",
        exclude=True,  # Exclude from JSON serialization to maintain API compatibility
    )

    def set_header(self, name: str, value: str) -> None:
        """Set a custom HTTP header in the response.

        Args:
            name (str): The name of the header to set
            value (str): The value of the header

        Examples:
            >>> response = Response(data={"key": "value"})
            >>> response.set_header("X-Custom-Header", "CustomValue")
            >>> print(response.headers)
            [{"X-Custom-Header": "CustomValue"}]
        """
        if self.headers is None:
            self.headers = []
        self.headers.append({name: value})

    def delete_header(self, name: str) -> None:
        """Delete a custom HTTP header from the response.

        Args:
            name (str): The name of the header to delete

        Examples:
            >>> response = Response(data={"key": "value"})
            >>> response.set_header("X-Custom-Header", "CustomValue")
            >>> print(response.headers)
            [{"X-Custom-Header": "CustomValue"}]
            >>> response.delete_header("X-Custom-Header")
            >>> print(response.headers)
            []
        """
        if self.headers is None:
            return
        self.headers = [h for h in self.headers if name not in h]

    def delete_cookie(
        self,
        key: str,
        path: str = "/",
        domain: Optional[str] = None,
        secure: bool = False,
        httponly: bool = False,
        samesite: Optional[str] = "lax",
    ) -> None:
        """Delete a cookie by setting it to empty value with immediate expiration.

        Args:
            key (str): Cookie name to delete
            path (str): Cookie path scope (default: "/")
            domain (Optional[str]): Cookie domain scope
            secure (bool): Secure flag (default: False)
            httponly (bool): HttpOnly flag (default: False)
            samesite (Optional[str]): SameSite policy (default: "lax")
        """
        self.set_cookie(
            key=key,
            value="",
            max_age=0,
            expires="Thu, 01 Jan 1970 00:00:00 GMT",
            path=path,
            domain=domain,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
        )

    def set_cookie(
        self,
        key: str,
        value: str = "",
        max_age: Optional[int] = None,
        expires: Optional[Union[datetime, str, int]] = None,
        path: str = "/",
        domain: Optional[str] = None,
        secure: bool = False,
        httponly: bool = False,
        samesite: Optional[str] = "lax",
    ) -> None:
        """Set a cookie in the response.

        This method signature matches FastAPI's Response.set_cookie() exactly,
        allowing drop-in replacement without code modifications. The generated
        cookie string follows the HTTP Set-Cookie header format specification.

        Args:
            key (str): Cookie name (e.g., "session_id", "oauth_state")
            value (str): Cookie value (default: "")
            max_age (Optional[int]): Cookie lifetime in seconds. Takes precedence over expires.
            expires (Optional[Union[datetime, str, int]]): Cookie expiration as datetime,
                string, or Unix timestamp. Ignored if max_age is set.
            path (str): Cookie path scope (default: "/")
            domain (Optional[str]): Cookie domain scope (e.g., ".example.com")
            secure (bool): Secure flag - only send over HTTPS (default: False)
            httponly (bool): HttpOnly flag - not accessible via JavaScript (default: False)
            samesite (Optional[str]): SameSite policy: "strict", "lax", or "none" (default: "lax")

        Returns:
            None: Modifies the response's cookies list in-place

        Note:
            **Cookie Precedence**: If both max_age and expires are provided, max_age takes
            precedence as per HTTP specification.

            **SameSite Handling**: The samesite value is automatically title-cased to match
            HTTP specification ("Lax", "Strict", "None").

            **Datetime Handling**: datetime objects are converted to HTTP-date format
            automatically. Unix timestamps are converted to datetime first.

            **AWS API Gateway**: These cookies are automatically converted to multi-value
            Set-Cookie headers when used with ProxyResponse.
        """
        if self.cookies is None:
            self.cookies = []

        # Build cookie string following HTTP Set-Cookie format
        cookie_parts = [f"{key}={value}"]

        if max_age is not None:
            cookie_parts.append(f"Max-Age={max_age}")

        if expires is not None:
            if isinstance(expires, datetime):
                expires_str = expires.strftime("%a, %d %b %Y %H:%M:%S GMT")
            elif isinstance(expires, str):
                expires_str = expires
            elif isinstance(expires, int):
                # Assume Unix timestamp
                expires_dt = datetime.fromtimestamp(expires)
                expires_str = expires_dt.strftime("%a, %d %b %Y %H:%M:%S GMT")
            else:
                expires_str = str(expires)
            cookie_parts.append(f"Expires={expires_str}")

        if path:
            cookie_parts.append(f"Path={path}")

        if domain:
            cookie_parts.append(f"Domain={domain}")

        if secure:
            cookie_parts.append("Secure")

        if httponly:
            cookie_parts.append("HttpOnly")

        if samesite:
            cookie_parts.append(f"SameSite={samesite.title()}")

        cookie_string = "; ".join(cookie_parts)
        self.cookies.append(cookie_string)

    @property
    def timestamp(self) -> str:
        """Get the current timestamp in ISO format.

        Returns the current UTC timestamp whenever accessed, providing a
        fresh timestamp for each property access.

        Returns:
            str: ISO formatted timestamp in UTC timezone with microsecond precision

        Note:
            This property generates a new timestamp on each access rather than
            storing a creation timestamp. For audit trails requiring a fixed
            creation time, store the timestamp value when the response is created.
        """
        return datetime.now(timezone.utc).isoformat()

    @model_validator(mode="before")
    @classmethod
    def validate_model(cls, values: Any) -> Any:
        """Validate the response model before instantiation.

        Performs validation on the input values, ensuring the data field contains
        only supported types (dict, list, str) and handles both snake_case and
        PascalCase field naming conventions.

        Args:
            values (Any): The input values to validate, typically a dictionary

        Returns:
            Any: Validated values with data field properly typed

        Raises:
            ValueError: If data field is not a dictionary, list, or string

        Note:
            **BaseModel Handling**: If data is a Pydantic BaseModel, it's automatically
            converted to a dictionary using model_dump(mode="json").

            **Case Sensitivity**: Supports both "data" and "Data" field names for
            compatibility with DynamoDB PascalCase conventions.
        """
        if isinstance(values, dict):
            # Check both snake_case and PascalCase field names
            data = values.get("data")
            if data is not None:
                if isinstance(data, BaseModel):
                    data = data.model_dump(mode="json")
                elif not isinstance(data, (dict, list, str)):
                    raise ValueError("data must be a dictionary, list, or string")
                values["data"] = data
        return values

    def model_dump(self, **kwargs) -> dict:
        """Convert the model to a dictionary, excluding None values by default.

        Provides consistent serialization behavior across all response types,
        with sensible defaults for API responses.

        Args:
            **kwargs: Additional arguments for model dumping. Common options:
                - exclude_none (bool): Exclude None values (default: True)
                - by_alias (bool): Use field aliases (default: False)
                - exclude (set): Fields to exclude from output
                - include (set): Fields to include in output

        Returns:
            dict: Dictionary representation of the response with None values excluded

        Note:
            **Default Behavior**: Unlike standard Pydantic models, this method defaults
            to exclude_none=True for cleaner API responses.

            **Excluded Fields**: Fields marked with exclude=True (like cookies and message)
            are automatically excluded from serialization.
        """
        # Set default exclude_none=True if not specified
        kwargs.setdefault("exclude_none", True)
        return super().model_dump(**kwargs)

    def model_dump_json(self, **kwargs) -> str:
        """Convert the model to a JSON string, excluding None values by default."""
        kwargs.setdefault("exclude_none", True)
        return super().model_dump_json(**kwargs)

    def __repr__(self) -> str:
        """Return string representation of the Response.

        Provides a concise string representation showing the key response attributes
        for debugging and logging purposes.

        Returns:
            str: String representation showing status, code, and data

        """
        return f"Response(status={self.status}, code={self.code}, data={self.data})"


class SuccessResponse(Response):
    """Convenience class for successful API responses.

    This class automatically sets the status to "ok" and code to 200,
    simplifying the creation of successful responses.

    Args:
        data (Any, optional): The response data to return. Can be dict, list, string, or None.
            Defaults to None.
        links (list[dict], optional): Links to related resources following REST conventions.
            Defaults to None.
        metadata (dict, optional): Additional metadata for the response. Defaults to None.
        message (str, optional): Convenience message that will be set as data if data is None,
            or added to data dict if data is a dictionary. Defaults to None.

    """

    @model_validator(mode="after")
    def validate_after(self) -> Self:
        """Validate the success response after instantiation.

        This method ensures the response is properly configured for success,
        setting status to "ok" and handling message processing.

        Returns:
            SuccessResponse: The validated SuccessResponse instance

        """
        # Ensure status is "ok" and code is HTTP_OK
        self.status = "ok"
        if not self.code or self.code < 200 or self.code >= 300:
            self.code = HTTP_OK

        return self

    def __repr__(self) -> str:
        """Return string representation of the SuccessResponse.

        Returns:
            str: String representation showing the response data

        """
        return f"SuccessResponse(data={self.data})"


class CreatedResponse(Response):
    """Convenience class for created responses.

    This class is used when a resource is successfully created. Sets status to "ok" and code to 201 (Created).
    """

    @model_validator(mode="after")
    def validate_after(self) -> Self:
        self.status = "ok"
        self.code = HTTP_CREATED
        return self


class NoContentResponse(Response):
    """Convenience class for no-content responses.

    This class is used when an operation completes successfully but has no
    content to return. Sets status to "ok" and code to 204 (No Content).

    Args:
        data (Any, optional): The response data, typically a message explaining the
            no-content status. Can be dict, list, string, or None. Defaults to None.
        links (list[dict], optional): Links to related resources. Defaults to None.
        metadata (dict, optional): Additional metadata for the response. Defaults to None.
        message (str, optional): Convenience message for the no-content response.
            Defaults to None.

    """

    @model_validator(mode="after")
    def validate_after(self) -> Self:
        """Validate the no-content response after instantiation.

        This method ensures the response is properly configured for no-content,
        setting status to "ok" and code to 204.

        Returns:
            NoContentResponse: The validated NoContentResponse instance

        """
        # Ensure data is None or a string message
        self.status = "ok"
        self.code = HTTP_NO_CONTENT

        return self

    def __repr__(self) -> str:
        """Return string representation of the NoContentResponse.

        Returns:
            str: String representation showing the response data

        """
        return f"NoContentResponse(data={self.data})"


class ErrorDetail(BaseModel):
    """Model representing detailed error information.

    This class captures exception details including type, message, and stack trace
    for comprehensive error reporting in API responses.

    Args:
        type (str): The type of the exception that occurred (e.g., "ValueError", "KeyError")
        message (str): The error message describing what went wrong
        track (str, optional): The stack trace information for debugging purposes.
            Defaults to None.

    Attributes:
        type (str): Exception type name
        message (str): Error message
        track (str | None): Stack trace for debugging

    """

    model_config = ConfigDict(populate_by_name=True)

    type: str = Field(
        ...,
        description="The type of the exception",
    )
    message: str = Field(
        ...,
        description="The error message",
    )
    track: str | None = Field(
        None,
        description="The stack trace of the error",
    )

    def model_dump(self, **kwargs) -> dict:
        """Convert the model to a dictionary, excluding None values by default.

        Args:
            **kwargs: Additional arguments for model dumping. Common options:
                - exclude_none (bool): Exclude None values (default: True)
                - by_alias (bool): Use field aliases (default: False)

        Returns:
            dict: Dictionary representation of the error detail

        """
        # Set default exclude_none=True if not specified
        kwargs.setdefault("exclude_none", True)
        return super().model_dump(**kwargs)


class ErrorResponse(Response):
    """Convenience class for error API responses.

    This class automatically sets the status to "error" and builds a comprehensive
    error chain from the provided exception, including stack traces for debugging.

    Args:
        exception (Exception, optional): The exception that caused the error. If provided,
            the code will be extracted from exception.code (if available) and the message
            from str(exception). Defaults to None.
        code (int, optional): The HTTP status code. If not provided and exception has a
            code attribute, that will be used. Otherwise defaults to 500. Defaults to None.
        message (str, optional): Custom error message. If not provided and exception is
            given, str(exception) will be used. Defaults to None.
        metadata (dict, optional): Additional metadata for the error response.
            Defaults to None.

    Attributes:
        exception (Exception | None): The original exception (excluded from serialization)
        errors (list[ErrorDetail] | None): List of error details with traceback information

    """

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)

    error: str | None = Field(None, description="Stable, human-readable error code")

    errors: list[ErrorDetail] | None = Field(
        None,
        description="List of errors that occurred during processing with traceback information",
    )

    # Add exception field to store the original exception (optional and excluded from serialization)
    exception: Exception | None = Field(
        default=None,
        description="The original exception",
        exclude=True,
    )

    @model_validator(mode="after")
    def build_error_response(self) -> Self:
        """Build error response after model instantiation.

        This method configures the error response by extracting information from the
        exception, setting appropriate status codes, and building the error chain.

        Returns:
            ErrorResponse: The configured ErrorResponse instance

        """
        self.status = "error"

        # Extract code from exception if not provided
        if not self.code and self.exception:
            self.code = getattr(self.exception, "code", HTTP_INTERNAL_SERVER_ERROR)
        elif not self.code:
            self.code = HTTP_INTERNAL_SERVER_ERROR

        if not self.error:
            self.error = self._get_error_name(self.code)

        # Build error chain from exception if not already provided
        if not self.errors and self.exception:
            self.errors = _build_error_chain(self.exception)

        return self

    def _get_error_name(self, status_code: int) -> str:
        """Map HTTP status codes to stable, SPA-friendly error codes.

        AWS API Gateway doesn't require any particular error name. We provide a
        comprehensive, human-readable, snake_case mapping for all standard 4xx and
        5xx statuses so the SPA can react consistently. Unknown 4xx map to
        "client_error" and unknown 5xx map to "server_error".

        Args:
            status_code (int): HTTP status code

        Returns:
            str: Error code (e.g., "bad_request", "unauthorized", "not_found").
        """
        # Centralized mapping table for API Gateway error responses used across the codebase.
        # This table is intentionally exhaustive for common web errors so the SPA can

        # switch on a stable, human-readable code regardless of the numeric HTTP status.
        ERROR_CODE_TO_NAME: Dict[int, str] = {
            # 4xx Client Errors
            400: "bad_request",
            401: "unauthorized",
            402: "payment_required",
            403: "forbidden",
            404: "not_found",
            405: "method_not_allowed",
            406: "not_acceptable",
            407: "proxy_authentication_required",
            408: "request_timeout",
            409: "conflict",
            410: "gone",
            411: "length_required",
            412: "precondition_failed",
            413: "payload_too_large",
            414: "uri_too_long",
            415: "unsupported_media_type",
            416: "range_not_satisfiable",
            417: "expectation_failed",
            418: "im_a_teapot",
            421: "misdirected_request",
            422: "unprocessable_entity",
            423: "locked",
            424: "failed_dependency",
            425: "too_early",
            426: "upgrade_required",
            428: "precondition_required",
            429: "too_many_requests",
            431: "request_header_fields_too_large",
            451: "unavailable_for_legal_reasons",
            # 5xx Server Errors
            500: "internal_server_error",
            501: "not_implemented",
            502: "bad_gateway",
            503: "service_unavailable",
            504: "gateway_timeout",
            505: "http_version_not_supported",
            506: "variant_also_negotiates",
            507: "insufficient_storage",
            508: "loop_detected",
            510: "not_extended",
            511: "network_authentication_required",
        }

        if status_code in ERROR_CODE_TO_NAME:
            return ERROR_CODE_TO_NAME[status_code]
        if 400 <= status_code <= 499:
            return "client_error"
        if 500 <= status_code <= 599:
            return "server_error"
        # Non-error classes shouldn't hit this function, but provide a safe default
        return "unknown_error"

    def __repr__(self) -> str:
        """Return string representation of the ErrorResponse.

        Returns:
            str: String representation showing the error code and message

        """
        message = self.data.get("message") if isinstance(self.data, dict) else None
        return f"ErrorResponse(code={self.code}, message={message})"


def _build_error_chain(exc: Exception) -> list[ErrorDetail]:
    """Build a chain of error details from an exception and its causes.

    This function traverses the exception chain (including __cause__ and __context__)
    to create a comprehensive list of error details for debugging.

    Args:
        exc (Exception): The exception to build the error chain from

    Returns:
        list[ErrorDetail]: List of error details representing the exception chain,
            starting with the most recent exception

    Examples:
        >>> # Building error chain from a simple exception
        >>> try:
        ...     raise ValueError("Invalid input")
        ... except ValueError as e:
        ...     errors = _build_error_chain(e)
        >>> len(errors)  # 1
        >>> errors[0].type  # "ValueError"
        >>> errors[0].message  # "Invalid input"

        >>> # Building error chain from chained exceptions
        >>> try:
        ...     try:
        ...         raise ValueError("Original error")
        ...     except ValueError as e:
        ...         raise RuntimeError("Secondary error") from e
        ... except RuntimeError as e:
        ...     errors = _build_error_chain(e)
        >>> len(errors)  # 2
        >>> errors[0].type  # "RuntimeError" (most recent)
        >>> errors[1].type  # "ValueError" (original cause)

        >>> # Pydantic ValidationError with multiple field errors
        >>> from pydantic import BaseModel, ValidationError
        >>> class TestModel(BaseModel):
        ...     name: str
        ...     age: int
        >>> try:
        ...     TestModel(name="", age="invalid")
        ... except ValidationError as e:
        ...     errors = _build_error_chain(e)
        >>> len(errors)  # Multiple errors - one for each validation failure
        >>> errors[0].type  # "ValidationError"
        >>> "name" in errors[0].message  # True - contains field info
    """
    if isinstance(exc, ValidationError):
        # Special case for Pydantic ValidationError - create individual error details for each validation error
        error_chain = []

        for error in exc.errors():
            # Extract field path
            field_path = " -> ".join(str(loc) for loc in error["loc"]) if error["loc"] else "root"

            # Build detailed error message
            error_type = error["type"]
            error_msg = error["msg"]
            error_input = error.get("input")

            # Format message with field context
            if error_input is not None:
                message = f"Field '{field_path}': {error_msg} (received: {error_input})"
            else:
                message = f"Field '{field_path}': {error_msg}"

            error_detail = ErrorDetail(
                type=f"ValidationError.{error_type}",
                message=message,
                track="".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
            )
            error_chain.append(error_detail)

        return error_chain

    # Handle regular exceptions
    error_chain = []
    while exc:
        error_detail = ErrorDetail(
            type=type(exc).__name__,
            message=str(exc),
            track="".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
        )
        error_chain.append(error_detail)
        exc = exc.__cause__ or exc.__context__

    return error_chain


class RedirectResponse(Response):

    url: str = Field(
        ...,
        description="The URL to redirect to",
        exclude=True,
    )

    @model_validator(mode="before")
    @classmethod
    def validate(cls, values: dict[str, Any]) -> dict[str, Any]:
        values["code"] = 302
        return values

    def __repr__(self) -> str:
        return f"RedirectResponse(code={self.code}, url={self.url})"


# --- Cookie utilities -------------------------------------------------------
def cookie_opts() -> Dict[str, Any]:
    """Return default cookie options derived from environment.

    Centralizes cookie policy so all endpoints set/delete cookies consistently.

    Environment variables:
      - ENVIRONMENT: when "production" defaults SameSite=None, otherwise Lax
      - SCK_COOKIE_SAMESITE: none|lax|strict (overrides default)
      - SCK_COOKIE_SECURE: true|false (defaults true when SameSite=None)
      - SCK_COOKIE_HTTPONLY: true|false (default true)
      - SCK_COOKIE_DOMAIN: cookie Domain attribute (omit/None to bind to host)
      - SCK_COOKIE_PATH: cookie Path attribute (default "/")

    Returns a dict suitable for passing to set_cookie/delete_cookie, e.g.:
        response.set_cookie("session", token, max_age=1800, **cookie_opts())
        response.delete_cookie("session", **cookie_opts())
    """
    env = os.getenv("ENVIRONMENT", "development").lower()

    # Determine SameSite with sensible defaults per environment
    default_samesite = "none" if env == "production" else "lax"
    samesite = os.getenv("SCK_COOKIE_SAMESITE", default_samesite).strip().lower()
    if samesite not in ("none", "lax", "strict"):
        samesite = default_samesite

    # Secure default: required when SameSite=None; otherwise configurable
    secure_env = os.getenv("SCK_COOKIE_SECURE", "").strip().lower()
    if secure_env:
        secure = secure_env in ("1", "true", "yes", "on")
    else:
        secure = samesite == "none"

    # Enforce modern browser rule: SameSite=None requires Secure
    if samesite == "none" and not secure:
        secure = True

    httponly = os.getenv("SCK_COOKIE_HTTPONLY", "true").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    path = os.getenv("SCK_COOKIE_PATH", "/")
    domain = os.getenv("SCK_COOKIE_DOMAIN") or None  # Keep None to omit Domain attribute

    return {
        "path": path,
        "domain": domain,
        "secure": secure,
        "httponly": httponly,
        "samesite": samesite,
    }


class HttpStatus(int, Enum):
    """HTTP status codes for API responses."""

    # Success
    OK = 200
    CREATED = 201
    NO_CONTENT = 204

    # Redirection
    MOVED_PERMANENTLY = 301
    FOUND = 302
    SEE_OTHER = 303
    NOT_MODIFIED = 304
    TEMPORARY_REDIRECT = 307
    PERMANENT_REDIRECT = 308

    # Client Error
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    CONFLICT = 409
    UNPROCESSABLE_ENTITY = 422

    # Server Error
    INTERNAL_SERVER_ERROR = 500
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503


class ProxyResponse(BaseModel):
    """AWS API Gateway Lambda proxy integration response model.

    Ensures Lambda function responses conform exactly to the AWS API Gateway
    proxy integration response format. Provides validation, helper methods, and
    automatic formatting to prevent integration issues.

    AWS API Gateway requires responses in this exact format:

    Example Recommended Usage:

        proxy = ProxyResponse.from_response(response)
        return proxy.model_dump()

    .. code-block:: python

        {
            "isBase64Encoded": false,
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Cache-Control": "no-cache"
            },
            "multiValueHeaders": {
                "Set-Cookie": [
                    "session=abc123; HttpOnly",
                    "csrf=xyz789; Secure"
                ]
            },
            "body": '{"message": "Success"}'
        }

    Attributes:
        statusCode (int): HTTP status code (required by AWS API Gateway)
        body (str): Response body content as string (required)
        headers (Dict[str, str]): Single-value HTTP headers (optional)
        multiValueHeaders (Dict[str, List[str]]): Multi-value headers (optional)
        isBase64Encoded (bool): Whether body is base64 encoded (optional)

    """

    statusCode: int = Field(..., description="HTTP status code required by AWS API Gateway")
    body: str = Field(default="", description="Response body content as string")
    headers: Dict[str, str] = Field(default_factory=dict, description="Single-value HTTP headers")
    multiValueHeaders: Dict[str, List[str]] = Field(default_factory=dict, description="Multi-value HTTP headers")
    isBase64Encoded: bool = Field(default=False, description="Whether body content is base64 encoded")

    @field_validator("statusCode", mode="before")
    @classmethod
    def validate_status_code(cls, v):
        """Validate that status code is a valid HTTP status code."""
        if not isinstance(v, int) or v < 100 or v > 599:
            raise ValueError(f"Invalid HTTP status code: {v}. Must be between 100-599")
        return v

    @field_validator("body", mode="before")
    @classmethod
    def validate_body_is_string(cls, v):
        """Ensure body is always a string for AWS API Gateway compatibility."""
        if v is None:
            return ""
        if not isinstance(v, str):
            raise ValueError("Body must be a string for AWS API Gateway compatibility")
        return v

    def add_header(self, name: str, value: str) -> "ProxyResponse":
        """Add a single-value header to the response.

        Args:
            name (str): Header name (e.g., "Content-Type")
            value (str): Header value (e.g., "application/json")

        Returns:
            ProxyResponse: Self for method chaining

        Example:
            .. code-block:: python

                response = ProxyResponse(statusCode=200)
                response.add_header("Content-Type", "application/json")
                response.add_header("Cache-Control", "no-cache")
        """
        self.headers[str(name)] = str(value)
        return self

    def add_multi_value_header(self, name: str, value: str) -> "ProxyResponse":
        """Add a multi-value header to the response.

        Useful for headers like Set-Cookie where multiple values are needed.

        Args:
            name (str): Header name (e.g., "Set-Cookie")
            value (str): Header value to add

        Returns:
            ProxyResponse: Self for method chaining

        Example:
            .. code-block:: python

                response = ProxyResponse(statusCode=200)
                response.add_multi_value_header("Set-Cookie", "session=abc123; HttpOnly")
                response.add_multi_value_header("Set-Cookie", "csrf=xyz789; Secure")
        """
        if name not in self.multiValueHeaders:
            self.multiValueHeaders[name] = []
        self.multiValueHeaders[name].append(str(value))
        return self

    def add_cookie(self, cookie_string: str) -> "ProxyResponse":
        """Add a Set-Cookie header to the response.

        Convenience method for adding cookies using the multi-value header mechanism.

        Args:
            cookie_string (str): Complete cookie string (e.g., "session=abc123; HttpOnly; Secure")

        Returns:
            ProxyResponse: Self for method chaining

        Example:
            .. code-block:: python

                response = ProxyResponse(statusCode=200)
                response.add_cookie("session_id=abc123; Path=/; HttpOnly; SameSite=Lax")
                response.add_cookie("csrf_token=xyz789; Path=/; Secure")
        """
        return self.add_multi_value_header("Set-Cookie", cookie_string)

    def set_binary_body(self, content: bytes, content_type: str = "application/octet-stream") -> "ProxyResponse":
        """Set the response body to base64-encoded binary content.

        Args:
            content (bytes): Binary content to encode
            content_type (str): MIME type of the content

        Returns:
            ProxyResponse: Self for method chaining

        Example:
            .. code-block:: python

                with open("report.pdf", "rb") as f:
                    pdf_data = f.read()

                response = ProxyResponse(statusCode=200)
                response.set_binary_body(pdf_data, "application/pdf")
                response.add_header("content-disposition", "attachment; filename=report.pdf")
        """
        self.body = base64.b64encode(content).decode("utf-8")
        self.isBase64Encoded = True
        self.add_header("Content-Type", content_type)
        return self

    @classmethod
    def from_response(cls, response: Response) -> "ProxyResponse":
        """Create a ProxyResponse from a core Response/Error/Redirect.

        Rules:
        - 3xx -> redirect: set Location header and empty body
        - otherwise -> JSON body from response.model_dump_json(by_alias=False)
        - copy single-value headers and cookies
        - add default no-cache headers unless SCK_API_NO_CACHE is false
        """
        add_cache_control = os.getenv("SCK_API_NO_CACHE", "true").lower() in ("1", "true", "yes")

        # Instantiate ProxyResponse
        proxy = cls(statusCode=response.code)

        # Add single-value headers directly
        if response.headers:
            for item in response.headers:
                for name, value in item.items():
                    proxy.add_header(name, value)

        # Redirect responses
        if isinstance(response, RedirectResponse) and cls._is_valid_location_url(response.url):

            # Add Redirect headers
            proxy.add_header("Location", response.url)

        else:

            # Add JSON headers
            proxy.add_header("Content-Type", "application/json")

            # Serialize body to JSON
            try:
                if response.code != 204:  # No body for 204 No Content
                    proxy.body = response.model_dump_json(by_alias=False, exclude_none=True)
            except Exception:
                if isinstance(response, BaseModel):
                    obj = response.model_dump(by_alias=False, mode="json")
                else:
                    obj = response  # Fallback
                proxy.body = json.dumps(obj, default=str)

        # Add cookies
        if response.cookies:
            for cookie in response.cookies:
                proxy.add_cookie(cookie)

        # Add default no-cache headers
        if add_cache_control:
            proxy.add_header("Cache-Control", "no-cache, no-store, must-revalidate")
            proxy.add_header("Pragma", "no-cache")
            proxy.add_header("Expires", "0")

        return proxy

    @classmethod
    def _is_valid_location_url(cls, url: str) -> bool:
        """Basic validation for redirect URLs."""
        if not url or not isinstance(url, str):
            return False
        url = url.strip()
        if url.startswith(("/", "http://", "https://")):
            return True
        return False


def get_proxy_response(response: Response) -> dict:
    """Return AWS proxy dict via ProxyResponse.from_response(response)."""
    return ProxyResponse.from_response(response).model_dump()


def get_proxy_error_response(error: ErrorResponse) -> dict:
    """Return AWS proxy dict via ProxyResponse.from_response(error)."""
    return ProxyResponse.from_response(error).model_dump()


class OAuthResponse(Response):

    def model_dump(self, **kwargs):

        kwargs["exclude"] = self._get_exclude_fields(**kwargs)

        return super().model_dump(**kwargs)

    def model_dump_json(self, **kwargs):

        kwargs["exclude"] = self._get_exclude_fields(**kwargs)

        return super().model_dump_json(**kwargs)

    def _get_exclude_fields(self, **kwargs) -> set:

        exclude = kwargs.get("exclude", set())

        if isinstance(exclude, str):
            exclude = {exclude}
        elif not isinstance(exclude, set):
            exclude = set(exclude) if exclude else set()

        return exclude | {"code", "status", "message", "data", "links", "metadata"}

    def __repr__(self):
        return f"<OAuthResponse status={self.status or ''} code={self.code or ''}>"


class OAuthSuccessResponse(OAuthResponse):

    @model_validator(mode="before")
    def validate_success(cls, values):
        # Custom validation logic for success responses
        values["status"] = "ok"
        values["code"] = 200
        return values

    def __repr__(self):
        return f"<OAuthSuccessResponse status={self.status or 'ok'} code={self.code or '200'}>"


class OAuthErrorResponse(OAuthResponse):

    error_description: str
    error_uri: Optional[str] = None
    state: Optional[str] = None

    @computed_field
    @property
    def error(self) -> str:
        """Auto-generate OAuth error code from HTTP status code"""
        error_mapping = {
            400: "invalid_request",
            401: "invalid_client",
            403: "access_denied",
            404: "invalid_request",
            500: "server_error",
            502: "temporarily_unavailable",
            503: "temporarily_unavailable",
        }
        return error_mapping.get(self.code, "server_error")

    @model_validator(mode="before")
    def validate_oauth_response(cls, values):
        if "code" not in values:
            raise ValueError("code is required for OAuthErrorResponse")
        values["status"] = "error"
        return values

    def __repr__(self):
        return f"<OAuthErrorResponse error={self.error} description={self.error_description}>"


class OAuthTokenResponse(OAuthSuccessResponse):
    """OAuth token endpoint response (RFC 6749 Section 5.1)."""

    access_token: str = Field(description="The access token issued by the authorization server")
    token_type: str = Field(default="Bearer", description="The type of token issued")
    expires_in: Optional[int] = Field(default=None, description="Token lifetime in seconds")
    scope: Optional[str] = Field(default=None, description="The scope of the access token")
    refresh_token: Optional[str] = Field(default=None, description="The refresh token for obtaining new access tokens")

    def __repr__(self):
        return f"<OAuthTokenResponse token_type={self.token_type} expires_in={self.expires_in} scope={self.scope}>"


class OAuthIntrospectionResponse(OAuthSuccessResponse):
    """OAuth introspection endpoint response (RFC 7662)."""

    active: bool = Field(description="Whether the token is active")
    client_id: Optional[str] = Field(default=None, description="Client identifier for the OAuth client")
    username: Optional[str] = Field(default=None, description="Human-readable identifier for the resource owner")
    scope: Optional[str] = Field(default=None, description="Space-separated list of scopes")
    token_type: Optional[str] = Field(default=None, description="Type of the token")
    exp: Optional[int] = Field(default=None, description="Token expiration timestamp")
    iat: Optional[int] = Field(default=None, description="Token issued at timestamp")
    sub: Optional[str] = Field(default=None, description="Subject of the token")
    aud: Optional[str] = Field(default=None, description="Intended audience of the token")


class OAuthUserInfoResponse(OAuthSuccessResponse):
    """OpenID Connect UserInfo endpoint response (OpenID Connect Core 1.0 Section 5.3)."""

    sub: str = Field(description="Subject identifier - unique user identifier")
    email: Optional[str] = Field(default=None, description="User's email address")
    name: Optional[str] = Field(default=None, description="User's full name")
    given_name: Optional[str] = Field(default=None, description="User's first/given name")
    family_name: Optional[str] = Field(default=None, description="User's last/family name")
    preferred_username: Optional[str] = Field(default=None, description="User's preferred username")
    updated_at: Optional[int] = Field(default=None, description="Time the user's information was last updated (Unix timestamp)")
    # Add other standard claims as needed:
    # picture: Optional[str] = Field(default=None, description="URL of user's profile picture")
    # website: Optional[str] = Field(default=None, description="URL of user's website")
    # locale: Optional[str] = Field(default=None, description="User's locale")


class OAuthJWKSResponse(OAuthSuccessResponse):
    """JSON Web Key Set endpoint response (RFC 7517)."""

    keys: List[Dict[str, Any]] = Field(description="Array of JSON Web Key objects")


class OAuthLogoutResponse(OAuthResponse):
    """OpenID Connect RP-Initiated Logout response."""

    message: str = Field(description="Logout confirmation message")
    user: Optional[str] = Field(default=None, description="User that was logged out")


class OAuthCredentialResponse(OAuthSuccessResponse):
    """Response for credential encryption key endpoint."""

    cred_enc_key: str = Field(description="Base64-encoded encryption key")
