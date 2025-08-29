from typing import Dict, List, Optional, Union, Any
from pydantic import BaseModel, Field, field_validator
import json
import base64
from enum import Enum

from core_db.response import Response, ErrorResponse, RedirectResponse


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

    This class ensures that Lambda function responses conform exactly to the
    AWS API Gateway proxy integration response format. It provides validation,
    helper methods, and automatic formatting to prevent integration failures.

    AWS API Gateway requires responses in this exact format:

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

    Example:
        .. code-block:: python

            # JSON Response
            response = ProxyResponse.json(
                data={"users": [{"id": 1, "name": "John"}]},
                status_code=200,
                headers={"X-Total-Count": "1"}
            )

            # Redirect Response
            response = ProxyResponse.redirect(
                location="/auth/login",
                status_code=302,
                cookies=["session=abc123; HttpOnly"]
            )

            # Error Response
            response = ProxyResponse.error(
                error="invalid_request",
                description="Missing required parameter",
                status_code=400
            )

            # Convert to AWS API Gateway format
            aws_response = response.to_dict()
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
        self.headers[name] = str(value)
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

    def set_json_body(self, data: Any) -> "ProxyResponse":
        """Set the response body to JSON and update Content-Type header.

        Args:
            data (Any): Data to serialize as JSON

        Returns:
            ProxyResponse: Self for method chaining

        Example:
            .. code-block:: python

                response = ProxyResponse(statusCode=200)
                response.set_json_body({"success": True, "data": [1, 2, 3]})
        """
        self.body = json.dumps(data, default=str)
        self.add_header("Content-Type", "application/json")
        return self

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
                response.add_header("Content-Disposition", "attachment; filename=report.pdf")
        """
        self.body = base64.b64encode(content).decode("utf-8")
        self.isBase64Encoded = True
        self.add_header("Content-Type", content_type)
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Convert to AWS API Gateway Lambda proxy integration response format.

        Returns:
            Dict[str, Any]: Response dictionary in exact format required by AWS API Gateway

        Example:
            .. code-block:: python

                response = ProxyResponse.json({"message": "Hello"})
                aws_response = response.to_dict()
                # Returns: {
                #     "statusCode": 200,
                #     "headers": {"Content-Type": "application/json"},
                #     "multiValueHeaders": {},
                #     "body": '{"message": "Hello"}',
                #     "isBase64Encoded": false
                # }
        """
        return {
            "statusCode": self.statusCode,
            "headers": self.headers,
            "multiValueHeaders": self.multiValueHeaders,
            "body": self.body,
            "isBase64Encoded": self.isBase64Encoded,
        }

    @classmethod
    def json(
        cls,
        data: Any,
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[List[str]] = None,
    ) -> "ProxyResponse":
        """Create a JSON response.

        Args:
            data (Any): Data to serialize as JSON
            status_code (int): HTTP status code (default: 200)
            headers (Optional[Dict[str, str]]): Additional headers
            cookies (Optional[List[str]]): Set-Cookie header values

        Returns:
            ProxyResponse: Configured JSON response

        Example:
            .. code-block:: python

                response = ProxyResponse.json(
                    data={"portfolios": [{"id": 1, "name": "Portfolio 1"}]},
                    status_code=200,
                    headers={"X-Total-Count": "1"},
                    cookies=["session=abc123; HttpOnly"]
                )
        """
        response = cls(statusCode=status_code)
        response.set_json_body(data)

        if headers:
            for name, value in headers.items():
                response.add_header(name, value)

        if cookies:
            for cookie in cookies:
                response.add_cookie(cookie)

        return response

    @classmethod
    def redirect(
        cls,
        location: str,
        status_code: int = 302,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[List[str]] = None,
    ) -> "ProxyResponse":
        """Create a redirect response.

        Args:
            location (str): Redirect URL
            status_code (int): HTTP status code (default: 302)
            headers (Optional[Dict[str, str]]): Additional headers
            cookies (Optional[List[str]]): Set-Cookie header values

        Returns:
            ProxyResponse: Configured redirect response

        Example:
            .. code-block:: python

                response = ProxyResponse.redirect(
                    location="/auth/v1/authorize?client_id=app&state=xyz",
                    status_code=302,
                    cookies=["oauth_state=abc123; Max-Age=600; HttpOnly"]
                )
        """
        response = cls(statusCode=status_code, body="")
        response.add_header("Location", location)

        if headers:
            for name, value in headers.items():
                response.add_header(name, value)

        if cookies:
            for cookie in cookies:
                response.add_cookie(cookie)

        return response

    @classmethod
    def error(
        cls,
        error: str,
        description: str = "",
        status_code: int = 400,
        headers: Optional[Dict[str, str]] = None,
    ) -> "ProxyResponse":
        """Create an OAuth-compatible error response.

        Args:
            error (str): Error code (e.g., "invalid_request", "invalid_client")
            description (str): Human-readable error description
            status_code (int): HTTP status code (default: 400)
            headers (Optional[Dict[str, str]]): Additional headers

        Returns:
            ProxyResponse: Configured error response

        Example:
            .. code-block:: python

                response = ProxyResponse.error(
                    error="invalid_request",
                    description="Missing required parameter: client_id",
                    status_code=400
                )
        """
        error_data = {"error": error}
        if description:
            error_data["error_description"] = description

        response = cls(statusCode=status_code)
        response.set_json_body(error_data)

        if headers:
            for name, value in headers.items():
                response.add_header(name, value)

        return response

    @classmethod
    def from_response(
        cls,
        response: Union[Response, ErrorResponse],
        correlation_id: Optional[str] = None,
    ) -> "ProxyResponse":
        """Convert core_db Response/ErrorResponse to ProxyResponse.

        Args:
            response (Union[Response, ErrorResponse]): Core database response object
            correlation_id (Optional[str]): Request correlation ID for tracking

        Returns:
            ProxyResponse: AWS API Gateway compatible response

        Example:
            .. code-block:: python

                # From successful Response
                db_response = Response(data={"users": []}, code=200)
                proxy_response = ProxyResponse.from_response(db_response)

                # From ErrorResponse
                error_response = ErrorResponse(message="Not found", code=404)
                proxy_response = ProxyResponse.from_response(error_response)
        """
        if isinstance(response, ErrorResponse):
            error_data = {"error": "api_error", "error_description": response.message}
            if correlation_id:
                error_data["correlation_id"] = correlation_id

            return cls.json(
                data=error_data,
                status_code=response.code,
                headers={"X-Correlation-ID": correlation_id} if correlation_id else {},
            )
        else:
            response_data = response.data if hasattr(response, "data") else {}
            if correlation_id:
                response_data["correlation_id"] = correlation_id

            return cls.json(
                data=response_data,
                status_code=response.code,
                headers={"X-Correlation-ID": correlation_id} if correlation_id else {},
            )


def get_proxy_response(response: Response) -> ProxyResponse:
    """Convert generic Response to AWS API Gateway ProxyResponse.

    Handles all HTTP status codes and response types including redirects,
    JSON responses, and cookie management for OAuth flows. Properly extracts
    cookies set via the Response.set_cookie() method.

    Args:
        response (Response): Generic response object from OAuth endpoint

    Returns:
        ProxyResponse: AWS API Gateway compatible response

    Examples:
        >>> # OAuth redirect with cookies
        >>> response = SuccessResponse(data="/auth/github/login")
        >>> response.code = 302
        >>> response.set_cookie("oauth_state", "abc123", max_age=600, httponly=True)
        >>> proxy_response = get_proxy_response(response)
        >>> print(proxy_response.statusCode)  # 302

        >>> # JSON response with session cookie
        >>> response = SuccessResponse(data={"access_token": "xyz789"})
        >>> response.set_cookie("session", "abc123", httponly=True, secure=True)
        >>> proxy_response = get_proxy_response(response)
        >>> print(proxy_response.statusCode)  # 200
    """
    # Handle redirect responses (3xx status codes)
    if 300 <= response.code < 400:
        # Determine redirect location from multiple possible sources
        location = None

        # 1. Check for RedirectResponse
        if isinstance(response, RedirectResponse):
            location = response.url
        # 2. Check metadata for locaiotn field
        elif isinstance(response.metadata, dict) and "location" in response.metadata:
            location = response.metadata["location"]
        # 3. Check data for location field
        elif isinstance(response.data, dict) and "location" in response.data:
            location = response.data["location"]
        # 4. Check if data is a URL string
        elif isinstance(response.data, str) and (
            response.data.startswith(("http://", "https://", "/")) or "?" in response.data  # Query string indicates URL
        ):
            location = response.data

        if not location:
            # No valid location found, treat as JSON
            return ProxyResponse.json(
                data=response.model_dump(),
                status_code=response.code,
                cookies=response.cookies,
            )

        return ProxyResponse.redirect(
            location=location,
            status_code=response.code,
            cookies=response.cookies,  # Use cookies directly from Response
        )

    # Handle all other responses (1xx, 2xx, 4xx, 5xx) as JSON
    return ProxyResponse.json(
        data=response.data,
        status_code=response.code,
        cookies=response.cookies,  # Use cookies directly from Response
    )


def get_proxy_error_response(error: ErrorResponse) -> ProxyResponse:
    """Convert ErrorResponse to AWS API Gateway ProxyResponse.

    Creates OAuth-compatible error responses with proper error codes and
    descriptions. Preserves any cookies that may have been set before
    the error occurred.

    Args:
        error (ErrorResponse): Error response object with exception details

    Returns:
        ProxyResponse: AWS API Gateway compatible error response

    Examples:
        >>> # OAuth error response
        >>> error = ErrorResponse(
        ...     status="error",
        ...     code=400,
        ...     message="Invalid client_id"
        ... )
        >>> proxy_response = get_proxy_error_response(error)
        >>> print(proxy_response.statusCode)  # 400

        >>> # Error with cookies (e.g., clearing invalid session)
        >>> error = ErrorResponse(status="error", code=401, message="Unauthorized")
        >>> error.set_cookie("session", "", max_age=0)  # Clear session
        >>> proxy_response = get_proxy_error_response(error)
    """
    # Build OAuth-compatible error data structure
    error_data = {"error": "api_error", "error_description": None}  # Generic error type

    # Extract error message from various possible locations
    if isinstance(error.data, dict) and "message" in error.data:
        error_data["error_description"] = error.data["message"]
    elif isinstance(error.data, str):
        error_data["error_description"] = error.data
    elif hasattr(error, "message") and error.message:
        error_data["error_description"] = error.message
    else:
        error_data["error_description"] = "An error occurred"

    # Add detailed error information if available
    if error.errors and len(error.errors) > 0:
        error_data["details"] = [
            {
                "type": err.type if hasattr(err, "type") else "unknown",
                "message": err.message if hasattr(err, "message") else str(err),
            }
            for err in error.errors
        ]

    # For OAuth-specific errors, use more specific error codes
    if error.code == 400:
        error_data["error"] = "invalid_request"
    elif error.code == 401:
        error_data["error"] = "invalid_client"
    elif error.code == 403:
        error_data["error"] = "access_denied"
    elif error.code == 404:
        error_data["error"] = "not_found"

    return ProxyResponse.json(
        data=error_data,
        status_code=error.code,
        cookies=error.cookies,  # Use cookies directly from ErrorResponse
    )


# Export both existing and new classes
__all__ = ["Response", "ErrorResponse", "ProxyResponse", "HttpStatus"]
