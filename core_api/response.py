import os
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic import computed_field
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
                proxy.body = response.model_dump_json(by_alias=False)
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
        # If the exclude set() exists, add code to it
        exclude = kwargs.get("exclude", set())

        # Convert to set if needed and add 'code'
        if isinstance(exclude, str):
            exclude = {exclude}
        elif not isinstance(exclude, set):
            exclude = set(exclude) if exclude else set()

        kwargs["exclude"] = exclude | {"code", "status", "message"}

        return super().model_dump(**kwargs)


class OAuthSuccessResponse(OAuthResponse):

    @model_validator(mode="before")
    def validate_success(cls, values):
        # Custom validation logic for success responses
        values["status"] = "ok"
        values["code"] = 200
        return values


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


class OAuthTokenResponse(OAuthSuccessResponse):
    """OAuth token endpoint response (RFC 6749 Section 5.1)."""

    access_token: str = Field(description="The access token issued by the authorization server")
    token_type: str = Field(default="Bearer", description="The type of token issued")
    expires_in: Optional[int] = Field(default=None, description="Token lifetime in seconds")
    scope: Optional[str] = Field(default=None, description="The scope of the access token")
    refresh_token: Optional[str] = Field(default=None, description="The refresh token for obtaining new access tokens")


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
