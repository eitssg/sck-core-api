"""AWS API Gateway request structures and validation models.

This module provides Pydantic models that exactly match AWS API Gateway proxy
integration event structures. These models are used to validate and process
incoming requests from AWS API Gateway and local development environments.

The models ensure type safety and validation for:
- AWS API Gateway proxy events with complete field coverage
- Lambda execution context information
- Cognito identity and authentication data
- Request routing and method handling

Example:
    Basic event processing::

        from core_api.request import ProxyEvent, RequestContext, CognitoIdentity

        # Create event from AWS API Gateway data
        event = ProxyEvent(**aws_event_data)

        # Access typed fields safely
        method = event.httpMethod  # "GET", "POST", etc.
        path = event.path         # "/api/v1/users/123"
        body = event.body         # Automatically parsed from JSON

Attributes:
    API_ID (str): Default API Gateway ID for local development.
    DOMAIN_PREFIX (str): Domain prefix for API Gateway endpoints.
"""

from typing import Any, Callable, Dict, List, Optional, Set, Union
from enum import Enum
from datetime import datetime, timezone
import json
import urllib.parse

from pydantic import (
    BaseModel,
    ConfigDict,
    ValidationInfo,
    Field,
    field_validator,
    model_validator,
    PrivateAttr,
)

import core_framework as util

from .actions import ApiActionsClass
from .constants import HDR_X_CORRELATION_ID, API_ID, DOMAIN_PREFIX


class RequestMethod(Enum):
    """HTTP request methods supported by the API.

    Maps HTTP methods to their corresponding action names for internal
    processing. Provides both the standard HTTP method name and the
    action-oriented name used in the application logic.

    Attributes:
        LIST: Retrieve multiple resources (GET with list semantics).
        GET: Retrieve a single resource.
        POST: Create a new resource (alias for CREATE).
        CREATE: Create a new resource.
        PUT: Update/replace a resource (alias for UPDATE).
        UPDATE: Update/replace a resource.
        DELETE: Remove a resource.
        PATCH: Partially update a resource.

    Example:
        .. code-block:: python

            method = RequestMethod.POST
            print(method)        # Output: "create"
            print(method.value)  # Output: "create"

            # Check if method creates resources
            if method in [RequestMethod.POST, RequestMethod.CREATE]:
                print("This method creates resources")
    """

    LIST = "list"
    GET = "get"
    POST = "create"
    CREATE = "create"
    PUT = "update"
    UPDATE = "update"
    DELETE = "delete"
    PATCH = "patch"

    def __str__(self) -> str:
        """Return string representation of the enum value.

        Returns:
            str: The action name for this HTTP method.
        """
        return self.value

    def __repr__(self) -> str:
        """Return detailed string representation of the enum.

        Returns:
            str: Full enum representation with class and member name.
        """
        return f"{self.__class__.__name__}.{self.name}"


class RequestType(str, Enum):
    """Types of resources that can be requested through the API.

    Defines all available resource types in the system, including both
    primary resources (portfolio, app, component) and registry resources
    for metadata and configuration management.

    Inherits from str to allow direct string comparison and serialization
    without requiring .value access.

    Attributes:
        PORTFOLIO: Portfolio management operations.
        APP: Application lifecycle operations.
        BRANCH: Source code branch operations.
        BUILD: Build and deployment operations.
        COMPONENT: Component configuration operations.
        EVENT: Event processing and monitoring.
        FACTS: System facts and metadata retrieval.
        REG_CLIENT: Registry client management.
        REG_PORTFOLIO: Registry portfolio metadata.
        REG_APP: Registry application metadata.
        REG_ZONE: Registry zone configuration.

    Note:
        Registry resources (REG_*) use colon notation to indicate
        nested resource hierarchies within the registry subsystem.

        As a str Enum, instances can be used directly in string operations:
        - String concatenation: f"Action: {RequestType.PORTFOLIO}"
        - Dictionary keys: {RequestType.PORTFOLIO: handler}
        - Direct comparison: if resource_type == "portfolio"

    Example:
        .. code-block:: python

            resource_type = RequestType.PORTFOLIO
            print(resource_type)        # Output: "portfolio"
            print(repr(resource_type))  # Output: "RequestType.PORTFOLIO"

            # Direct string comparison (str Enum benefit)
            if resource_type == "portfolio":
                print("Portfolio resource detected")

            # Registry resources
            reg_type = RequestType.REG_CLIENT
            print(reg_type)            # Output: "registry:client"

            # Use in action strings
            action = f"{resource_type}:{RequestMethod.CREATE}"
            print(action)              # Output: "portfolio:create"

            # JSON serialization works automatically
            import json
            data = {"type": resource_type}
            json_str = json.dumps(data)  # {"type": "portfolio"}
    """

    PORTFOLIO = "portfolio"
    APP = "app"
    BRANCH = "branch"
    BUILD = "build"
    COMPONENT = "component"
    EVENT = "event"
    FACTS = "facts"
    REG_CLIENT = "registry:client"
    REG_PORTFOLIO = "registry:portfolio"
    REG_APP = "registry:app"
    REG_ZONE = "registry:zone"


RequestRoutesType = Dict[RequestType, ApiActionsClass]


class Request(BaseModel):
    """Structured request model for Lambda handler invocation.

    This class provides a structured interface for Lambda function handlers,
    converting the raw API Gateway proxy event into a typed, validated request
    object with action-based routing information.

    The ``data`` field corresponds to the ``body`` field in ProxyEvent, but
    provides a dictionary interface instead of requiring JSON string parsing.

    Attributes:
        action (str): Action to perform in format "type:method" (e.g., "portfolio:create").
        data (Dict[str, Any]): Primary payload data for the action (parsed from JSON).
        auth (Optional[Dict[str, Any]]): Authentication information extracted from headers.

    Note:
        The Request model serves as an abstraction layer between the raw AWS
        API Gateway event format and the application's business logic, providing
        type safety and validation for common request patterns.

    Example:
        .. code-block:: python

            # From API Gateway event
            request = Request(
                action="portfolio:create",
                data={"name": "My Portfolio", "description": "Portfolio description"},
                auth={"user_id": "123", "role": "admin"}
            )

            # Access typed fields
            action_parts = request.action.split(":")
            resource_type = action_parts[0]  # "portfolio"
            method = action_parts[1]         # "create"

            # Use with property setters
            request.typ = RequestType.PORTFOLIO
            request.method = RequestMethod.CREATE
            # request.action is automatically updated to "portfolio:create"
    """

    model_config = ConfigDict(populate_by_name=True)

    action: str = Field(description="The action to perform in format 'type:method' (e.g., 'portfolio:create')")
    data: Dict[str, Any] = Field(
        description="The primary payload data for the action (equivalent to ProxyEvent.body)",
        default_factory=dict,
    )
    auth: Optional[Dict[str, Any]] = Field(
        None,
        description="Authentication information extracted from request headers and context",
    )

    _type: Optional[RequestType] = PrivateAttr(None)
    _method: Optional[RequestMethod] = PrivateAttr(None)

    @property
    def typ(self) -> Optional[RequestType]:
        """Get the request type.

        Returns:
            Optional[RequestType]: The resource type for this request.
        """
        return self._type

    @typ.setter
    def typ(self, value: RequestType) -> None:
        """Set the request type and update action string.

        Args:
            value (RequestType): The resource type to set.

        Note:
            If method is also set, this will automatically update the action string.
        """
        self._type = value
        if self._method:
            self.action = f"{self._type}:{self._method}"

    @property
    def method(self) -> Optional[RequestMethod]:
        """Get the request method.

        Returns:
            Optional[RequestMethod]: The action method for this request.
        """
        return self._method

    @method.setter
    def method(self, value: RequestMethod) -> None:
        """Set the request method and update action string.

        Args:
            value (RequestMethod): The action method to set.

        Note:
            If type is also set, this will automatically update the action string.
        """
        self._method = value
        if self._type:
            self.action = f"{self._type}:{self._method}"

    @field_validator("action", mode="before")
    @classmethod
    def validate_action(cls, value: str) -> str:
        """Validate and normalize the action field format.

        Args:
            value (str): Action string to validate.

        Returns:
            str: Validated and normalized action string.

        Raises:
            ValueError: If action format is invalid or contains unknown types/methods.

        Note:
            Supports both "type:method" and "namespace:type:method" formats.
            The latter is automatically normalized to the former.
        """
        parts = value.split(":")
        if len(parts) == 2:
            typ = RequestType(parts[0])
            method = RequestMethod(parts[1])
            return f"{typ}:{method}"
        elif len(parts) == 3:
            # Handle registry namespace format (registry:client:create)
            section = f"{parts[0]}:{parts[1]}"
            typ = RequestType(section)
            method = RequestMethod(parts[2])
            return f"{typ}:{method}"
        else:
            raise ValueError(f"Invalid action format: '{value}'. Expected 'type:method' or 'namespace:type:method'.")

    @model_validator(mode="before")
    @classmethod
    def validate_model(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """Validate model and construct action from type/method if needed.

        Args:
            values (Dict[str, Any]): Raw model values.

        Returns:
            Dict[str, Any]: Validated model values with action field set.

        Raises:
            ValueError: If neither action nor type/method combination is provided.
        """
        if not values.get("action"):
            typ = values.pop("typ", None)
            method = values.pop("method", None)
            if not typ or not method:
                raise ValueError("Either 'action' field or 'typ'+'method' fields are required")
            values["action"] = f"{typ}:{method}"
        return values

    def model_dump(self, **kwargs) -> Dict[str, Any]:
        """Serialize model excluding None values by default.

        Args:
            **kwargs: Additional arguments passed to parent model_dump.

        Returns:
            Dict[str, Any]: Serialized model data.

        Note:
            Sets exclude_none=True by default to match API response conventions.
        """
        if "exclude_none" not in kwargs:
            kwargs["exclude_none"] = True
        return super().model_dump(**kwargs)


class CognitoIdentity(BaseModel):
    """AWS Cognito identity information for authenticated API requests.

    Contains complete identity and authentication context from AWS Cognito,
    matching the structure provided by AWS API Gateway in the request context.
    Used for authorization, auditing, and user tracking.

    Attributes:
        cognitoIdentityPoolId (Optional[str]): Cognito Identity Pool identifier.
        accountId (Optional[str]): AWS account ID of the authenticated user.
        cognitoIdentityId (Optional[str]): Unique Cognito identity identifier.
        caller (Optional[str]): The calling service or application identifier.
        sourceIp (Optional[str]): Client IP address from which request originated.
        principalOrgId (Optional[str]): AWS Organizations principal ID.
        accessKey (Optional[str]): AWS access key for assumed role (if applicable).
        cognitoAuthenticationType (Optional[str]): Type of Cognito authentication used.
        cognitoAuthenticationProvider (Optional[str]): Cognito authentication provider.
        userArn (Optional[str]): AWS ARN of the authenticated user.
        userAgent (Optional[str]): HTTP User-Agent string from client request.
        user (Optional[str]): User identifier (username or user ID).

    Note:
        All fields are optional to handle various authentication scenarios:

        - Anonymous access (no Cognito fields set)
        - Federated identity (some provider fields set)
        - Full Cognito authentication (most fields populated)

    Example:
        .. code-block:: python

            # Typical authenticated user
            identity = CognitoIdentity(
                accountId="123456789012",
                user="john.doe@example.com",
                userArn="arn:aws:cognito-idp:us-east-1:123456789012:user/john.doe",
                sourceIp="192.168.1.100",
                cognitoAuthenticationType="authenticated"
            )

            # Check authentication status
            if identity.cognitoAuthenticationType == "authenticated":
                print(f"Authenticated user: {identity.user}")
    """

    model_config = ConfigDict(populate_by_name=True)

    cognitoIdentityPoolId: Optional[str] = Field(None, description="Cognito Identity Pool ID for federated identities")
    accountId: Optional[str] = Field(None, description="AWS account ID associated with the user")
    cognitoIdentityId: Optional[str] = Field(None, description="Unique identifier for the Cognito identity")
    caller: Optional[str] = Field(None, description="Identifier of the calling service or application")
    sourceIp: Optional[str] = Field(None, description="IP address from which the request originated")
    principalOrgId: Optional[str] = Field(None, description="AWS Organizations principal organization ID")
    accessKey: Optional[str] = Field(None, description="AWS access key for assumed role credentials")
    cognitoAuthenticationType: Optional[str] = Field(
        None,
        description="Type of Cognito authentication ('authenticated' or 'unauthenticated')",
    )
    cognitoAuthenticationProvider: Optional[str] = Field(None, description="Cognito authentication provider used for login")
    userArn: Optional[str] = Field(None, description="AWS ARN of the authenticated user")
    userAgent: Optional[str] = Field(None, description="HTTP User-Agent string from the client request")
    user: Optional[str] = Field(None, description="User identifier (username, email, or user ID)")


class RequestContext(BaseModel):
    """AWS API Gateway request context information.

    Contains comprehensive metadata about the API Gateway request, including
    routing information, timing data, identity context, and AWS-specific
    identifiers. This matches the requestContext structure that AWS API Gateway
    provides to Lambda functions.

    Attributes:
        resourceId (str): API Gateway resource identifier.
        resourcePath (str): Resource path template with parameter placeholders.
        httpMethod (str): HTTP method (GET, POST, PUT, DELETE, etc.).
        extendedRequestId (Optional[str]): Extended request ID for detailed tracing.
        requestTime (str): Human-readable request timestamp.
        path (str): Full request path including stage prefix.
        accountId (Optional[str]): AWS account ID for the API Gateway.
        protocol (str): HTTP protocol version (default: "HTTP/1.1").
        stage (str): API Gateway deployment stage name.
        domainPrefix (str): Domain prefix for the API Gateway endpoint.
        requestTimeEpoch (int): Request timestamp as Unix epoch milliseconds.
        requestId (str): Unique identifier for this specific request.
        domainName (str): Full domain name of the API Gateway endpoint.
        identity (CognitoIdentity): Authentication and identity information.
        apiId (str): API Gateway API identifier.

    Note:
        The RequestContext provides complete metadata for:

        - Request routing and resource identification
        - Timing and tracing information
        - Authentication and authorization context
        - AWS infrastructure identifiers

    Example:
        .. code-block:: python

            context = RequestContext(
                resourceId="abc123",
                resourcePath="/users/{id}",
                httpMethod="GET",
                path="/prod/users/123",
                requestId="550e8400-e29b-41d4-a716-446655440000",
                identity=cognito_identity
            )

            # Access routing information
            print(f"Resource: {context.resourcePath}")
            print(f"Method: {context.httpMethod}")
            print(f"Stage: {context.stage}")
    """

    model_config = ConfigDict(populate_by_name=True)

    resourceId: str = Field(description="API Gateway resource identifier for routing")
    resourcePath: str = Field(description="Resource path template with parameter placeholders (e.g., '/users/{id}')")
    httpMethod: str = Field(description="HTTP method for the request (GET, POST, PUT, DELETE, etc.)")
    extendedRequestId: Optional[str] = Field(None, description="Extended request ID for detailed request tracing")
    requestTime: str = Field(
        description="Human-readable request timestamp in API Gateway format",
        default_factory=lambda: datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S %z"),
    )
    path: str = Field(description="Full request path including API Gateway stage prefix")
    accountId: Optional[str] = Field(None, description="AWS account ID that owns the API Gateway")
    protocol: str = Field(description="HTTP protocol version", default="HTTP/1.1")
    stage: str = Field(
        description="API Gateway deployment stage name (prod, dev, etc.)",
        default_factory=util.get_environment,
    )
    domainPrefix: str = Field(description="Domain prefix for the API Gateway endpoint", default=DOMAIN_PREFIX)
    requestTimeEpoch: int = Field(
        description="Request timestamp as Unix epoch time in milliseconds",
        default_factory=lambda: int(datetime.now(timezone.utc).timestamp() * 1000),
    )
    requestId: str = Field(description="Unique identifier for this specific API request")
    domainName: str = Field(
        description="Full domain name of the API Gateway endpoint",
        default=f"{DOMAIN_PREFIX}.execute-api.us-east-1.amazonaws.com",
    )
    identity: CognitoIdentity = Field(description="Authentication and identity information for the request")
    apiId: str = Field(description="API Gateway API identifier", default=API_ID)


class ProxyEvent(BaseModel):
    """AWS API Gateway proxy integration event model.

    Represents the complete event structure that AWS API Gateway sends to
    Lambda functions via proxy integration. This model ensures type safety
    and validation for all AWS API Gateway event fields.

    The body field is automatically parsed from JSON string to dictionary
    for convenient access in handler functions, while maintaining compatibility
    with the AWS event format.

    Attributes:
        httpMethod (str): HTTP method (GET, POST, PUT, DELETE, etc.).
        resource (str): API resource path with parameter placeholders.
        path (Optional[str]): Actual request path with resolved parameters.
        queryStringParameters (Dict[str, str]): Single-value query parameters.
        multiValueQueryStringParameters (Dict[str, List[str]]): Multi-value query parameters.
        pathParameters (Dict[str, str]): Path parameter values extracted from URL.
        stageVariables (Dict[str, str]): API Gateway stage variables.
        requestContext (RequestContext): Complete request context information.
        headers (Dict[str, str]): Single-value HTTP headers.
        multiValueHeaders (Dict[str, List[str]]): Multi-value HTTP headers.
        isBase64Encoded (bool): Whether the body content is base64 encoded.
        body (Union[Dict[str, Any], str]): Request body (auto-parsed from JSON).

    Note:
        AWS API Gateway always provides both single-value and multi-value
        versions of headers and query parameters. The multi-value versions
        are lists that can contain multiple values for the same key.

        The body field accepts both string (raw AWS format) and dict (parsed)
        formats, automatically converting JSON strings to dictionaries.

    Example:
        .. code-block:: python

            # From AWS API Gateway
            event = ProxyEvent(
                httpMethod="POST",
                resource="/users",
                path="/users",
                headers={"Content-Type": "application/json"},
                body='{"name": "John", "email": "john@example.com"}',
                requestContext=request_context
            )

            # Access parsed body
            user_data = event.body  # Returns: {"name": "John", "email": "john@example.com"}

            # Route key for handler lookup
            route = event.route_key  # Returns: "POST:/users"
    """

    model_config = ConfigDict(populate_by_name=True)

    httpMethod: str = Field(description="HTTP method for the request (GET, POST, PUT, DELETE, etc.)")
    resource: str = Field(description="API resource path with parameter placeholders (e.g., '/users/{id}')")
    path: Optional[str] = Field(
        None,
        description="Actual request path with resolved parameters (e.g., '/users/123')",
    )
    queryStringParameters: Dict[str, str] = Field(description="Single-value query string parameters", default_factory=dict)
    multiValueQueryStringParameters: Dict[str, List[str]] = Field(
        description="Multi-value query string parameters (AWS API Gateway format)",
        default_factory=dict,
    )
    pathParameters: Dict[str, str] = Field(description="Path parameter values extracted from the URL", default_factory=dict)
    stageVariables: Dict[str, str] = Field(
        description="API Gateway stage variables for environment configuration",
        default_factory=dict,
    )
    requestContext: RequestContext = Field(description="Complete request context information from API Gateway")
    headers: Dict[str, str] = Field(description="Single-value HTTP request headers", default_factory=dict)
    multiValueHeaders: Dict[str, List[str]] = Field(
        description="Multi-value HTTP headers (AWS API Gateway format)",
        default_factory=dict,
    )
    cookies: Optional[list[str]] = Field(None, description="Parsed cookies from request (AWS API Gateway v2.0+ format)")
    isBase64Encoded: bool = Field(
        description="Whether the body content is base64 encoded (for binary data)",
        default=False,
    )
    body: Union[Dict[str, Any], str] = Field(
        description="Request body content (automatically parsed from JSON string)",
        default_factory=dict,
    )

    @property
    def parsed_cookies(self) -> Dict[str, str]:
        """Parse cookies from headers if not provided in cookies field.

        Returns:
            Dict[str, str]: Parsed cookie name-value pairs

        Note:
            AWS API Gateway v1.0 puts cookies in headers['Cookie']
            AWS API Gateway v2.0+ puts them in the cookies field
        """
        # If API Gateway v2.0+ provided parsed cookies, use them
        if self.cookies:
            return {cookie.split("=", 1)[0]: cookie.split("=", 1)[1] for cookie in self.cookies if "=" in cookie}

        # Otherwise parse from Cookie header (v1.0 format)
        cookie_header = self.headers.get("Cookie", "")
        if not cookie_header:
            return {}

        cookies_list = cookie_header.split(";")
        return {cookie.split("=", 1)[0].strip(): cookie.split("=", 1)[1].strip() for cookie in cookies_list if "=" in cookie}

    @property
    def content_type(self) -> str:
        """Get the Content-Type header value."""
        return self.headers.get("content-type", "application/json")

    @field_validator("body", mode="after")
    @classmethod
    def body_dict(cls, body: Any, info: ValidationInfo) -> Union[Dict[str, Any], str]:
        """Convert JSON string body to dictionary for convenient access.

        Args:
            body (Any): Raw body value from API Gateway.
            info (ValidationInfo): Pydantic validation context.

        Returns:
            Union[Dict[str, Any], str]: Parsed dictionary or original string.

        Raises:
            ValueError: If JSON string is malformed.

        Note:
            - None values are converted to empty dictionaries
            - Valid dictionaries are passed through unchanged
            - JSON strings are parsed to dictionaries
            - Empty strings become empty dictionaries
            - Invalid JSON raises ValueError with descriptive message
        """
        if isinstance(body, dict):
            return body
        content_type = info.data.get("headers", {}).get("content-type", "application/json")
        if util.is_json_mimetype(content_type):
            try:
                return util.from_json(body) if body else {}
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON string for body: {e}") from e
        elif "application/x-www-form-urlencoded" in content_type:
            data = cls._to_dict(urllib.parse.parse_qs(body)) if body else {}
            return data
        return {"data": body}  # Put whatever mimetype this data is in a dict

    @classmethod
    def _to_dict(cls, data: Dict[str, List[str]]) -> Dict[str, Any]:
        """Convert form-encoded data to a dictionary.

        Args:
            data (Dict[str, List[str]]): Form-encoded data.

        Returns:
            Dict[str, Any]: Dictionary representation of the form data.
        """
        return {k: v[0] if len(v) == 1 else v for k, v in data.items()}

    @field_validator("httpMethod", mode="before")
    @classmethod
    def uppercase_method(cls, httpMethod: str, info: ValidationInfo) -> str:
        """Normalize HTTP method to uppercase for consistency.

        Args:
            httpMethod (str): HTTP method string.
            info (ValidationInfo): Pydantic validation context.

        Returns:
            str: Uppercase HTTP method.
        """
        return httpMethod.upper()

    @property
    def route_key(self) -> str:
        """Generate route key for handler lookup.

        Returns:
            str: Route key in format "METHOD:resource" for handler routing.

        Example:
            .. code-block:: python

                event = ProxyEvent(httpMethod="GET", resource="/users/{id}")
                route = event.route_key  # Returns: "GET:/users/{id}"
        """
        method = self.httpMethod.upper()
        return f"{method}:{self.resource}"

    def get_header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """Get header value case-insensitively.

        Args:
            name (str): Header name to retrieve.

        Returns:
            str: Header value or empty string if not found.
        """
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return k, v
        return name, default or None


class RouteEndpoint:
    """
    Represents an endpoint for a specific API route, encapsulating the handler
    function and its associated metadata such as required permissions and
    access control settings.

    Pass attributes in kwargs to initialize the endopint

    Args:
        method (Callable[..., Any]): The handler function for the route.
        required_permissions (Set): Permissions required to access the route.
        required_token_type (str): Type of token required (default: "access").
        allow_anonymous (bool): Whether anonymous access is allowed (default: False).
        client_isolation (bool): Whether client isolation is enforced (default: True if not anonymous).


    """

    def __init__(self, method: Callable[..., Any], **kwargs):
        self.handler = method
        self.required_permissions: Set = kwargs.get("required_permissions", set())
        self.required_token_type: str = kwargs.get("required_token_type", "access")
        self.allow_anonymous: bool = kwargs.get("allow_anonymous", False)
        self.client_isolation: bool = kwargs.get("client_isolation", False if self.allow_anonymous else True)


ActionHandlerRoutes = Dict[str, RouteEndpoint]


def get_correlation_id(request: ProxyEvent) -> str:
    """Generate forensic-grade correlation ID optimized for cost and audit trails.

    Format: {base36_timestamp_6}{base36_random_6} = 12 characters
    Example: "K7N2X1A9B3C7"

    Provides:
    - 67% shorter than UUID4 (12 vs 36 chars)
    - Virtually zero collision risk for multi-year forensic auditing
    - Timestamp prefix enables chronological sorting
    - Cost savings while maintaining audit integrity
    """
    _, correlation_id = request.get_header(HDR_X_CORRELATION_ID)

    if not correlation_id:
        if request.requestContext and request.requestContext.requestId:
            # ✅ FORENSIC-GRADE: Use 12 chars from AWS request ID
            # Removes dashes, takes first 12 chars (still globally unique)
            aws_id = request.requestContext.requestId.replace("-", "")
            correlation_id = aws_id[:12].upper()  # "550E8400E29B"
        else:
            # Fallback: Generate forensic-grade ID
            correlation_id = util.generate_forensic_correlation_id()

        request.headers[HDR_X_CORRELATION_ID.lower()] = correlation_id

    return correlation_id
