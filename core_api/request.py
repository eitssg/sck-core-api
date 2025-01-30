"""Module for handling API request structures and validation in the core API."""

from typing import Any, Callable
from enum import Enum
from datetime import datetime, timezone

import json

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
    PrivateAttr,
)

import core_framework as util
from core_db.response import Response

from .actions import ApiActionsClass

API_ID = "coreApiv1"
DOMAIN_PREFIX = "core"  # e.g. core.execute-api.us-east-1.amazonaws.com


class RequestMethod(Enum):
    """HTTP request methods supported by the API."""

    LIST = "list"
    GET = "get"
    POST = "create"
    CREATE = "create"
    PUT = "update"
    UPDATE = "update"
    DELETE = "delete"
    PATCH = "patch"

    def __str__(self):
        """Return string representation of the enum value."""
        return self.value

    def __repr__(self):
        """Return detailed string representation of the enum."""
        return f"{self.__class__.__name__}.{self.name}"


class RequestType(Enum):
    """Types of resources that can be requested through the API."""

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

    def __str__(self):
        """Return string representation of the enum value."""
        return self.value

    def __repr__(self):
        """Return detailed string representation of the enum."""
        return f"{self.__class__.__name__}.{self.name}"


RequestRoutesType = dict[RequestType, ApiActionsClass]


class Request(BaseModel):
    """This class is used to provided structure to the Lambda Invoker Handler
    Do note that the "data" field is a dictionary that is equivalent to the "body" field
    in the ProxyEvent class.  This is the primary payload for the action.

    The difference is the ProxyEvent.body is expected to be a JSON string, while the
    Request.data is expected to be a dictionary.

    Args:
        BaseModel ([type]): [description]
        typ: RequestType | None = None: Type of request model
        action: RequestMethod | None = None: Action to perform of the model

    """

    model_config = ConfigDict(populate_by_name=True)

    action: str = Field(description="The action to perform such as 'portfolio:create'")
    data: dict[str, Any] = Field(
        description="The data to use in the action.  This is the primary payload",
        default={},
    )
    auth: dict[str, Any] | None = Field(
        None, description="The authentication information"
    )

    _type: RequestType | None = PrivateAttr(None)
    _method: RequestMethod | None = PrivateAttr(None)

    @property
    def typ(self) -> RequestType | None:
        return self._type

    @typ.setter
    def typ(self, value: RequestType) -> None:
        self._type = value
        if self._method:
            self.action = f"{self._type}:{self._method}"

    @property
    def method(self) -> RequestMethod | None:
        return self._method

    @method.setter
    def method(self, value: RequestMethod) -> None:
        self._method = value
        if self._type:
            self.action = f"{self._type}:{self._method}"

    @classmethod
    @field_validator("action", mode="before")
    def validate_action(cls, value: str) -> str:
        """Pre validate the 'action' fields to help with field defaults"""
        parts = value.split(":")
        if len(parts) == 2:
            typ = RequestType(parts[0])
            method = RequestMethod(parts[1])
            return f"{typ}:{method}"
        if len(parts) == 3:
            section = f"{parts[0]}:{parts[1]}"
            typ = RequestType(section)
            method = RequestMethod(parts[2])
            return f"{typ}:{method}"
        raise ValueError("Invalid action format. Expected 'type:method'.")

    @classmethod
    @model_validator(mode="before")
    def validate_model(cls, values):
        """Pre validate the model to help with defaults"""
        if not values.get("action"):
            typ = values.pop("typ", None)
            method = values.pop("method", None)
            if not typ or not method:
                raise ValueError("The action field or typ:method fields is required")
            values["action"] = f"{typ}:{method}"
        return values

    # Override the model_dump method to exclude None values
    def model_dump(self, **kwargs) -> dict:
        if "exclude_none" not in kwargs:
            kwargs["exclude_none"] = True
        return super().model_dump(**kwargs)


class CognitoIdentity(BaseModel):
    """AWS Cognito identity information for API requests."""

    model_config = ConfigDict(populate_by_name=True)

    cognitoIdentityPoolId: str | None = None
    accountId: str | None = None
    cognitoIdentityId: str | None = None
    caller: str | None = None
    sourceIp: str | None = None
    principalOrgId: str | None = None
    accessKey: str | None = None
    cognitoAuthenticationType: str | None = None
    cognitoAuthenticationProvider: str | None = None
    userArn: str | None = None
    userAgent: str | None = None
    user: str | None = None


class RequestContext(BaseModel):
    """API Gateway request context information."""

    model_config = ConfigDict(populate_by_name=True)

    resourceId: str
    resourcePath: str
    httpMethod: str
    extendedRequestId: str | None = None
    requestTime: str = Field(
        description="The request time",
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    path: str
    accountId: str | None = None
    protocol: str = Field(description="The protocol", default="HTTP/1.1")
    stage: str = Field(description="The stage", default_factory=util.get_environment)
    domainPrefix: str = Field(description="The domain prefix", default=DOMAIN_PREFIX)
    requestTimeEpoch: int = Field(
        description="The request time epoch",
        default_factory=lambda: int(datetime.now(timezone.utc).timestamp()),
    )
    requestId: str
    domainName: str = Field(
        description="The domain name",
        default=f"{DOMAIN_PREFIX}.execute-api.us-east-1.amazonaws.com",
    )
    identity: CognitoIdentity
    apiId: str = Field(description="The API ID", default=API_ID)


class ProxyEvent(BaseModel):
    """
    This is the request that comes INTO the lambda function from the API Gateway

    It is expected that any "body" object is a JSON document to be processed by the
    respective command.  So, we don't do much to validate it.  We simply change it
    to a python dictionary.
    """

    model_config = ConfigDict(populate_by_name=True)

    httpMethod: str = Field(
        ..., description="The HTTP Method such as GET, POST, PUT, DELETE"
    )
    resource: str = Field(
        ..., description="The resource path such as /api/v1/client/{client}"
    )
    path: str | None = Field(
        None, description="The user supplied path such as /api/v1/client/my_name"
    )
    queryStringParameters: dict = Field(
        description="The query string parameters dictonary", default={}
    )
    pathParameters: dict = Field(
        description="The path parameters dictionary", default={}
    )
    requestContext: RequestContext = Field(
        ..., description="The request context suuplied by API interface"
    )
    headers: dict = Field(
        description="this should be content-type: applcation/json", default={}
    )
    isBase64Encoded: bool = Field(
        description="This should be false as the body is JSON", default=False
    )
    body: dict[str, Any] | str = Field(
        description="RESTful API Request (a.k.a DynamoDB Object)",
        default={},
    )

    @field_validator("body", mode="before")
    @classmethod
    def body_dict(cls, body: Any, info: ValidationInfo) -> Any:
        """Convert the body to a dictionary if it is a string
        Note that the Proxy will ALWAYS send a string, even if it is empty
        since we are managing only dictionary, we will convert empty string
        to None.  Otherwise, we will convert the string to a dictionary.
        """
        if body is None:
            return {}
        if isinstance(body, dict):
            return body
        if isinstance(body, str):
            try:
                if len(body) == 0:
                    return {}
                return util.from_json(body)
            except json.JSONDecodeError as e:
                raise ValueError("Invalid JSON string for body") from e
        raise ValueError("Invalid body type")

    @field_validator("httpMethod", mode="before")
    @classmethod
    def uppercase_method(cls, httpMethod: str, info: ValidationInfo) -> str:
        """
        If for some reason the httpMethod is not in uppercase, we will convert it to uppercase.
        """
        return httpMethod.upper()

    @property
    def route_key(self) -> str:
        """
        Convenience method to get the route key for the request. In case you forget how
        it's formatted.
        """
        return f"{self.httpMethod}:{self.resource}"


ActionHandler = Callable[..., Response]

ActionHandlerRoutes = dict[str, ActionHandler]
