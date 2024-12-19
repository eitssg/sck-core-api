from typing import Any
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

import json

import core_framework as util


class Request(BaseModel):
    """This class is used to provided structure to the Lambda Invoker Handler
    Do note that the "data" field is a dictionary that is equivalent to the "body" field
    in the ProxyEvent class.  This is the primary payload for the action.

    The difference is the ProxyEvent.body is expected to be a JSON string, while the
    Request.data is expected to be a dictionary.

    """

    model_config = ConfigDict(populate_by_name=True)

    action: str = Field(description="The action to perform such as 'portfolio:create'")
    data: dict[str, Any] = Field(
        description="The data to use in the action.  This is the primary payload"
    )
    auth: dict[str, Any] | None = Field(
        None, description="The authentication information"
    )

    # Override the model_dump method to exclude None values
    def model_dump(self, **kwargs) -> dict:
        if "exclude_none" not in kwargs:
            kwargs["exclude_none"] = True
        return super().model_dump(**kwargs)


class RequestContextIdentity(BaseModel):
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


class EventRequestContext(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    resourceId: str | None = None
    resourcePath: str | None = None
    httpMethod: str | None = None
    extendedRequestId: str | None = None
    requestTime: str | None = None
    path: str | None = None
    accountId: str | None = None
    protocol: str | None = None
    stage: str | None = None
    domainPrefix: str | None = None
    requestTimeEpoch: int | None = None
    requestId: str | None = None
    domainName: str | None = None
    identity: RequestContextIdentity | None = None


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
    queryStringParameters: dict | None = Field(
        None, description="The query string parameters dictonary"
    )
    pathParameters: dict | None = Field(
        None, description="The path parameters dictionary"
    )
    requestContext: EventRequestContext | None = Field(
        None, description="The request context suuplied by API interface"
    )
    headers: dict = Field(
        {}, description="this should be content-type: applcation/json"
    )
    isBase64Encoded: bool | None = Field(
        False, description="This should be false as the body is JSON"
    )
    body: dict[str, Any] | None = Field(
        description="RESTful API Request (a.k.a DynamoDB Object)",
        default_factory=lambda: {},
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
            return None
        if isinstance(body, str):
            try:
                if len(body) == 0:
                    return None
                return util.from_json(body)
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON string for body")
        if isinstance(body, dict):
            return body
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
