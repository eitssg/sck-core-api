# pylint: disable=unused-argument
from collections import ChainMap

from core_db.event.actions import EventActions
from core_db.exceptions import BadRequestException, NotFoundException, ConflictException, ForbiddenException

from ..security import EnhancedSecurityContext, Permission
from ..actions import ApiActions
from ..request import RouteEndpoint
from ..response import Response, SuccessResponse, ErrorResponse


class ApiEventActions(ApiActions, EventActions):
    """Bridge API-layer helpers with core database event actions."""

    pass


def _merged(query_params: dict, path_params: dict, body: dict) -> dict:
    args = dict(ChainMap(path_params, query_params, body))
    if "client" in args:
        del args["client"]
    return args

def action_get_event_list(*, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    """Retrieve events for the authenticated client.

    **Method:** `GET`

    **Path:** `/api/v1/events`

    **Required Permission:** `EVENT_READ`

    #### Request

    | Location | Name            | Type   | Required | Description |
    |----------|-----------------|--------|----------|-------------|
    | query/body | `prn`           | str    | No       | PRN filter (e.g., `client:portfolio:app:branch`). |
    | query/body | `earliest_time` | str    | No       | ISO8601 lower bound for `timestamp`. |
    | query/body | `latest_time`   | str    | No       | ISO8601 upper bound for `timestamp`. |
    | query/body | `sort`          | str    | No       | `ascending` (default) or `descending`. |
    | query/body | `limit`         | int    | No       | Page size (defaults to service limit). |
    | query/body | `data_paginator`| str    | No       | Opaque token for the next page. |

    Authentication: `Authorization: Bearer <access_token>` header; tenant scope derived from `EnhancedSecurityContext`.

    #### Responses

    | Status | Description                                   |
    |--------|-----------------------------------------------|
    | 200    | Events returned in `data`, paginator in `metadata`. |
    | 400    | Validation failed (missing/invalid filters).      |
    | 500    | Unexpected server error.                         |

    #### Example

    >>> curl \\
    ...  -H "Authorization: Bearer $TOKEN" \\
    ...  "https://api.example.com/api/v1/events?prn=client:portfolio:app&limit=50"

          
    """
    try:
        args = _merged(query_params, path_params, body)
        results, paginator = ApiEventActions.list(client=security.client, **args)
        data = [item.model_dump(by_alias=False, mode="json") for item in results]
        return SuccessResponse(data=data, metadata=paginator.get_metadata())

    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def action_create_event(*, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs) -> Response:
    """Create a new event fact for the authenticated client.

    **Method:** `PUT`

    **Path:** `/api/v1/event`

    **Required Permission:** `EVENT_CREATE`

    #### Request

    | Location | Name        | Type | Required | Description |
    |----------|-------------|------|----------|-------------|
    | body     | `prn`       | str  | Yes      | Fully qualified PRN for the event (e.g., `client:portfolio:app:branch:build:component`). |
    | body     | `timestamp` | str  | Yes      | Event timestamp in ISO8601 format. |
    | body     | `event_type`| str  | Yes      | Logical event type (`status`, `metric`, etc.). |
    | body     | `status`    | str  | Yes      | Outcome or state (`success`, `failure`, etc.). |
    | body     | `message`   | str  | No       | Human-readable summary. |
    | body     | `metadata`  | dict | No       | Arbitrary structured payload associated with the event. |

    Authentication: `Authorization: Bearer <access_token>` header; tenant scope derived from `EnhancedSecurityContext`.

    #### Responses

    | Status | Description                                   |
    |--------|-----------------------------------------------|
    | 201    | Event created; serialized event returned in `data`. |
    | 400    | Validation failed (missing fields, bad types).      |
    | 409    | Duplicate event detected (conflict).                |
    | 500    | Unexpected server error.                           |

    #### Example

    ```bash
    curl \
      -X PUT \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
            "prn": "client:portfolio:app:branch:build:component",
            "timestamp": "2025-10-21T00:00:00Z",
            "event_type": "status",
            "status": "success",
            "message": "Build finished"
          }' \
      "https://api.example.com/api/v1/event"
    ```
    """
    try:

        args = _merged(query_params, path_params, body)
        result = ApiEventActions.create(client=security.client, **args)
        data = result.model_dump(by_alias=False, mode="json")
        return SuccessResponse(data=data, code=201)
    
    except BadRequestException as e:
        return ErrorResponse(code=400, message=str(e))
    
    except ConflictException as e:
        return ErrorResponse(code=409, message=str(e))

    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)


def action_delete_event(
    *, query_params: dict, path_params: dict, body: dict, security: EnhancedSecurityContext, **kwargs
) -> Response:
    """Delete an event using path or query parameters.

    **Method:** `DELETE`

    **Path:** `/api/v1/event`

    **Required Permission:** `EVENT_ADMIN`

    #### Request

    | Location | Name  | Type | Required | Description |
    |----------|-------|------|----------|-------------|
    | query/path/body | `prn` | str  | Yes      | PRN of the event to remove. |
    | query/path/body | `timestamp` | str | No | When supplied, deletes the specific record at that timestamp; otherwise defaults per data store semantics. |

    Authentication: `Authorization: Bearer <access_token>` header; tenant scope derived from `EnhancedSecurityContext`.

    #### Responses

    | Status | Description                               |
    |--------|-------------------------------------------|
    | 204    | Event deleted; no response body returned. |
    | 404    | Event not found for supplied identifiers. |
    | 500    | Unexpected server error.                  |

    #### Example

    ```bash
    curl \
      -X DELETE \
      -H "Authorization: Bearer $TOKEN" \
      "https://api.example.com/api/v1/event?prn=client:portfolio:app:branch:build:component&timestamp=2025-10-21T00:00:00Z"
    ```
    """
    try:
        args = _merged(query_params, path_params, body)
        ApiEventActions.delete(client=security.client, **args)
        return SuccessResponse(code=204)
    
    except NotFoundException as e:
        return ErrorResponse(code=404, message=str(e))
    
    except Exception as e:
        return ErrorResponse(code=500, message=str(e), exception=e)

# Define API Gateway routes
event_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/events": RouteEndpoint(
        action_get_event_list,
        required_permissions={Permission.EVENT_READ},
        client_isolated=True,
    ),
    "PUT:/api/v1/event": RouteEndpoint(
        action_create_event,
        required_permissions={Permission.EVENT_WRITE},
        client_isolated=True,
    ),
    "DELETE:/api/v1/event": RouteEndpoint(
        action_delete_event,
        required_permissions={Permission.EVENT_ADMIN},
        client_isolated=True,
    ),
}
