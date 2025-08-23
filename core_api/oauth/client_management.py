"""
OAuth 2.0 Dynamic Client Registration (RFC 7591)
"""

import hashlib
import uuid
from datetime import datetime, timezone
import secrets

from fastapi import Request, APIRouter
from fastapi.responses import JSONResponse

from core_db.registry.client.actions import ClientActions
from core_db.response import SuccessResponse

client_router = APIRouter()


@client_router.post("/v1/register")
async def register_client(request: Request):
    """Register a new OAuth client."""
    body = await request.json()

    # Validate registration
    client_id = f"client_{uuid.uuid4().hex[:12]}"
    client_secret = secrets.token_urlsafe(32) if body.get("client_type") == "confidential" else None

    client_data = {
        "client": client_id,
        "client_id": client_id,
        "client_secret": hashlib.sha256(client_secret.encode()).hexdigest() if client_secret else None,
        "client_redirect_uris": body["redirect_uris"],
        "client_type": body.get("client_type", "public"),
        "client_scopes": body.get("scopes", ["registry-clients:read"]),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        # Store in DynamoDB oauth-clients table
        response: SuccessResponse = ClientActions.create(**client_data)
        data = response.data

        response = {"client_id": client_id}
        if client_secret:
            response["client_secret"] = client_secret

        return JSONResponse(status_code=201, content=response)

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
