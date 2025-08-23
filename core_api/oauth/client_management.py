"""
OAuth 2.0 Dynamic Client Registration (RFC 7591)
"""

import hashlib
import uuid
from datetime import datetime, timezone
import secrets

from fastapi import Request, APIRouter, Response
from fastapi.responses import JSONResponse

import core_logging as log

from core_db.registry.client.actions import ClientActions

from core_api.item.build import SuccessResponse

client_router = APIRouter()


@client_router.post("/v1/register")
async def register_client(request: Request) -> Response:
    """Register a new OAuth client."""

    log.debug("Registering new client")
    try:
        body = await request.json()
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON payload"})

    client = body.get("client")
    if not client:
        return JSONResponse(status_code=400, content={"error": "Missing client name"})

    redirect_uris = body.get("redirect_uris")
    if not redirect_uris:
        return JSONResponse(status_code=400, content={"error": "Missing redirect_uris"})

    if isinstance(redirect_uris, str):
        redirect_uris = [redirect_uris]

    client_type = body.get("client_type", "public")

    scopes = body.get("scopes", ["registry-clients:read"])
    if not isinstance(scopes, list):
        scopes = [scopes]

    # Validate registration
    client_id = f"{client}_{uuid.uuid4().hex[:12]}"
    client_secret = secrets.token_urlsafe(32) if body.get("client_type") == "confidential" else None
    client_secret_hash = hashlib.sha256(client_secret.encode()).hexdigest() if client_secret else None
    client_data = {
        "client": client,
        "client_id": client_id,
        "client_secret": client_secret_hash,
        "client_redirect_uris": redirect_uris,
        "client_type": client_type,
        "client_scopes": scopes,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    log.debug(f"Creating client:", details=client_data)

    try:
        # Store in DynamoDB oauth-clients table
        ClientActions.create(**client_data)
    except Exception as e:
        log.error(f"Error creating client: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

    response = {"client": client, "client_id": client_id}
    if client_secret:
        response["client_secret"] = client_secret

    return JSONResponse(status_code=201, content=response)


@client_router.put("/v1/clients/{client}")
async def update_client(client: str, request: Request) -> Response:
    """Update an existing OAuth client."""

    log.debug(f"Updating client: {client}")
    try:
        body = await request.json()
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON payload"})

    # Fetch existing client data
    try:
        existing_client: SuccessResponse = ClientActions.get(client=client)
        data = existing_client.data
    except Exception as e:
        log.info(f"Client Not Found: {client}: {str(e)}")
        return JSONResponse(status_code=404, content={"error": "Client not found"})

    client_id = data.get("ClientId")
    if not client_id:
        client_id = f"{client}_{uuid.uuid4().hex[:12]}"
        data["ClientId"] = client_id

    client_type = body.get("client_type", data.get("client_type", "public"))
    client_secret = secrets.token_urlsafe(32) if client_type == "confidential" else None
    client_secret_hash = hashlib.sha256(client_secret.encode()).hexdigest() if client_secret else None
    redirect_uris = body.get("redirect_uris", data.get("client_redirect_uris"))

    data["ClientSecret"] = client_secret_hash

    if redirect_uris:
        data["client_redirect_uris"] = redirect_uris

    # Update client data
    log.debug(f"Updating client data:", details=data)
    try:
        ClientActions.update(**data)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

    return JSONResponse(
        status_code=200,
        content={
            "client": client,
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )
