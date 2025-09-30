"""
OAuth 2.0 Dynamic Client Registration (RFC 7591)
"""

import hashlib
import uuid
from datetime import datetime, timezone
import secrets


import core_logging as log

from core_db.registry.client import ClientActions, ClientFact

from ..request import RouteEndpoint
from ..response import RedirectResponse, SuccessResponse, ErrorResponse, Response, SuccessResponse, CreatedResponse

###########################################################
#
# THIS FILE IS RUN INSIDE A LAMBDA FUNCTION IT IS NOT A
# FASTAPI ASYNC HANDLER
#
###########################################################

## INCOMPLETE:  This is a starting point for OAuth client registration, it is not complete


def register_client(*, body: dict, **kwargs) -> Response:
    """Register a new OAuth client."""

    # Get the form data
    client = body.get("client")
    redirect_uris = body.get("redirect_uris")
    client_type = body.get("client_type", "public")
    scopes = body.get("scopes", ["registry-clients:read"])

    # Register the client

    if not client:
        return ErrorResponse(code=400, message={"error": "Missing client name"})

    if not redirect_uris:
        return ErrorResponse(code=400, message={"error": "Missing redirect_uris"})

    if isinstance(redirect_uris, str):
        redirect_uris = [redirect_uris]

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

    log.debug("Creating client:", details=client_data)

    try:

        record = ClientFact(**client_data)
        # Store in DynamoDB oauth-clients table
        ClientActions.create(client=client, record=record)
        log.info(
            "OAuth client registered",
            details={"client": client, "client_id": client_id, "client_type": client_type, "redirect_uris": redirect_uris},
        )
    except Exception as e:
        log.warn("OAuth client creation failed", details={"client": client, "error": str(e)})
        return ErrorResponse(code=500, message={"error": str(e)})

    response = {"client": client, "client_id": client_id}
    if client_secret:
        response["client_secret"] = client_secret

    return CreatedResponse(data=response)


def update_client(*, query_params: dict, body: dict, **kwargs) -> Response:
    """Update an existing OAuth client."""

    client = query_params.get("client")

    log.debug(f"Updating client: {client}")

    # Fetch existing client data
    try:
        data = ClientActions.get(client=client)
    except Exception as e:
        log.debug("Client lookup failed for %s: %s", client, str(e))
        return ErrorResponse(code=404, message={"error": "Client not found"})

    client_id = data.client_id
    if not data.client_id:
        client_id = f"{client}_{uuid.uuid4().hex[:12]}"
        data.client_id = client_id

    client_type = body.get("client_type", data.client_type or "public")
    client_secret = secrets.token_urlsafe(32) if client_type == "confidential" else None
    client_secret_hash = hashlib.sha256(client_secret.encode()).hexdigest() if client_secret else None
    redirect_urls = body.get("redirect_uris", data.client_redirect_urls)

    data.client_secret = client_secret_hash

    if redirect_urls:
        data.client_redirect_urls = redirect_urls

    # Update client data
    log.debug("Updating client data:", details=data.model_dump(by_alias=False))
    try:
        ClientActions.update(client=client, record=data)
        log.info("OAuth client updated", details={"client": client, "client_id": client_id, "client_type": client_type})
    except Exception as e:
        log.warn("OAuth client update failed", details={"client": client, "error": str(e)})
        return ErrorResponse(code=500, message={"error": str(e)})

    return SuccessResponse(
        data={
            "client": client,
            "client_id": client_id,
            "client_secret": client_secret,
        }
    )


# At the moment, the API being used is "/api/v1/registry/clients".
# This file and these API may not be needed.

auth_client_endpoints: dict[str, RouteEndpoint] = {
    "POST:/api/v1/clients": register_client,
    "PUT:/api/v1/clients/{client}": update_client,
}
