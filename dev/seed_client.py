"""Dev helper: seed or update a SPA OAuth client in the registry.

Usage (recommended):
  cd sck-core-api
  uv run python dev/seed_client.py --client core --client-id $VITE_OAUTH_CLIENT_ID \
    --redirect http://127.0.0.1:8080/authorized --name "Core UI (Dev)"

Environment:
  AWS creds/region must be configured for your dev DB (DynamoDB Local or AWS account).

Safety:
  - Idempotent: updates existing client if found (by client or by client_id)
  - Adds redirect URI to list if missing
"""

from __future__ import annotations

import argparse
import os
from typing import List

import core_logging as log

from core_db.registry.client.actions import ClientActions
from core_db.registry.client.models import ClientFact


def _ensure_redirects(existing: List[str] | None, redirect: str) -> List[str]:
    lst = [*(existing or [])]
    if redirect and redirect not in lst:
        lst.append(redirect)
    return lst


def seed(client: str, client_id: str, redirect_uri: str, name: str | None = None, description: str | None = None) -> ClientFact:
    # Try by client_id first
    try:
        fact_list = ClientActions.get_by_client_id(client_id=client_id)
        fact = fact_list[0] if fact_list else None
        if fact:
            updates = {
                "client": fact.client,
                "client_name": name or fact.client_name,
                "client_description": description or fact.client_description,
                "client_redirect_urls": _ensure_redirects(fact.client_redirect_urls, redirect_uri),
            }
            ClientActions.patch(**updates)
            log.info("Updated existing client by client_id", details={"client": fact.client})
            return ClientActions.get(client=fact.client)
    except Exception:
        pass

    # Try by client slug
    try:
        res: ClientFact = ClientActions.get(client=client)
        updates = {
            "client": res.client,
            "client_id": client_id or res.client_id,
            "client_name": name or res.client_name,
            "client_description": description or res.client_description,
            "client_redirect_urls": _ensure_redirects(res.client_redirect_urls, redirect_uri),
        }
        ClientActions.patch(**updates)
        log.info("Updated existing client by slug", details={"client": res.client})
        return ClientActions.get(client=res.client)
    except Exception:
        pass

    # Create fresh
    payload = {
        "client": client,
        "client_id": client_id,
        "client_name": name or client,
        "client_description": description or f"Seeded via dev script for {client}",
        "client_redirect_urls": [redirect_uri],
        "client_scopes": ["read:profile", "write:profile"],
    }
    res: ClientFact = ClientActions.create(**payload)
    log.info("Created client", details={"client": client})
    return res


def main():
    parser = argparse.ArgumentParser(description="Seed or update SPA OAuth client in registry")
    parser.add_argument("--client", default=os.getenv("SCK_SEED_CLIENT", "core"), help="Client slug (tenant)")
    parser.add_argument("--client-id", default=os.getenv("SCK_SEED_CLIENT_ID", ""), help="OAuth client_id to register")
    parser.add_argument(
        "--redirect",
        default=os.getenv("SCK_SEED_REDIRECT_URI", "http://127.0.0.1:8080/authorized"),
        help="Allowed redirect URI for the SPA",
    )
    parser.add_argument("--name", default=os.getenv("SCK_SEED_NAME", None), help="Display name")
    parser.add_argument("--description", default=os.getenv("SCK_SEED_DESC", None), help="Description")
    args = parser.parse_args()

    if not args.client_id:
        raise SystemExit("--client-id is required (e.g., VITE_OAUTH_CLIENT_ID)")

    fact = seed(args.client, args.client_id, args.redirect, args.name, args.description)
    print("OK:", fact.model_dump_json())


if __name__ == "__main__":
    main()
