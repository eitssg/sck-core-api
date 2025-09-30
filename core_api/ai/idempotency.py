import hashlib
import os
import time
from typing import Callable, Any, Dict

import core_logging as log
import core_framework as util
from core_helper import aws  # provides global InMemoryCache instance `store`

# Default TTL for idempotent results (seconds)
IDEMPOTENCY_TTL = int(os.getenv("CORE_AI_IDEMPOTENCY_TTL", "900"))  # 15 minutes default


def _hash_components(components: list[str]) -> str:
    sha = hashlib.sha256()
    for part in components:
        if part is None:
            part = ""
        sha.update(part.encode("utf-8"))
        sha.update(b"\0")  # delimiter
    return sha.hexdigest()


def build_idempotency_key(
    *,
    operation: str,
    tenant: str | None,
    payload: dict | None,
    explicit_key: str | None = None,
    client_id: str | None = None,
    user_id: str | None = None,
) -> str:
    """Construct a deterministic cache key for an AI operation respecting multi-tenancy.

    Key structure (segments separated by ':'):
        ai-idem:<scope-segments>:<operation>:<hash|explicit>

    Scope segments are determined by CORE_AI_IDEMPOTENCY_SCOPE env var:
        'client' -> client_id only
        'tenant' (default) -> client_id + tenant
        'user'   -> client_id + tenant + user_id

    Args:
        operation: Logical operation name (e.g. 'templates.generate').
        tenant: Active tenant/client slug (cnm claim). None -> 'global'.
        payload: Request payload dict used to derive hash (order-insensitive canonical JSON) when explicit_key absent.
        explicit_key: Optional caller-provided stable key overriding payload hashing.
        client_id: OAuth client_id (cid claim) to namespace across SPA deployments.
        user_id: Subject (sub claim) for optional per-user scoping.

    Returns:
        Namespaced cache key string.
    """
    scope_mode = os.getenv("CORE_AI_IDEMPOTENCY_SCOPE", "tenant").lower()
    tenant_part = (tenant or "global").lower()
    client_part = (client_id or "global").lower()
    user_part = (user_id or "anon").lower()

    # Build scope prefix according to mode
    if scope_mode == "client":
        scope_prefix = f"{client_part}"
    elif scope_mode == "user":
        scope_prefix = f"{client_part}:{tenant_part}:{user_part}"
    else:  # tenant (default)
        scope_prefix = f"{client_part}:{tenant_part}"

    if explicit_key:
        base = explicit_key
    else:
        try:
            canonical = util.to_json(payload or {}, sort_keys=True)
        except Exception:
            canonical = str(payload or {})
        base = _hash_components([operation, canonical])

    return f"ai-idem:{scope_prefix}:{operation}:{base}"


def run_idempotent(
    *,
    key: str,
    producer: Callable[[], Dict[str, Any]],
    ttl: int | None = None,
    want_meta: bool = False,
) -> Any:
    """Execute producer under idempotency, caching successful result.

    The cache value stored:
        {"created_at": epoch_seconds, "hits": n, "duration_ms": ms, "result": <producer dict>}

    Args:
        key: Pre-built idempotency key.
        producer: Zero-arg callable returning a JSON-serializable dict (contract data portion).
        ttl: Optional override TTL in seconds; defaults to IDEMPOTENCY_TTL.
        want_meta: When True, return a tuple of (result, meta) where meta includes cache key & hit info.

    Returns:
        result dict OR (result dict, meta dict) if want_meta=True.
    """
    cache = aws.store  # InMemoryCache instance
    envelope = cache.retrieve_data(key)
    if envelope:
        envelope["hits"] = int(envelope.get("hits", 0)) + 1
        cache.store_data(key, envelope, ttl=ttl or IDEMPOTENCY_TTL)
        log.debug("Idempotent cache hit", details={"key": key, "hits": envelope["hits"]})
        result = envelope.get("result", {})
        if want_meta:
            meta = {
                "key": key,
                "hit": True,
                "hits": envelope["hits"],
                "created_at": envelope.get("created_at"),
                "duration_ms": envelope.get("duration_ms"),
            }
            return result, meta
        return result

    start = time.time()
    result = producer()
    duration_ms = int((time.time() - start) * 1000)

    to_store = {"created_at": int(start), "hits": 1, "duration_ms": duration_ms, "result": result}
    cache.store_data(key, to_store, ttl=ttl or IDEMPOTENCY_TTL)
    log.debug(
        "Idempotent cache store",
        details={"key": key, "duration_ms": duration_ms, "ttl": ttl or IDEMPOTENCY_TTL},
    )
    if want_meta:
        meta = {
            "key": key,
            "hit": False,
            "hits": 1,
            "created_at": to_store["created_at"],
            "duration_ms": duration_ms,
        }
        return result, meta
    return result


def get_cache_stats() -> dict[str, Any]:
    """Return lightweight statistics about the shared InMemoryCache.

    Avoids enumerating all keys (which could be large) – only size and rough counts.
    """
    cache = aws.store
    try:
        size = cache.size()
    except Exception:
        size = -1
    # keys() may be moderately sized; wrap in try/except
    key_names: list[str] = []
    try:
        key_names = cache.keys()  # type: ignore[attr-defined]
    except Exception:
        pass
    ai_idem = [k for k in key_names if k.startswith("ai-idem:")]
    return {
        "total_keys": len(key_names),
        "cache_entries": size,
        "ai_idempotent_entries": len(ai_idem),
    }
