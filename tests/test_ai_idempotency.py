import os
import time

from core_api.ai.service import generate_templates, compile_template
from core_api.ai.idempotency import build_idempotency_key
from core_api.security import EnhancedSecurityContext
from core_api.auth.tools import JwtPayload


class DummyResponseModel:
    """Minimal stand-in to assert shape if needed (not used directly)."""

    pass


def _mk_security(cid: str = "spa123", cnm: str = "core", sub: str = "user@example.com") -> EnhancedSecurityContext:
    payload = JwtPayload(sub=sub, cid=cid, cnm=cnm, ttl=5)
    return EnhancedSecurityContext(permissions=set(), roles=set(), jwt_payload=payload)


def test_generate_templates_idempotent_hit(tmp_path, monkeypatch):
    os.environ["CORE_AI_IDEMPOTENCY_ENABLED"] = "true"
    os.environ["CORE_AI_IDEMPOTENCY_SCOPE"] = "tenant"

    body = {"query": "make me a template"}
    security = _mk_security()

    # First call should compute
    resp1 = generate_templates(cookies={}, headers={}, path_params={}, query_params={}, body=body, security=security)
    data1 = resp1.data
    key1 = resp1.headers.get("X-Idempotent-Key")
    assert key1
    assert resp1.headers.get("X-Idempotent-Hit") == "0"
    assert "X-Idempotent-Compute-Ms" in resp1.headers

    # Second call identical -> cache hit
    resp2 = generate_templates(cookies={}, headers={}, path_params={}, query_params={}, body=body, security=security)
    data2 = resp2.data
    key2 = resp2.headers.get("X-Idempotent-Key")
    assert key1 == key2
    assert resp2.headers.get("X-Idempotent-Hit") == "1"
    assert data1 == data2


def test_compile_template_idempotent(tmp_path, monkeypatch):
    os.environ["CORE_AI_IDEMPOTENCY_ENABLED"] = "true"
    body = {"source": "some template dsl"}

    resp1 = compile_template(cookies={}, headers={}, path_params={}, query_params={}, body=body)
    assert resp1.headers.get("X-Idempotent-Key")
    assert resp1.headers.get("X-Idempotent-Hit") == "0"

    resp2 = compile_template(cookies={}, headers={}, path_params={}, query_params={}, body=body)
    assert resp2.headers.get("X-Idempotent-Key") == resp1.headers.get("X-Idempotent-Key")
    assert resp2.headers.get("X-Idempotent-Hit") == "1"


def test_build_idempotency_key_stable(monkeypatch):
    os.environ["CORE_AI_IDEMPOTENCY_SCOPE"] = "tenant"
    k1 = build_idempotency_key(
        operation="templates.generate", tenant="core", payload={"a": 1, "b": 2}, explicit_key=None, client_id="spa123", user_id="u"
    )
    # Re-ordered payload should hash same
    k2 = build_idempotency_key(
        operation="templates.generate", tenant="core", payload={"b": 2, "a": 1}, explicit_key=None, client_id="spa123", user_id="u"
    )
    assert k1 == k2


def test_build_idempotency_key_scope_variants(monkeypatch):
    base_payload = {"x": 1}
    os.environ["CORE_AI_IDEMPOTENCY_SCOPE"] = "client"
    kc = build_idempotency_key(
        operation="op", tenant="core", payload=base_payload, explicit_key=None, client_id="cid1", user_id="user"
    )
    os.environ["CORE_AI_IDEMPOTENCY_SCOPE"] = "tenant"
    kt = build_idempotency_key(
        operation="op", tenant="core", payload=base_payload, explicit_key=None, client_id="cid1", user_id="user"
    )
    os.environ["CORE_AI_IDEMPOTENCY_SCOPE"] = "user"
    ku = build_idempotency_key(
        operation="op", tenant="core", payload=base_payload, explicit_key=None, client_id="cid1", user_id="user"
    )
    assert kc != kt != ku
