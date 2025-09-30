import os
import core_logging as log

from ..request import RouteEndpoint
from ..security import EnhancedSecurityContext, Permission
from ..response import Response, SuccessResponse, ErrorResponse

from core_framework.ai.contracts import (
    AIBaseModel,
    TemplateGenerateResponse,
    DSLValidateResponse,
    CompileResponse,
    CloudFormationValidateResponse,
    CompletionResponse,
    SearchDocsResponse,
    SearchSymbolsResponse,
)

from .ai_client import AIServerError, AIUpstreamValidationError, post_json
from .idempotency import build_idempotency_key, run_idempotent, get_cache_stats


# By putting the **kwargs at the end of this function signature, you can remove unused paramters if you don't like to see them.
def example_endpoint(*, cookies: dict, headers: dict, path_params: dict, query_params: dict, body: dict, **kwargs) -> Response:
    """
    Docstring for example_endpoint

    In this example the HTTP response body will be:

    JSON:
        {
            "status": "ok",
            "code": 200,
            "data": {"templates": [{ ... }, { ... }]},
            "message": null,
            "errors": null,
            "metadata": null,
            "links": null
        }

    where "data" is your response payload.

    Null or None attributes will not be returned in the actual HTTP response.

    """

    payload = {
        "templates": [
            {
                "id": "template1",
                "name": "Example Template 1",
                "content": "This is the content of template 1.",
            },
            {
                "id": "template2",
                "name": "Example Template 2",
                "content": "This is the content of template 2.",
            },
        ]
    }

    response = SuccessResponse(data=payload)  # HTTP 200 implied.  Specify other success codes if needed.

    # SuccessResponse data attribute will automatically convert the data to a python dictionary.  So the following
    # are equivalent:

    ai_model: AIBaseModel = AIBaseModel()

    response = SuccessResponse(data=ai_model)  # HTTP 200 OK
    response.set_cookie("session_id", "abc123")  # Set a cookie in the response
    response.set_header("X-Custom-Header", "value")  # Add a custom header to the response

    return response


# By putting the **kwargs at the end of this function signature, you can remove unused paramters if you don't like to see them.
def generate_templates(
    *,
    cookies: dict,
    headers: dict,
    path_params: dict,
    query_params: dict,
    body: dict,
    security: EnhancedSecurityContext | None = None,
    **kwargs,
) -> Response:
    """Generate infrastructure templates (idempotent).

    Invariants:
        * body: always a dict (never None) supplied by caller.
        * security.jwt_payload: validated EnhancedSecurityContext when present.
        * Returns SuccessResponse with template generation result.
    """
    # Optional idempotency: derive from JWT claims (cid, cnm, sub) with configurable scope
    if security and security.jwt_payload:
        payload = security.jwt_payload
        client_id = payload.cid
        tenant = payload.cnm
        user_id = payload.sub
    else:
        client_id = tenant = user_id = None

    # Body is guaranteed (by caller) to always be a dict (possibly empty) — never None.
    idem_key = body.get("idempotency_key")

    try:
        if os.getenv("CORE_AI_IDEMPOTENCY_ENABLED", "true").lower() == "true":
            cache_key = build_idempotency_key(
                operation="templates.generate",
                tenant=tenant,
                payload=body,
                explicit_key=idem_key,
                client_id=client_id,
                user_id=user_id,
            )

            def _produce() -> dict:
                result: TemplateGenerateResponse = post_json("/v1/templates/generate", body, TemplateGenerateResponse)
                return result.model_dump(by_alias=True, exclude_none=True)

            cached, meta = run_idempotent(key=cache_key, producer=_produce, want_meta=True)
            resp = SuccessResponse(data=cached)
            resp.set_header("X-Idempotent-Key", meta["key"])  # echo key for observability
            resp.set_header("X-Idempotent-Hit", "1" if meta["hit"] else "0")
            if meta.get("duration_ms") is not None and not meta["hit"]:
                resp.set_header("X-Idempotent-Compute-Ms", str(meta["duration_ms"]))
            return resp
        else:
            result: TemplateGenerateResponse = post_json("/v1/templates/generate", body, TemplateGenerateResponse)
            return SuccessResponse(data=result)
    except AIServerError as e:
        log.error("AI service error (generate_templates): %s", str(e))
        return ErrorResponse(message=str(e), code=502, exception=e)
    except AIUpstreamValidationError as e:
        log.error("AI service validation error (generate_templates): %s", str(e))
        return ErrorResponse(message=str(e), code=424, exception=e)


def validate_dsl(*, cookies: dict, headers: dict, path_params: dict, query_params: dict, body: dict, **kwargs) -> Response:
    """Validate DSL content (pure function – safe to make idempotent later if needed)."""
    try:
        result: DSLValidateResponse = post_json("/v1/dsl/validate", body, DSLValidateResponse)
        return SuccessResponse(data=result)
    except AIServerError as e:
        log.error("AI service error (validate_dsl): %s", str(e))
        return ErrorResponse(message=str(e), code=502, exception=e)
    except AIUpstreamValidationError as e:
        log.error("AI service validation error (validate_dsl): %s", str(e))
        return ErrorResponse(message=str(e), code=424, exception=e)


def compile_template(*, cookies: dict, headers: dict, path_params: dict, query_params: dict, body: dict, **kwargs) -> Response:
    """Compile template. Deterministic for identical input: apply idempotency when enabled."""
    idem_enabled = os.getenv("CORE_AI_IDEMPOTENCY_ENABLED", "true").lower() == "true"
    cache_key = None
    if idem_enabled:
        cache_key = build_idempotency_key(
            operation="templates.compile",
            tenant=None,  # compile may not need tenant scoping here; add if required later
            payload=body,
            explicit_key=body.get("idempotency_key"),
            client_id=None,
            user_id=None,
        )
    try:
        if cache_key:

            def _produce() -> dict:
                r: CompileResponse = post_json("/v1/templates/compile", body, CompileResponse)
                return r.model_dump(by_alias=True, exclude_none=True)

            compiled, meta = run_idempotent(key=cache_key, producer=_produce, want_meta=True)
            resp = SuccessResponse(data=compiled)
            resp.set_header("X-Idempotent-Key", meta["key"])
            resp.set_header("X-Idempotent-Hit", "1" if meta["hit"] else "0")
            if meta.get("duration_ms") is not None and not meta["hit"]:
                resp.set_header("X-Idempotent-Compute-Ms", str(meta["duration_ms"]))
            return resp
        result: CompileResponse = post_json("/v1/templates/compile", body, CompileResponse)
        return SuccessResponse(data=result)
    except AIServerError as e:
        log.error("AI service error (compile_template): %s", str(e))
        return ErrorResponse(message=str(e), code=502, exception=e)
    except AIUpstreamValidationError as e:
        log.error("AI service validation error (compile_template): %s", str(e))
        return ErrorResponse(message=str(e), code=424, exception=e)


def validate_cloudformation(
    *, cookies: dict, headers: dict, path_params: dict, query_params: dict, body: dict, **kwargs
) -> Response:
    """Validate CloudFormation template. Pure validation → candidate for idempotency."""
    try:
        result: CloudFormationValidateResponse = post_json("/v1/cloudformation/validate", body, CloudFormationValidateResponse)
        return SuccessResponse(data=result)
    except AIServerError as e:
        log.error("AI service error (validate_cloudformation): %s", str(e))
        return ErrorResponse(message=str(e), code=502, exception=e)
    except AIUpstreamValidationError as e:
        log.error("AI service validation error (validate_cloudformation): %s", str(e))
        return ErrorResponse(message=str(e), code=424, exception=e)


def completions(*, cookies: dict, headers: dict, path_params: dict, query_params: dict, body: dict, **kwargs) -> Response:
    """Provide code/text completions. Not cached by default (may depend on stochastic model settings)."""
    try:
        result: CompletionResponse = post_json("/v1/completions", body, CompletionResponse)
        return SuccessResponse(data=result)
    except AIServerError as e:
        log.error("AI service error (completions): %s", str(e))
        return ErrorResponse(message=str(e), code=502, exception=e)
    except AIUpstreamValidationError as e:
        log.error("AI service validation error (completions): %s", str(e))
        return ErrorResponse(message=str(e), code=424, exception=e)


def search_docs(*, cookies: dict, headers: dict, path_params: dict, query_params: dict, body: dict, **kwargs) -> Response:
    """Semantic document search. Determinism depends on backend retrieval config – not cached unless later proven stable."""
    try:
        result: SearchDocsResponse = post_json("/v1/search/docs", body, SearchDocsResponse)
        return SuccessResponse(data=result)
    except AIServerError as e:
        log.error("AI service error (search_docs): %s", str(e))
        return ErrorResponse(message=str(e), code=502, exception=e)
    except AIUpstreamValidationError as e:
        log.error("AI service validation error (search_docs): %s", str(e))
        return ErrorResponse(message=str(e), code=424, exception=e)


def search_symbols(*, cookies: dict, headers: dict, path_params: dict, query_params: dict, body: dict, **kwargs) -> Response:
    """Symbol index search. Left non-idempotent for now (index freshness concerns)."""
    try:
        result: SearchSymbolsResponse = post_json("/v1/search/symbols", body, SearchSymbolsResponse)
        return SuccessResponse(data=result)
    except AIServerError as e:
        log.error("AI service error (search_symbols): %s", str(e))
        return ErrorResponse(message=str(e), code=502, exception=e)
    except AIUpstreamValidationError as e:
        log.error("AI service validation error (search_symbols): %s", str(e))
        return ErrorResponse(message=str(e), code=424, exception=e)


def optimize_cloudformation(
    *, cookies: dict, headers: dict, path_params: dict, query_params: dict, body: dict, **kwargs
) -> Response:
    return ErrorResponse(message="Not implemented", code=501)  # HTTP 501 Not Implemented


def ai_cache_stats(*, cookies: dict, headers: dict, path_params: dict, query_params: dict, body: dict, **kwargs) -> Response:
    """Lightweight internal cache statistics endpoint.

    NOTE: This should likely be protected by an internal-only permission or feature flag.
    """
    if os.getenv("CORE_AI_CACHE_STATS_ENABLED", "false").lower() != "true":
        return ErrorResponse(message="Cache stats disabled", code=403)
    stats = get_cache_stats()
    return SuccessResponse(data=stats)


service_actions = {
    "POST:/auth/v1/ai/templates/generate": RouteEndpoint(
        generate_templates,
        permissions=[Permission.DATA_READ],
        allow_anonymous=False,
        client_isolation=True,
    ),
    "POST:/auth/v1/ai/dsl/validate": RouteEndpoint(
        validate_dsl,
        permissions=[Permission.DATA_READ],
        allow_anonymous=False,
        client_isolation=True,
    ),
    "POST:/auth/v1/ai/templates/compile": RouteEndpoint(
        compile_template,
        permissions=[Permission.DATA_READ],
        allow_anonymous=False,
        client_isolation=True,
    ),
    "POST:/auth/v1/ai/cloudformation/validate": RouteEndpoint(
        validate_cloudformation,
        permissions=[Permission.DATA_READ],
        allow_anonymous=False,
        client_isolation=True,
    ),
    "POST:/auth/v1/ai/completions": RouteEndpoint(
        completions,
        permissions=[Permission.DATA_READ],
        allow_anonymous=False,
        client_isolation=True,
    ),
    "POST:/auth/v1/ai/search/docs": RouteEndpoint(
        search_docs,
        permissions=[Permission.DATA_READ],
        allow_anonymous=False,
        client_isolation=True,
    ),
    "POST:/auth/v1/ai/search/symbols": RouteEndpoint(
        search_symbols,
        permissions=[Permission.DATA_READ],
        allow_anonymous=False,
        client_isolation=True,
    ),
    "POST:/auth/v1/ai/cloudformation/optimize": RouteEndpoint(
        optimize_cloudformation,
        permissions=[Permission.DATA_READ],
        allow_anonymous=False,
        client_isolation=True,
    ),
    "GET:/auth/v1/ai/cache/stats": RouteEndpoint(
        ai_cache_stats,
        permissions=[Permission.DATA_READ],
        allow_anonymous=False,
        client_isolation=False,
    ),
}
