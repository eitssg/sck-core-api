import os
import time
from typing import Type, TypeVar, Union, Any

import httpx

import core_logging as log

from core_framework.ai.contracts import (
    AIBaseModel,
    TemplateGenerateRequest,  # noqa: F401 (imported for type side-effect / future use)
    TemplateGenerateResponse,  # noqa: F401
)

from pydantic import ValidationError

_AI_CLIENT: httpx.Client | None = None


def get_ai_client() -> httpx.Client:
    global _AI_CLIENT
    if _AI_CLIENT is None:
        base_url = os.getenv("CORE_AI_BASE_URL", "http://localhost:9999")
        total_timeout = float(os.getenv("CORE_AI_TIMEOUT_SECONDS", "60"))
        connect_timeout = float(os.getenv("CORE_AI_CONNECT_TIMEOUT_SECONDS", "5"))
        # read=None allows long-running streaming / large processing jobs
        timeout = httpx.Timeout(connect=connect_timeout, read=total_timeout, write=total_timeout, pool=total_timeout)
        _AI_CLIENT = httpx.Client(base_url=base_url, timeout=timeout)
    return _AI_CLIENT


class AIServerError(RuntimeError):
    """Upstream AI service network / transport / server error."""


class AIUpstreamValidationError(RuntimeError):
    """AI response did not conform to expected contract model."""


T = TypeVar("T", bound=AIBaseModel)


def _coerce_payload(payload: Union[AIBaseModel, dict, None]) -> dict[str, Any]:
    """Normalize different payload input shapes to a JSON-serializable dict.

    Accepts either an AIBaseModel (preferred) or a plain dict for convenience.
    """
    if payload is None:
        return {}
    if isinstance(payload, AIBaseModel):
        return payload.model_dump(by_alias=True, exclude_none=True)
    if isinstance(payload, dict):
        return payload
    raise TypeError(f"Unsupported payload type: {type(payload)}")


def post_json(path: str, payload: Union[AIBaseModel, dict, None], out_cls: Type[T]) -> T:
    """POST to AI service and parse into the provided Pydantic response model.

    Args:
        path: Upstream relative path (e.g. '/v1/templates/generate').
        payload: Request body (model or dict). None -> empty JSON object.
        out_cls: Contract response model class to validate response data.
    Returns:
        Instance of out_cls.
    Raises:
        AIServerError: Network / timeout / non-success envelope.
        AIUpstreamValidationError: Response JSON fails contract validation.
    """
    client = get_ai_client()
    json_body = _coerce_payload(payload)
    headers: dict[str, str] = {}
    corr_id = log.get_correlation_id()
    if corr_id:
        headers["X-Correlation-ID"] = corr_id
    slow_warn_ms = int(os.getenv("CORE_AI_SLOW_WARN_MS", "30000"))  # 30s default
    very_slow_warn_ms = int(os.getenv("CORE_AI_VERY_SLOW_WARN_MS", "60000"))  # 60s default
    start = time.time()
    try:
        resp = client.post(path, json=json_body, headers=headers or None)
    except httpx.TimeoutException as e:
        raise AIServerError(f"AI request timeout: {path}") from e
    except httpx.HTTPError as e:
        raise AIServerError(f"AI network error: {path}") from e

    elapsed_ms = int((time.time() - start) * 1000)
    if elapsed_ms >= very_slow_warn_ms:
        log.warn("AI upstream VERY SLOW call", details={"path": path, "elapsed_ms": elapsed_ms})
    elif elapsed_ms >= slow_warn_ms:
        log.info("AI upstream slow call", details={"path": path, "elapsed_ms": elapsed_ms})

    try:
        data = resp.json()
    except ValueError as e:
        raise AIServerError(f"Non-JSON response from AI: {path}") from e

    if isinstance(data, dict) and {"status", "code"}.issubset(data.keys()):
        if data.get("status") != "success":
            raise AIServerError(f"AI error: {data.get('message')}")
        inner = data.get("data", {})
    else:
        inner = data

    try:
        return out_cls.model_validate(inner)
    except ValidationError as e:
        raise AIUpstreamValidationError(f"Contract mismatch for {out_cls.__name__}") from e
