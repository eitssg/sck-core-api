import pytest
from fastapi import Response
from core_api.api.apis import generate_response_from_lambda


@pytest.mark.asyncio
async def test_204_no_entity_headers_and_no_body():
    result = {
        "statusCode": 204,
        "body": "",
        "headers": {"Content-Type": "application/json", "X-Test": "ok"},
        "multiValueHeaders": {"Set-Cookie": ["a=1", "b=2"]},
        "isBase64Encoded": False,
    }
    resp: Response = await generate_response_from_lambda(result)
    assert resp.status_code == 204
    # Starlette normalizes header capitalization; check by lower() presence
    keys = {k.lower() for k in resp.headers.keys()}
    assert "content-type" not in keys
    assert "content-length" not in keys
    assert resp.body == b""  # no body
    # cookies preserved (headers multi-set under the hood)
    set_cookies = [v for (k, v) in resp.raw_headers if k.decode().lower() == "set-cookie"]
    assert len(set_cookies) == 2


@pytest.mark.asyncio
async def test_304_no_entity_headers_and_no_body():
    result = {
        "statusCode": 304,
        "body": "",
        "headers": {"Content-Type": "application/json", "ETag": 'W/"123"'},
        "multiValueHeaders": {},
        "isBase64Encoded": False,
    }
    resp: Response = await generate_response_from_lambda(result)
    assert resp.status_code == 304
    keys = {k.lower() for k in resp.headers.keys()}
    assert "content-type" not in keys
    assert "content-length" not in keys
    assert resp.body == b""
