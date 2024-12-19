import pytest

from fastapi.testclient import TestClient
from core_api.api.fast_api import get_app

from .test_api_data import api_paths

client = TestClient(get_app())


@pytest.mark.parametrize("http_path,expected_result", api_paths)
def test_app(http_path, expected_result):  # noqa E302

    try:
        method, path, body = http_path
        if method == "GET":
            response = client.get(path)
        elif method == "POST":
            response = client.post(path, json=body)
        elif method == "PUT":
            response = client.put(path, json=body)
        elif method == "DELETE":
            response = client.delete(path)
        elif method == "PATCH":
            response = client.patch(path, json=body)
        else:
            assert False, f"Unknown method: {method}"

        response_data = response.json()
        expected_response = expected_result[1]

        assert response.status_code == expected_result[0]

        assert "status" in response_data
        assert response_data["status"] == expected_response["status"]
        assert "code" in response_data
        assert response_data["code"] == expected_response["code"]

        data = response_data.get("data", None)
        expected_data = expected_response.get("data", None)

        if isinstance(expected_data, dict):
            for k, v in expected_data.items():
                assert k in data
                assert data[k] == v

        elif isinstance(expected_data, list):
            assert len(data) > 0

    except Exception as e:
        assert False, f"Error: {e}"
