import pytest
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient

import core_framework as util

from core_db.event.models import EventModel
from core_db.item.models import ItemModel
from core_db.registry.client.models import ClientFactsModel
from core_db.registry.portfolio.models import PortfolioFactsModel
from core_db.registry.app.models import AppFactsModel
from core_db.registry.zone.models import ZoneFactsModel

from core_api.api.fast_api import get_app
from core_api.auth.tools import create_access_token_with_sts

from .test_facts_data import api_endpoints

from .bootstrap import bootstrap_dynamo
from .test_seed_data import seed_test_data

# Create a FastAPI test client the same that unvicorn will use
http_client = TestClient(get_app())


@pytest.fixture(scope="module", autouse=True)
def user_permissions() -> dict[str, list[str]]:
    """Define user permissions for testing.
    
    Emulate the 'read user permissions' from the UserProfile database.
    
    """
    return {
        "registry": ["*:read", "*:write", "*:admin"],
        "item": ["*:read", "*:write", "*:admin"],
        "event": ["read", "write", "admin"],
    }

@pytest.fixture(scope="module")
def session_token(user_permissions) -> str:
    """Create a session token for testing."""
    # Mock boto3.client for STS
    mock_sts_client = MagicMock()
    mock_sts_client.get_session_token.return_value = {
        'Credentials': {
            'AccessKeyId': 'TESTKEYXXXXXXX',
            'SecretAccessKey': 'TESTSECRETXXXXXXX',
            'SessionToken': 'TESTSESSIONXXXXXXX',
            'Expiration': '2030-01-01T14:00:00+00:00',
        }
    }

    with patch('boto3.client') as mock_client:
        mock_client.return_value = mock_sts_client
        
        # Create a test user and get a session token
        token = create_access_token_with_sts(
            aws_credentials={
                "AccessKeyId": "TESTKEYXXXXXXX",
                "SecretAccessKey": "TESTSECRETXXXXXXX",
            },
            client_id="core_669a5fdd8be7",  # Our test seed data uses this client ID
            client="core",
            subject="simple-cloud-kit",
            scope="sck:admin sck:read sck:write",
            permissions=user_permissions,
        )
    return token


@pytest.fixture(scope="module", autouse=True)
def client_headers(session_token: str) -> dict[str, str]:
    """Create headers for testing."""
    headers = {
        "Authorization": f"Bearer {session_token}",
        "Content-Type": "application/json",
    }
    return headers


@pytest.mark.parametrize("http_path,expected_result", api_endpoints)
def test_the_facts(http_path, expected_result, seed_test_data, client_headers):  # noqa E302

    http_client.headers = client_headers

    try:
        method, path, body = http_path
        if method == "GET":
            response = http_client.get(path)
        elif method == "POST":
            response = http_client.post(path, json=body)
        elif method == "PUT":
            response = http_client.put(path, json=body)
        elif method == "DELETE":
            response = http_client.delete(path)
        elif method == "PATCH":
            response = http_client.patch(path, json=body)
        else:
            assert False, f"Unknown method: {method}"

        response_envelope = response.json()
        expected_response = expected_result[1]

        assert response.status_code == expected_result[0], response_envelope

        if "status" in expected_response:
            assert "status" in response_envelope
            assert response_envelope["status"] == expected_response["status"]
        
        if "message" in expected_response:
            assert "message" in response_envelope
            assert response_envelope["message"] == expected_response["message"]

        if "code" in expected_response:
            assert "code" in response_envelope
            assert response_envelope["code"] == expected_response["code"]

        if "data" in expected_response:
            assert "data" in response_envelope
    
            response_data = response_envelope.get("data")     
            expected_data = expected_response.get("data")

            def compare_data(expected, actual) -> None:
                if isinstance(expected, dict):
                    for k, v in expected.items():
                        assert k in actual, f"Missing key: {k}"
                        compare_data(v, actual[k])
                elif isinstance(expected, list):
                    assert isinstance(actual, list), f"'{actual}' should be a list"
                    assert len(actual) == len(expected), f"The lists are different lengths"
                    for i in range(0, len(expected)):
                        compare_data(expected[i], actual[i])
                else:
                    assert expected == actual

            compare_data(expected_data, response_data)

    except Exception as e:
        assert False, f"Error: {e}"
