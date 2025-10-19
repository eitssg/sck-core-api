import pytest
import os
import io
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

import core_framework as util

from core_execute.actionlib.actions.system.no_op import NoOpActionResource

from core_db.event.models import EventModel
from core_db.item.models import ItemModel
from core_db.registry.client.models import ClientFactsModel
from core_db.registry.portfolio.models import PortfolioFactsModel
from core_db.registry.app.models import AppFactsModel
from core_db.registry.zone.models import ZoneFactsModel

from core_api.api.fast_api import get_app

# Fixed: Add missing imports
from core_framework.models import TaskPayload, DeploymentDetails
from core_helper.magic import MagicS3Client

from core_api.auth.tools import create_access_token_with_sts
from core_api.security import Permission

from .test_api_data import api_endpoints

# Create a FastAPI test client the same that uvicorn will use
client = TestClient(get_app())

from .bootstrap import *


@pytest.fixture(scope="module")
def session_token() -> str:
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
            client_id="cid_1",
            client="core",
            subject="simple-cloud-kit",
            scope="sck:admin sck:read sck:write",
            permissions={"*": Permission.SYSTEM_ADMIN},  # Use highest permission for testing
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


@pytest.fixture(scope="module")
def teardown_action(bootstrap_dynamo):
    """Create test action and upload to S3."""
    assert bootstrap_dynamo  # Fixed: ensure bootstrap completed

    action = NoOpActionResource.model_validate(
        {
            "name": "teardown",
            "description": "Teardown test resources",
            "spec": {
                "account": "123456789012",
                "region": "us-west-1",
                "stack_name": "no-stack-exists",
            },
        }
    )

    task_payload = TaskPayload(
        task="teardown",  # Pydantic models use snake_case
        deployment_details=DeploymentDetails(portfolio="simple-cloud-kit", app="api", branch="main", build="1"),
    )

    # Pydantic models use snake_case attributes
    bucket_name = task_payload.actions.bucket_name
    action_details = task_payload.actions
    state_details = task_payload.state

    # MagicS3Client constructor uses PascalCase parameters - CORRECTED
    magicS3 = MagicS3Client(Region=action_details.bucket_region)

    # Create a sample action file for the test cases (teardown)
    action_list = [action.model_dump()]

    data = io.StringIO()
    util.write_yaml(action_list, data)

    data.seek(0)  # Reset the stream position to the beginning

    # MagicS3Client put_object uses PascalCase parameters - CORRECTED
    magicS3.put_object(Bucket=bucket_name, Key=action_details.key, Body=data)

    # Create a sample state file (context file) for the test cases
    fn = os.path.join(os.path.dirname(__file__), "test_context_state.yaml")
    with open(fn, "r") as f:
        data_content = f.read()

    # MagicS3Client put_object uses PascalCase parameters - CORRECTED
    magicS3.put_object(Bucket=bucket_name, Key=state_details.key, Body=data_content)

    return action


@pytest.mark.parametrize("http_path,expected_result", api_endpoints)
def test_app(http_path, expected_result, bootstrap_dynamo, teardown_action, client_headers):
    """Test API endpoints with various HTTP methods."""
    assert bootstrap_dynamo  # Fixed: ensure bootstrap completed
    assert teardown_action  # Fixed: ensure teardown action is available

    client.headers = client_headers

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

        response_envelope = response.json()
        expected_response = expected_result[1]

        if response.status_code != expected_result[0]:
            assert False, response_envelope["data"]["message"]

        assert "status" in response_envelope
        assert response_envelope["status"] == expected_response["status"]
        assert "code" in response_envelope
        assert response_envelope["code"] == expected_response["code"]

        response_data = response_envelope.get("data", None)
        expected_data = expected_response.get("data", None)

        if isinstance(expected_data, dict):
            for k, v in expected_data.items():
                assert k in response_data
                assert response_data[k] == v

        elif isinstance(expected_data, list):
            assert len(response_data) > 0
            for i in range(len(response_data)):
                if isinstance(expected_data[i], dict):
                    for k, v in expected_data[i].items():
                        assert k in response_data[i]
                        assert response_data[i][k] == v
                elif isinstance(expected_data[i], str):
                    assert response_data[i] == expected_data[i]

        elif isinstance(expected_data, str):
            assert response_data == expected_data

    except Exception as e:
        assert False, f"Error: {str(e)}"
