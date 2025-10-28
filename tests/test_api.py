import pytest
import os
import io
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

import core_framework as util

from core_execute.actionlib.actions.system.no_op import NoOpActionResource

from core_api.api.fast_api import get_app

# Fixed: Add missing imports
from core_framework.models import TaskPayload, DeploymentDetails
from core_helper.magic import MagicS3Client

from core_api.auth.tools import create_access_token_with_sts
from core_api.security import Permission

from .test_api_data import api_endpoints

# Create a FastAPI test client the same that uvicorn will use
http_client = TestClient(get_app())

from .bootstrap import *

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

    # IRL, these details would come from the deployment context calculated by environment variables
    # Typcially client_id is set by the program environment and client is defaulted from environment variables
    # or configuration files.

    dd = DeploymentDetails.model_validate(
        {
            "client_id": "core_669a5fdd8be7",  # Our test seed data uses this client ID
            "client": "core",
            "portfolio": "simple-cloud-kit",
            "app": "api",
            "branch": "main",
            "build": "1",
        }
    )

    task_payload = TaskPayload(Task="teardown", DeploymentDetails=dd)

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

        response_envelope = response.json() if response.content else {}

        assert response.status_code == expected_result[0], response_envelope

        expected_response = expected_result[1]

        if "status" in expected_response:
            assert "status" in response_envelope
            assert response_envelope["status"] == expected_response["status"]

        if "message" in expected_response:
            assert "message" in response_envelope
            assert response_envelope["message"] == expected_response["message"]

        if "code" in expected_response:
            assert "code" in response_envelope
            assert response_envelope["code"] == expected_response["code"]


        def compare_dicts(expected: any, actual: any):
            if isinstance(expected, dict):
                for k, v in expected.items():
                    assert k in actual, f"Missing key: {k}"
                    compare_dicts(v, actual[k])
            elif isinstance(expected, list):
                assert isinstance(actual, list), f"Expected list but got {type(actual)}"
                assert len(expected) == len(actual), f"Expected list length {len(expected)} but got {len(actual)}"
                for exp_item, act_item in zip(expected, actual):
                    compare_dicts(exp_item, act_item)
            else:
                assert expected == actual, f"Expected value {expected} but got {actual}"
                
        if "data" in expected_response:
            assert "data" in response_envelope

            response_data = response_envelope.get("data", None)
            expected_data = expected_response.get("data", None)

            compare_dicts(expected_data, response_data)

    except Exception as e:
        assert False, f"Error: {str(e)}"
