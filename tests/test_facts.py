import os
import io
import pytest

from fastapi.testclient import TestClient

from ruamel.yaml import YAML

import core_framework as util
from core_framework.magic import MagicS3Client

from core_framework.models import (
    ActionDefinition,
    ActionParams,
    DeploymentDetails as DeploymentDetailsClass,
    TaskPayload,
)

from core_db.event.models import EventModel
from core_db.item.models import ItemModel
from core_db.registry.client.models import ClientFacts
from core_db.registry.portfolio.models import PortfolioFacts
from core_db.registry.app.models import AppFacts
from core_db.registry.zone.models import ZoneFacts

from core_api.api.fast_api import get_app

from .test_api_data import api_paths

# Create a FastAPI test client the same that unvicorn will use
client = TestClient(get_app())


@pytest.fixture(scope="module")
def bootstrap_dynamo():

    # see environment variables in .env
    host = util.get_dynamodb_host()

    assert (
        host == "http://localhost:8000"
    ), "DYNAMODB_HOST must be set to http://localhost:8000"

    try:
        if EventModel.exists():
            EventModel.delete_table()
        EventModel.create_table(wait=True)

        if ItemModel.exists():
            ItemModel.delete_table()
        ItemModel.create_table(wait=True)

        if ClientFacts.exists():
            ClientFacts.delete_table()
        ClientFacts.create_table(wait=True)

        if PortfolioFacts.exists():
            PortfolioFacts.delete_table()
        PortfolioFacts.create_table(wait=True)

        if AppFacts.exists():
            AppFacts.delete_table()
        AppFacts.create_table(wait=True)

        if ZoneFacts.exists():
            ZoneFacts.delete_table()
        ZoneFacts.create_table(wait=True)

    except Exception as e:
        print(e)
        assert False

    return True


@pytest.fixture(scope="module")
def teardown_action():

    action = ActionDefinition(
        Label="my-teardown-action",
        Type="SYSTEM::NoOp",
        Params=ActionParams(  # These parameters are not even used by NoOp
            Account="123456789012", Region="us-west-1", StackName="no-stack-exists"
        ),
        Scope="build",
    )

    task_payload = TaskPayload(
        Task="teardown",
        DeploymentDetails=DeploymentDetailsClass(
            Portfolio="simple-cloud-kit", App="api", Branch="main", Build="1"
        ),
    )

    action_details = task_payload.Actions
    state_details = task_payload.State

    y = YAML(typ="safe")
    y.allow_unicode = True
    y.default_flow_style = False

    magicS3 = MagicS3Client(
        region=action_details.BucketRegion, app_path=action_details.AppPath
    )

    # Create a sample action file for the test cases (teardown)
    action_list = [action.model_dump()]
    data = io.BytesIO()
    y.dump(action_list, data)
    magicS3.put_object(Key=action_details.Key, Body=data.getvalue())

    # Create a sample state file (context file) for the test cases
    magicS3 = MagicS3Client(
        region=action_details.BucketRegion, app_path=state_details.AppPath
    )

    fn = os.path.join(os.path.dirname(__file__), "test_context_state.yaml")
    with open(fn, "r") as f:
        data = f.read()
    magicS3.put_object(Key=state_details.Key, Body=data)

    return action


@pytest.mark.parametrize("http_path,expected_result", api_paths)
def test_app(  # noqa E302
    http_path, expected_result, bootstrap_dynamo, teardown_action
):

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

        assert response.status_code == expected_result[0]

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

    except Exception as e:
        assert False, f"Error: {e}"
