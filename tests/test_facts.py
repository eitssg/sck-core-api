import pytest

from fastapi.testclient import TestClient

import core_framework as util

from core_db.event.models import EventModel
from core_db.item.models import ItemModel
from core_db.registry.client.models import ClientFacts
from core_db.registry.portfolio.models import PortfolioFacts
from core_db.registry.app.models import AppFacts
from core_db.registry.zone.models import ZoneFacts

from core_api.api.fast_api import get_app

from .test_facts_data import api_paths

from .bootstrap import *

# Create a FastAPI test client the same that unvicorn will use
client = TestClient(get_app())


def compare_list(item1: list, item2: list):
    """Compare two lists

    Asserts that the two lists are the same length and that each element is the same

    Args:
        item1 (list): The first list (Expected Data)
        item2 (list): The second list (Actual Data)

    """
    assert len(item1) == len(item2), f"Length: {len(item1)}"
    for i in range(len(item1)):
        if isinstance(item1[i], dict):
            compare_dict(item1[i], item2[i])
        elif isinstance(item1[i], list):
            compare_list(item1[i], item2[i])
        else:
            assert item1[i] == item2[i], f"Key: {i}, {item1}"


def compare_dict(item1: dict, item2: dict):
    """Compare two dictionaries

    Asserts that the two dictionaries have the same keys and values.

    This only looks at item1 keys.  So, if item2 has more keys, they are ignored.
    This allows "actual data" to have more data than "expected data" so you
    can inspect specific elements only.

    Args:
        item1 (dict): The first dictionary (Expected Data)
        item2 (dict): The second dictionary (Actual Data)
    """

    for k, v in item1.items():
        if isinstance(v, dict):
            compare_dict(v, item2[k])
        elif isinstance(v, list):
            compare_list(v, item2[k])
        else:
            assert v == item2[k], f"Key: {k}, {item1}"


@pytest.mark.parametrize("http_path,expected_result", api_paths)
def test_the_facts(http_path, expected_result, bootstrap_dynamo):  # noqa E302

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

        if response.status_code == 404:
            assert False, "Data not found - error 404"

        if response.status_code != expected_result[0]:
            assert False, response_envelope["data"]["message"]

        assert "status" in response_envelope
        assert response_envelope["status"] == expected_response["status"]
        assert "code" in response_envelope
        assert response_envelope["code"] == expected_response["code"]

        response_data = response_envelope.get("data", None)

        expected_data = expected_response.get("data", None)

        # Jeeze... replace this with recursive function!
        if isinstance(expected_data, dict):
            compare_dict(expected_data, response_data)

        elif isinstance(expected_data, list):
            compare_list(expected_data, response_data)

        elif isinstance(expected_data, str):
            assert expected_data == response_data

    except Exception as e:
        assert False, f"Error: {e}"
