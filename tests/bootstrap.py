import pytest

import boto3

from .conftest import *

import core_framework as util

from core_db.event import EventModelFactory
from core_db.item import ItemModelFactory
from core_db.registry.client import ClientFactsFactory
from core_db.registry.portfolio import PortfolioFactsFactory
from core_db.registry.app import AppFactsFactory
from core_db.registry.zone import ZoneFactsFactory

import core_logging as log


@pytest.fixture(scope="module")
def bootstrap_dynamo():

    # see environment variables in .env
    host = util.get_dynamodb_host()

    assert (
        host == "http://localhost:8000"
    ), "DYNAMODB_HOST must be set to http://localhost:8000"

    try:

        client = util.get_client()

        dynamodb = boto3.resource("dynamodb", endpoint_url=host)

        tables = dynamodb.tables.all()
        if tables:
            # delete all tables
            for table in tables:
                log.debug(f"Deleting table: {table.name}")
                table.delete()
                table.wait_until_not_exists()
                log.debug(f"Table {table.name} deleted successfully.")

        ClientFactsFactory.get_model(client, True)
        PortfolioFactsFactory.get_model(client, True)
        AppFactsFactory.get_model(client, True)
        ZoneFactsFactory.get_model(client, True)
        ItemModelFactory.get_model(client, True)
        EventModelFactory.get_model(client, True)

    except Exception as e:
        log.error(f"Error during bootstrap: {e}")
        assert False

    return True
