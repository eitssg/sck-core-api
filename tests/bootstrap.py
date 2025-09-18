import pytest

from .conftest import *

import core_framework as util

from core_db.event import EventModelFactory
from core_db.item.portfolio.models import PortfolioModelFactory
from core_db.registry.client.models import ClientFactsFactory
from core_db.registry.portfolio.models import PortfolioFactsFactory
from core_db.registry.app.models import AppFactsFactory
from core_db.registry.zone.models import ZoneFactsFactory
from core_db.profile.model import ProfileModelFactory
from core_db.oauth.models import AuthorizationsModelFactory
from core_db.passkey.passkeys import PassKeysModelFactory

import core_logging as log


def _delete_client_tables(client: str) -> None:
    try:
        if PortfolioModelFactory.exists(client):
            PortfolioModelFactory.delete_table(client, wait=True)

        if ZoneFactsFactory.exists(client):
            ZoneFactsFactory.delete_table(client, wait=True)

        if AppFactsFactory.exists(client):
            AppFactsFactory.delete_table(client, wait=True)

        if PortfolioFactsFactory.exists(client):
            PortfolioFactsFactory.delete_table(client, wait=True)

        if EventModelFactory.exists(client):
            EventModelFactory.delete_table(client, wait=True)

        if ProfileModelFactory.exists(client):
            ProfileModelFactory.delete_table(client, wait=True)

    except Exception as e:
        log.error(f"Error during bootstrap: {e}")
        assert False


def _create_client_tables(client: str) -> None:
    """Create "Tenant" Client tables"""
    PortfolioModelFactory.create_table(client, wait=True)
    ZoneFactsFactory.create_table(client, wait=True)
    AppFactsFactory.create_table(client, wait=True)
    PortfolioFactsFactory.create_table(client, wait=True)
    EventModelFactory.create_table(client, wait=True)
    ProfileModelFactory.create_table(client, wait=True)


def _create_global_tables():
    """
    Create "Global" tables
    """
    client = "core"
    if ClientFactsFactory.exists(client):
        ClientFactsFactory.delete_table(client, wait=True)

    if AuthorizationsModelFactory.exists(client):
        AuthorizationsModelFactory.delete_table(client, wait=True)

    if PassKeysModelFactory.exists(client):
        PassKeysModelFactory.delete_table(client, wait=True)

    ClientFactsFactory.create_table(client, wait=True)
    AuthorizationsModelFactory.create_table(client, wait=True)
    PassKeysModelFactory.create_table(client, wait=True)


@pytest.fixture(scope="module")
def bootstrap_dynamo():

    # see environment variables in .env
    host = util.get_dynamodb_host()

    assert host == "http://localhost:8000", "DYNAMODB_HOST must be set to http://localhost:8000"

    try:

        _create_global_tables()

        clients = ["core", "acme", "beta"]  # Example clients for fun.

        for client in clients:
            _delete_client_tables(client)
            _create_client_tables(client)

    except Exception as e:
        log.error(f"Error during bootstrap: {e}")
        assert False

    return True
