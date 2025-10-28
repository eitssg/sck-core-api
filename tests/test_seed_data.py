import os
from pathlib import Path

import pytest

import core_framework as util

from core_api.auth.tools import encrypt_credentials
from core_db.registry.client import ClientActions
from core_db.registry.zone import ZoneActions
from core_db.registry.portfolio import PortfolioActions
from core_db.registry.app import AppActions
from core_db.profile import ProfileActions

from .bootstrap import bootstrap_dynamo

oauth_client_secret_hash = os.getenv("CLIENT_SECRET")


@pytest.fixture(scope="session")
def seed_test_data(bootstrap_dynamo):

    CLIENT_FACTS_PATH = Path(__file__).with_name("facts-clients.yaml")
    _client_facts_payload = util.load_yaml_file(str(CLIENT_FACTS_PATH))
    client_facts = util.clean_yaml(_client_facts_payload["client_facts"])

    for fact in client_facts:
        if fact["client"] == "core":
            fact["client_secret"] = oauth_client_secret_hash
        ClientActions.create(**fact)

    ZONE_FACTS_PATH = Path(__file__).with_name("facts-zones.yaml")
    _zone_facts_payload = util.load_yaml_file(str(ZONE_FACTS_PATH))
    zone_facts = util.clean_yaml(_zone_facts_payload["zone_facts"])

    for fact in zone_facts:
        client = fact.pop("client")
        ZoneActions.create(client=client, **fact)

    PORTFOLIO_FACTS_PATH = Path(__file__).with_name("facts-portfolios.yaml")
    _portfolio_facts_payload = util.load_yaml_file(str(PORTFOLIO_FACTS_PATH))
    portfolio_facts = util.clean_yaml(_portfolio_facts_payload["portfolio_facts"])

    for fact in portfolio_facts:
        client = fact.pop("client")
        PortfolioActions.create(client=client, **fact)

    APPS_FACTS_PATH = Path(__file__).with_name("facts-apps.yaml")
    _apps_facts_payload = util.load_yaml_file(str(APPS_FACTS_PATH))
    app_facts = util.clean_yaml(_apps_facts_payload["app_facts"])

    for fact in app_facts:
        client = fact.pop("client")
        AppActions.create(client=client, **fact)

    PROFILES_FACTS_PATH = Path(__file__).with_name("facts-profiles.yaml")
    _profiles_facts_payload = util.load_yaml_file(str(PROFILES_FACTS_PATH))
    profile_facts = util.clean_yaml(_profiles_facts_payload["profile_facts"])

    seed_password = os.getenv("SEED_USER_PASSWORD", "Passw0rd!")
    for fact in profile_facts:
        client = fact.pop("client")
        fact["credentials"] = encrypt_credentials(password=seed_password)
        ProfileActions.create(client=client, **fact)

    return True


def test_seed_data(seed_test_data):
    assert seed_test_data
