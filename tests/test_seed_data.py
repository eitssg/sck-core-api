from typing import Any
import os
from pathlib import Path

import core_framework as util

from core_db.registry.client import ClientActions
from core_db.registry.zone import ZoneActions
from core_db.registry.portfolio import PortfolioActions
from core_db.registry.app import AppActions
from core_db.profile import ProfileActions

from ruamel.yaml.scalarbool import ScalarBoolean
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.scalarfloat import ScalarFloat
from ruamel.yaml.scalarint import ScalarInt
from ruamel.yaml.scalarstring import FoldedScalarString, LiteralScalarString, DoubleQuotedScalarString

from .bootstrap import *

oauth_client_secret_hash = os.getenv("CLIENT_SECRET")


def _clean_data(data: Any) -> Any:
    """Recursively convert ruamel containers/scalars into plain Python types."""

    if isinstance(data, CommentedMap):
        return {str(key): _clean_data(value) for key, value in data.items()}

    if isinstance(data, CommentedSeq):
        return [_clean_data(item) for item in data]

    if isinstance(data, ScalarBoolean):
        return bool(data)

    if isinstance(data, ScalarFloat):
        return float(data)

    if isinstance(data, ScalarInt):
        return int(data)

    if isinstance(data, (FoldedScalarString, LiteralScalarString, DoubleQuotedScalarString)):
        return str(data)

    if isinstance(data, list):
        return [_clean_data(item) for item in data]

    if isinstance(data, dict):
        return {str(key): _clean_data(value) for key, value in data.items()}

    return data


CLIENT_FACTS_PATH = Path(__file__).with_name("facts-clients.yaml")
_client_facts_payload = util.load_yaml_file(str(CLIENT_FACTS_PATH))
client_facts = _clean_data(_client_facts_payload["client_facts"])

ZONE_FACTS_PATH = Path(__file__).with_name("facts-zones.yaml")
_zone_facts_payload = util.load_yaml_file(str(ZONE_FACTS_PATH))
zone_facts = _clean_data(_zone_facts_payload["zone_facts"])


PORTFOLIO_FACTS_PATH = Path(__file__).with_name("facts-portfolios.yaml")
_portfolio_facts_payload = util.load_yaml_file(str(PORTFOLIO_FACTS_PATH))
portfolio_facts = _clean_data(_portfolio_facts_payload["portfolio_facts"])

APPS_FACTS_PATH = Path(__file__).with_name("facts-apps.yaml")
_apps_facts_payload = util.load_yaml_file(str(APPS_FACTS_PATH))
app_facts = _clean_data(_apps_facts_payload["app_facts"])

PROFILES_FACTS_PATH = Path(__file__).with_name("facts-profiles.yaml")
_profiles_facts_payload = util.load_yaml_file(str(PROFILES_FACTS_PATH))
profile_facts = _clean_data(_profiles_facts_payload["profile_facts"])


def test_seed_data(bootstrap_dynamo):
    # Create test data for clients
    for fact in client_facts:
        if fact["client"] == "core":  # Only 'core' is the oauth client
            fact["client_secret"] = oauth_client_secret_hash  # will set after creation
        client_fact = ClientActions.create(**fact)
        print(client_fact.model_dump_json(indent=2))

    # Create test data for zones
    for fact in zone_facts:
        client = fact.pop("client")  # client is not part of the fact, it's part of the table name
        zone_fact = ZoneActions.create(client=client, **fact)
        print(zone_fact.model_dump_json(indent=2))

    # Create test data for portfolios
    for fact in portfolio_facts:
        client = fact.pop("client")  # client is not part of the fact, it's part of the table name
        portfolio_fact = PortfolioActions.create(client=client, **fact)
        print(portfolio_fact.model_dump_json(indent=2))

    # Create deployments (prod/dev)
    for fact in app_facts:
        client = fact.pop("client")  # client is not part of the fact, it's part of the table name
        app_fact = AppActions.create(client=client, **fact)
        print(app_fact.model_dump_json(indent=2))

    for fact in profile_facts:
        client = fact.pop("client")
        profile = ProfileActions.create(client=client, **fact)
        print(profile.model_dump_json(indent=2))
