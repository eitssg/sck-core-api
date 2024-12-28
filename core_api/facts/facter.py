"""
The Factor object is the "FACTS" database.  This object is DEPRECATED and should not be used.
This FACTS database should come from DynamoDB.  Not 'accounts.yaml' and 'apps.yaml' files.

(In re-rewrite.  We need to use DynamoDB instead of FACTS YAML files)
"""

from collections import ChainMap

import re
import core_framework as util
import core_logging as log

from core_framework.constants import (
    DD_TAGS,
    FACTS_ACCOUNT,
    FACTS_REGION,
    FACTS_TAGS,
    TAG_CAPEX_CODE,
    TAG_ENVIRONMENT,
    TAG_JIRA_CODE,
    TAG_OPEX_CODE,
    TAG_OWNER,
    TAG_REGION,
    V_DEFAULT_BRANCH,
    V_DEFAULT_ENVIRONMENT,
    V_DEFAULT_REGION_ALIAS,
)

from ..constants import APPROVERS, CONTACTS, OWNER, REGION, ENVIRONMENT, ZONE_KEY

from core_db.registry.client.models import ClientFacts
from core_db.registry.portfolio.models import PortfolioFacts
from core_db.registry.zone.models import ZoneFacts
from core_db.registry.app.models import AppFacts


from ..types import ActionHandlerRoutes
from ..constants import QUERY_STRING_PARAMETERS, PATH_PARAMETERS, BODY_PARAMETER

from core_db.facter.actions import FactsActions
from core_db.response import Response

from ..actions import ApiActions


class ApiFactsActions(ApiActions, FactsActions):
    pass


def get_client_facts(client: str) -> dict | None:

    try:

        facts = ClientFacts.get(client)
        if facts is None:
            return None
        return facts.to_simple_dict()

    except Exception as e:
        log.error(f"Error getting client facts: {str(e)}")
        return None


def get_portfolio_facts(client: str, portfolio: str) -> dict | None:

    try:

        portfolio_facts = PortfolioFacts.get(client, portfolio)
        if portfolio_facts is None:
            return None
        return portfolio_facts.to_simple_dict()

    except Exception as e:
        log.error(f"Error getting portfolio facts: {e}")
        return None


def get_zone_facts(client: str, portfolio: str, zone: str) -> dict | None:

    try:

        zone_key = f"{client}-{portfolio}"
        zone_facts = ZoneFacts.get(zone_key, zone)

        if zone_facts is None:
            return None
        return zone_facts.to_simple_dict()

    except Exception as e:
        log.error(f"Error getting zone facts: {e}")
        return None


def get_zone_facts_by_account_id(account_id: str) -> list[dict] | None:

    try:
        zone_facts = ZoneFacts.query(account_id)
        if zone_facts is None:
            return None
        return [zf.to_simple_dict() for zf in zone_facts]

    except Exception as e:
        log.error(f"Error getting zone facts by account ID: {e}")
        return None


def get_app_facts(
    client: str,
    portfolio: str,
    app: str,
    branch: str | None = None,
    build: str | None = None,
) -> dict | None:

    if branch is None:
        branch = "*"

    if build is None:
        build = "*"

    portfolio_key = f"{client}-{portfolio}"
    app_test_string = f"prn:{portfolio}:{app}:{branch}:{build}"

    app_facts_list = AppFacts.query(portfolio_key)

    for app_facts in app_facts_list:
        arx = app_facts.AppRegex
        if re.match(arx, app_test_string):
            return app_facts.to_simple_dict()

    return None


def derrive_environment_from_branch(branch: str) -> tuple[str, str]:
    """Derrive the environmet and region alias from the branch name.

    Example of a branch name is **dev-sin** or **feature1/dev-sin**

    Where *dev* is the environment and *sin* is the region alias.

    Args:
        branch (str): The application deployment git repository branch name.

    Returns:
        (environmet, region_alias): The environment and region alias tuple
    """
    parts = branch.split("-")

    if len(parts) >= 2:
        branch = parts[0]

        # split the branch by '/' and retreive the last part
        branch_parts = branch.split("/")
        environment = branch_parts[
            -1
        ]  # in this format, the branch name is the environment (master, main, dev, feature1/dev, etc)
        region_alias = parts[
            1
        ]  # override region_alias fact with the branch region alias definition
    else:
        environment = branch
        region_alias = V_DEFAULT_REGION_ALIAS

    # If you are deploying a master branch, you are definitly PRODUCTION
    if environment == "master" or environment == "main":
        environment = V_DEFAULT_ENVIRONMENT

    return environment, region_alias


def get_facts_by_identity(client: str, identity: str) -> dict:

    portfolio, app, branch, build, _ = util.split_prn(identity)
    return get_facts(client, portfolio or "unknown", app or "unknown", branch, build)


def get_facts(  # noqa: C901
    client: str,
    portfolio: str,
    app: str,
    branch: str | None = None,
    build: str | None = None,
    zone: str | None = None,
) -> dict:
    """
    Get the facts for a given app, portfolio, and zone.

    TODO: This function is too long and should be refactored.  And, portfolio and app should bo optional.

    Args:
        client (str): The client FACTS database to query.
        portfolio (str): BizApp (Business Applicatino) slug/id
        app (str): BizApp Deployment unit slug/id
        branch (str | None, optional): Repository branch name of the Deployment Unit. Defaults to None.
        build (str | None, optional): Repository Tag or Commit ID of the Deployment Unit. Defaults to None.
        zone (str | None, optional): Landing Zone for the Deployment. Defaults to None.

    Raises:
        ValueError: For any inconsistency

    Returns:
        dict: The Jinja2 template context dictionary. (a.k.a FACTS)
    """

    if branch is None:
        branch = V_DEFAULT_BRANCH

    app_facts = get_app_facts(client, portfolio, app, branch, build)

    if app_facts is None:
        raise ValueError(
            f"App facts not found for {client}-{portfolio}-{app}-{branch}-{build}"
        )

    # If the app facts do not contain a region, use the default region alias
    region_alias = app_facts.get(REGION, None)

    # if environment is not set, try to derrive it from the branch.  But facts ALWAYS come first.
    environment = app_facts.get(ENVIRONMENT, None)
    branch_region_alias = V_DEFAULT_REGION_ALIAS
    if not environment:
        environment, branch_region_alias = derrive_environment_from_branch(branch)

    # FACTS always override user input.  So, don't use the user input if FACTS are present.
    if region_alias is None:
        region_alias = branch_region_alias

    # If the app doen't have an environment tag or a region tag, add it
    app_tags = app_facts.get(DD_TAGS, {})
    if TAG_ENVIRONMENT not in app_tags:
        app_tags[TAG_ENVIRONMENT] = environment
    if TAG_REGION not in app_tags:
        app_tags[TAG_REGION] = region_alias

    portfolio_facts = get_portfolio_facts(client, portfolio)
    if portfolio_facts is None:
        raise ValueError(f"Portfolio facts not found for {client}-{portfolio}")

    if "opex-code" in portfolio_facts and TAG_OPEX_CODE not in app_tags:
        app_tags[TAG_OPEX_CODE] = portfolio_facts["opex-code"]
    if "jira-code" in portfolio_facts and TAG_JIRA_CODE not in app_tags:
        app_tags[TAG_JIRA_CODE] = portfolio_facts["jira-code"]
    if "capex-code" in portfolio_facts and TAG_CAPEX_CODE not in app_tags:
        app_tags[TAG_CAPEX_CODE] = portfolio_facts["capex-code"]
    if "owner" in portfolio_facts and TAG_OWNER not in app_tags:
        app_tags[TAG_OWNER] = portfolio_facts["owner"]

    # If a zone is not explicitely provded, we will generate the zone name from the portfolio and environment
    # Remember, all "apps/deployments" go inside the same environment of the portfololiw (a.k.a landing zone)
    zone = app_facts.get(
        ZONE_KEY, None
    )  # if the app facts have a zone, use it. It really must. It's required.
    if zone is None:
        zone = f"{portfolio}-{environment}"

    # If your zone has not been registered, contact DevOps to register it.  Retrieve the facts from the registry.
    zone_facts = get_zone_facts(client, portfolio, zone)

    if zone_facts is None or app_facts is None:
        raise ValueError(
            f"Account or app facts not found for {client}-{portfolio}-{app}"
        )

    # Merge in the zone tags into the app tags
    zone_tags = zone_facts.get(FACTS_TAGS, {})
    for key, value in zone_tags.items():
        if key not in app_tags:
            app_tags[key] = value

    if FACTS_ACCOUNT not in zone_facts or FACTS_REGION not in zone_facts:
        raise ValueError(f"Account or region facts not found for {zone}")

    # Extract account facts and region-specific facts
    account_facts = zone_facts[FACTS_ACCOUNT]
    region_facts = zone_facts[FACTS_REGION].get(region_alias, None)

    if region_facts is None:
        raise ValueError(f"Region {region_alias} has not been enabled for {zone}")

    # Merge account facts and region-specific facts into facts dict
    facts = util.merge.deep_merge(account_facts, region_facts, merge_lists=True)

    # Merge app facts into facts dict
    facts = util.merge.deep_merge(facts, app_facts, merge_lists=True)

    if APPROVERS not in facts:
        facts[APPROVERS] = portfolio_facts.get("approvers", [])
    if CONTACTS not in facts:
        facts[CONTACTS] = portfolio_facts.get("contacts", [])
    if OWNER not in facts and "owner" in portfolio_facts:
        facts[OWNER] = portfolio_facts.get("owner")

    return facts


def get_facts_action(**kwargs) -> Response:
    """
    API Documentation:
    ----------------
    GET /api/v1/facts
        Retrieves facts for a given Pipeline Reference Number (PRN).

        Query Parameters:
            prn (string): Pipeline Reference Number in format prn:p:a:b:n where:
                p = portfolio
                a = application
                b = branch
                n = build number

        Response:
            200 OK
            {
                "AccountFacts": {
                    "AwsAccountId": "123456789012",
                    "AwsAccountName": "example-account"
                },
                "RegionFacts": {
                    "AwsRegion": "ap-southeast-1",
                    "RegionAlias": "sin"
                },
                "DD_TAGS": {
                    "client": "example-client",
                    "portfolio": "example-portfolio",
                    "app": "example-app",
                    "branch": "main",
                    "build": "123",
                    "environment": "prod",
                    "region": "sin",
                    "zone": "example-zone",
                    "owner": "team@example.com",
                    "opex-code": "OPEX123",
                    "capex-code": "CAPEX456",
                    "jira-code": "PROJ"
                },
                "Approvers": ["approver1@example.com"],
                "Contacts": ["contact1@example.com"],
                "Owner": "owner@example.com"
            }

            400 Bad Request
            {
                "error": "Invalid PRN format"
            }

            404 Not Found
            {
                "error": "Facts not found for given PRN"
            }
    """
    qsp = kwargs.get(QUERY_STRING_PARAMETERS, None) or {}
    pp = kwargs.get(PATH_PARAMETERS, None) or {}
    body = kwargs.get(BODY_PARAMETER, None) or {}
    return ApiFactsActions.get(**dict(ChainMap(body, pp, qsp)))


# Define API Gateway routes
facts_actions: ActionHandlerRoutes = {"GET:/api/v1/facts/{client}": get_facts_action}
