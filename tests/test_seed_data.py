from core_db.registry.client import ClientFact, ClientActions
from core_db.registry.zone import ZoneFact, ZoneActions
from core_db.registry.portfolio import PortfolioFact, PortfolioActions
from core_db.registry.app import AppFact, AppActions

from .bootstrap import *

client = util.get_client()


###############################
# Infrastructure definitions
###############################

client_facts = [
    {
        "client": client,  # slug
        "name": "Core Automation Team",
    }
]

zone_facts = [
    {
        "client": client,  # slug
        "zone": "core-automation-production",  # lowercase name
        "account_facts": {"aws_account_id": "123456789012"},
        "region_facts": {"us-east-1": {"aws_region": "us-east-1"}},
    },
    {
        "client": client,  # slug
        "zone": "core-automation-staging",
        "account_facts": {"aws_account_id": "123456789012"},
        "region_facts": {"us-east-1": {"aws_region": "us-east-1"}},
    },
    {
        "client": client,  # slug
        "zone": "core-automation-development",
        "account_facts": {"aws_account_id": "123456789012"},
        "region_facts": {"us-east-1": {"aws_region": "us-east-1"}},
    },
]


################################
# Application Definitions
################################

portfolio_facts = [
    {
        "client": client,  # slug
        "portfolio": "core-automation",  # slug
        "name": "Core Automation Engine",
        "project": {"code": "CORE", "name": "Core Automation"},
    }
]

############################
# Deployments
############################

prod_app_facts = [
    {
        "client": client,  # slug
        "portfolio": "core-automation",
        "app_regex": "^prn:core-automation:execute:main:[^:].*$",
        "name": "sck-core-execute",
        "zone": "core-automation-production",
        "environment": "prod",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation Action Library Lambda step-function",
        },
    },
    {
        "client": client,  # slug
        "portfolio": "core-automation",
        "app_regex": "^prn:core-automation:report:main:[^:].*$",
        "name": "sck-core-report",
        "zone": "core-automation-production",
        "environment": "prod",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation CodeCommit status report function",
        },
    },
    {
        "client": client,  # slug
        "portfolio": "core-automation",
        "app_regex": "^prn:core-automation:runner:main:[^:].*$",
        "name": "sck-core-runner",
        "zone": "core-automation-production",
        "environment": "prod",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation Runner.  A lambda function that runs the sck-core-execute Lambda step function",
        },
    },
    {
        "client": client,  # slug
        "portfolio": "core-automation",
        "app_regex": "^prn:core-automation:deployspec:main:[^:].*$",
        "name": "sck-core-deployspec",
        "zone": "core-automation-production",
        "environment": "prod",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation Deployment Specification template compiler.",
        },
    },
    {
        "client": client,  # slug
        "portfolio": "core-automation",
        "app_regex": "^prn:core-automation:component:main:[^:].*$",
        "name": "sck-core-component",
        "zone": "core-automation-production",
        "environment": "prod",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation Component Library template compiler.",
        },
    },
    {
        "client": client,  # slug
        "portfolio": "core-automation",
        "app_regex": "^prn:core-automation:invoker:main:[^:].*$",
        "name": "sck-core-invoker",
        "zone": "core-automation-production",
        "environment": "prod",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation Invoker determines if a task should run deployspec, component, or runner.",
        },
    },
    {
        "client": client,  # slug
        "portfolio": "core-automation",
        "app_regex": "^prn:core-automation:organization:main:[^:].*$",
        "name": "sck-core-organization",
        "zone": "core-automation-production",
        "environment": "prod",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation Organization Manaagement",
        },
    },
    {
        "client": client,  # slug
        "portfolio": "core-automation",
        "app_regex": "^prn:core-automation:api:main:[^:].*$",
        "name": "sck-core-api",
        "zone": "core-automation-production",
        "environment": "prod",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation API lambda function. Handles API requests and responses.",
        },
    },
]

dev_app_facts = [
    {
        "client": client,  # slug
        "portfolio": "core-automation",
        "app_regex": "^prn:core-automation:execute:develop:[^:].*$",
        "name": "sck-core-execute",
        "zone": "core-automation-development",
        "environment": "dev",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation Action Library Lambda step-function",
        },
    },
    {
        "client": client,  # slug
        "portfolio": "core-automation",
        "app_regex": "^prn:core-automation:report:develop:[^:].*$",
        "name": "sck-core-report",
        "zone": "core-automation-development",
        "environment": "dev",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation CodeCommit status report function",
        },
    },
    {
        "client": client,  # slug
        "portfolio": "core-automation",
        "app_regex": "^prn:core-automation:runner:develop:[^:].*$",
        "name": "sck-core-runner",
        "zone": "core-automation-development",
        "environment": "dev",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation Runner.  A lambda function that runs the sck-core-execute Lambda step function",
        },
    },
    {
        "client": client,  # slug
        "portfolio": "core-automation",
        "app_regex": "^prn:core-automation:deployspec:develop:[^:].*$",
        "name": "sck-core-deployspec",
        "zone": "core-automation-development",
        "environment": "dev",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation Deployment Specification template compiler.",
        },
    },
    {
        "client": client,  # slug
        "portfolio": "core-automation",
        "app_regex": "^prn:core-automation:component:develop:[^:].*$",
        "name": "sck-core-component",
        "zone": "core-automation-development",
        "environment": "dev",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation Component Library template compiler.",
        },
    },
    {
        "client": client,  # slug
        "portfolio": "core-automation",
        "app_regex": "^prn:core-automation:invoker:develop:[^:].*$",
        "name": "sck-core-invoker",
        "zone": "core-automation-development",
        "environment": "dev",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation Invoker determines if a task should run deployspec, component, or runner.",
        },
    },
    {
        "client": client,  # slug
        "portfolio": "core-automation",
        "app_regex": "^prn:core-automation:organization:develop:[^:].*$",
        "name": "sck-core-organization",
        "zone": "core-automation-development",  # fixed: was production
        "environment": "dev",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation Organization Management",
        },
    },
    {
        "client": client,  # slug
        "portfolio": "core-automation",
        "app_regex": "^prn:core-automation:api:develop:[^:].*$",
        "name": "sck-core-api",
        "zone": "core-automation-development",
        "environment": "dev",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation API lambda function. Handles API requests and responses.",
        },
    },
]


def test_seed_data(bootstrap_dynamo):
    # Create test data for clients
    for fact in client_facts:
        result = ClientActions.create(**fact)
        client_fact = ClientFact(**result.data)
        print(client_fact.model_dump_json(indent=2))

    # Create test data for zones
    for fact in zone_facts:
        result = ZoneActions.create(**fact)
        zone_fact = ZoneFact(**result.data)
        print(zone_fact.model_dump_json(indent=2))

    # Create test data for portfolios
    for fact in portfolio_facts:
        result = PortfolioActions.create(**fact)
        portfolio_fact = PortfolioFact(**result.data)
        print(portfolio_fact.model_dump_json(indent=2))

    # Create deployments (prod)
    for fact in prod_app_facts:
        results = AppActions.create(**fact)
        app_fact = AppFact(**results.data)
        print(app_fact.model_dump_json(indent=2))

    # Create deployments (dev)
    for fact in dev_app_facts:
        results = AppActions.create(**fact)
        app_fact = AppFact(**results.data)
        print(app_fact.model_dump_json(indent=2))
