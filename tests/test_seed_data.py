import os

from core_db.registry.client import ClientFact, ClientActions
from core_db.registry.zone import ZoneFact, ZoneActions
from core_db.registry.portfolio import PortfolioFact, PortfolioActions
from core_db.registry.app import AppFact, AppActions
from core_db.profile import ProfileActions
from core_db.profile import UserProfile

from .bootstrap import *

client = os.getenv("CLIENT")
client_id = os.getenv("CLIENT_ID")
client_secret = os.getenv("CLIENT_SECRET")
client_redirect_uri = os.getenv("CLIENT_CALLBACK")
client_secret_hash = "31617f564fcc8688b8914655b72437dc31e93a7c498d0ebe94eef55af1b9f986"

###############################
# Infrastructure definitions
###############################

client_facts = [
    {
        "client": client,  # slug
        "client_id": client_id,
        "client_secret": client_secret_hash,
        "client_name": "Core Automation Team",
        "client_redirect_urls": [uri.strip() for uri in client_redirect_uri.split(",")],
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
        "app_regex": "^prn:core-automation:api-[^:]*:main:[^:].*$",
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
        "app_regex": "^prn:core-automation:api-[^:]*:develop:[^:].*$",
        "name": "sck-core-api",
        "zone": "core-automation-development",
        "environment": "dev",
        "region": "us-east-1",
        "metadata": {
            "description": "Core Automation API lambda function. Handles API requests and responses.",
        },
    },
]

administrator = {
    "user_id": "jbarwick@eits.com.sg",
    "profile_name": "default",
    "display_name": "Administrator",
    "email": "jbarwick@eits.com.sg",
    "timezone": "GMT+8",
    "language": "en",
    "theme": "dark",
    "notifications_enabled": True,
    "preferred_region": "en",
    "permissions": {
        "*": ["read", "write", "delete", "admin"],
        "aws": [
            "credentials:read",
            "credentials:write",
            "resources:read",
            "resources:write",
        ],
        "billing": ["read", "write", "admin"],
        "admin": ["user:manage", "client:manage", "system:config"],
        "features": ["dashboard:advanced", "analytics", "billing:module"],
    },
    "is_active": True,
}


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

    results = ProfileActions.create(**administrator)
    profile = UserProfile(**results.data)
    print(profile.model_dump_json(indent=2))
