import os

from core_db.registry.client import ClientFact, ClientActions
from core_db.registry.zone import ZoneFact, ZoneActions
from core_db.registry.portfolio import PortfolioFact, PortfolioActions
from core_db.registry.app import AppFact, AppActions
from core_db.profile import ProfileActions
from core_db.profile import UserProfile

from .bootstrap import *

client_slug = os.getenv("CLIENT", "core")

oauth_client_id = os.getenv("CLIENT_ID")
oauth_client_secret = os.getenv("CLIENT_SECRET")
oauth_client_redirect_uri = os.getenv("CLIENT_CALLBACK")
oauth_client_secret_hash = None

###############################
# Infrastructure definitions
###############################

client_facts = [
    {
        "client": client_slug,  # slug
        "client_id": oauth_client_id,
        "client_secret": oauth_client_secret_hash,
        "client_name": "Core Automation Team",
        "client_description": "Core Automation Infrastructure Automation Team",
        "client_status": "active",
        "client_type": "enterprise",
        "client_scopes": ["openid", "profile", "email", "offline_access"],
        "organization_name": "EITS Pte Ltd",
        "organization_id": "o-1234567890",
        "organization_account": "123456789012",
        "organization_email": "admin@eits.com.sg",
        "domain": "eits.com.sg",
        "homepage": "https://www.eits.com.sg",
        "iam_account": "123456789012",
        "audit_account": "123456789012",
        "automation_account": "123456789012",
        "security_account": "123456789012",
        "network_account": "123456789012",
        "master_region": "us-east-1",
        "client_region": "us-east-1",
        "bucket_region": "us-east-1",
        "bucket_name": f"{client_slug}-automation",
        "docs_bucket_name": f"{client_slug}-docs",
        "artefact_bucket_name": f"{client_slug}-artefacts",
        "ui_bucket_name": f"{client_slug}-ui",
        "ui_bucket": f"{client_slug}-ui",
        "scope": "ca-",
        "client_redirect_urls": [uri.strip() for uri in oauth_client_redirect_uri.split(",")],
        "tags": {"Client": "core"},
        "tag_policy": [
            {"tag_name": "Client", "required": True, "description": "Client identifier or tenant name"},
            {"tag_name": "Portfolio", "required": True, "description": "Portfolio or project name"},
            {"tag_name": "App", "required": True, "description": "Application name"},
            {"tag_name": "Branch", "required": False, "description": "Source code branch"},
            {"tag_name": "Build", "required": False, "description": "Build version or identifier"},
            {"tag_name": "Environment", "required": False, "description": "Environment (e.g. dev, staging, prod)"},
            {"tag_name": "Region", "required": False, "description": "AWS region"},
            {"tag_name": "Team", "required": False, "description": "Team or department"},
            {"tag_name": "Owner", "required": False, "description": "Resource owner"},
            {"tag_name": "Project", "required": False, "description": "Project code or identifier"},
            {"tag_name": "CostCenter", "required": False, "description": "Cost center code"},
            {"tag_name": "Confidentiality", "required": False, "description": "Data confidentiality level"},
            {"tag_name": "Tier", "required": False, "description": "Application tier or level"},
            {"tag_name": "Compliance", "required": False, "description": "Compliance requirements"},
            {"tag_name": "Criticality", "required": False, "description": "Business criticality level"},
            {"tag_name": "Lifecycle", "required": False, "description": "Resource lifecycle stage"},
            {"tag_name": "Version", "required": False, "description": "Resource version"},
            {"tag_name": "Purpose", "required": False, "description": "Resource purpose or function"},
            {"tag_name": "Confidentiality", "required": False, "description": "Data confidentiality level"},
        ],
    },
    {
        "client": "acme",  # slug
        "client_id": oauth_client_id,
        "client_secret": oauth_client_secret_hash,
        "client_name": "Acme Group",
        "client_description": "Acme Group for developing AI services",
        "client_status": "active",
        "client_type": "enterprise",
        "client_scopes": ["openid", "profile", "email", "offline_access"],
        "organization_name": "Acme Corporation",
        "organization_id": "o-acme000001",
        "organization_account": "210987654321",
        "organization_email": "admin@acme.com",
        "domain": "acme.com",
        "homepage": "https://www.acme.com",
        "iam_account": "210987654321",
        "audit_account": "210987654321",
        "automation_account": "210987654321",
        "security_account": "210987654321",
        "network_account": "210987654321",
        "master_region": "us-east-1",
        "client_region": "us-east-1",
        "bucket_region": "us-east-1",
        "bucket_name": "acme-automation",
        "docs_bucket_name": "acme-docs",
        "artefact_bucket_name": "acme-artefacts",
        "ui_bucket_name": "acme-ui",
        "ui_bucket": "acme-ui",
        "scope": "ac-",
        "client_redirect_urls": [uri.strip() for uri in oauth_client_redirect_uri.split(",")],
    },
    {
        "client": "beta",  # slug
        "client_id": oauth_client_id,
        "client_secret": oauth_client_secret_hash,
        "client_name": "Beta Group",
        "client_description": "Beta Group for developing Robotics services",
        "client_status": "active",
        "client_type": "startup",
        "client_scopes": ["openid", "profile", "email", "offline_access"],
        "organization_name": "Beta Corporation",
        "organization_id": "o-beta000001",
        "organization_account": "345678901234",
        "organization_email": "admin@beta.com",
        "domain": "beta.com",
        "homepage": "https://www.beta.com",
        "iam_account": "345678901234",
        "audit_account": "345678901234",
        "automation_account": "345678901234",
        "security_account": "345678901234",
        "network_account": "345678901234",
        "master_region": "us-east-1",
        "client_region": "us-east-1",
        "bucket_region": "us-east-1",
        "bucket_name": "beta-automation",
        "docs_bucket_name": "beta-docs",
        "artefact_bucket_name": "beta-artefacts",
        "ui_bucket_name": "beta-ui",
        "ui_bucket": "beta-ui",
        "scope": "be-",
        "client_redirect_urls": [uri.strip() for uri in oauth_client_redirect_uri.split(",")],
    },
]

zone_facts = [
    {
        "client": client_slug,  # slug
        "zone": "core-automation-production",  # lowercase name
        "account_facts": {
            "organizational_unit": "Core",
            "aws_account_id": "123456789012",
            "account_name": "Core Automation Production",
            "environment": "prod",
            "kms": {
                "aws_account_id": "123456789012",
                "delegate_aws_account_ids": ["123456789012"],
                "allow_sns": True,
            },
            "resource_namespace": "core-automation",
            "network_name": "core-automation-network",
            "vpc_aliases": ["vpc-main"],
            "subnet_aliases": ["subnet-public", "subnet-private"],
            "tags": {"Environment": "production", "Owner": "platform-team"},
        },
        "region_facts": {
            "us-east-1": {
                "aws_region": "us-east-1",
                "az_count": 3,
                "image_aliases": {"ubuntu-22": "ami-ubuntu22", "amazon-linux-2": "ami-amzn2"},
                "min_successful_instances_percent": 100,
                "security_aliases": {
                    "corporate-cidrs": [{"type": "CIDR", "value": "10.0.0.0/8", "description": "Corporate network"}]
                },
                "security_group_aliases": {"web": "sg-web", "db": "sg-db"},
                "proxy_host": "proxy.internal",
                "proxy_port": 8080,
                "proxy_url": "http://proxy.internal:8080",
                "no_proxy": "*.internal,10.0.0.0/8",
                "name_servers": ["8.8.8.8", "1.1.1.1"],
                "tags": {"Environment": "production", "Region": "us-east-1"},
            }
        },
        "tags": {"ZoneType": "production", "Owner": "platform-team"},
    },
    {
        "client": client_slug,  # slug
        "zone": "core-automation-staging",
        "account_facts": {
            "organizational_unit": "Core",
            "aws_account_id": "123456789012",
            "account_name": "Core Automation Staging",
            "environment": "staging",
            "kms": {
                "aws_account_id": "123456789012",
                "delegate_aws_account_ids": ["123456789012"],
                "allow_sns": True,
            },
            "resource_namespace": "core-automation",
            "network_name": "core-automation-network",
            "vpc_aliases": ["vpc-main"],
            "subnet_aliases": ["subnet-public", "subnet-private"],
            "tags": {"Environment": "staging", "Owner": "platform-team"},
        },
        "region_facts": {
            "us-east-1": {
                "aws_region": "us-east-1",
                "az_count": 2,
                "image_aliases": {"ubuntu-22": "ami-ubuntu22", "amazon-linux-2": "ami-amzn2"},
                "min_successful_instances_percent": 90,
                "security_aliases": {
                    "corporate-cidrs": [{"type": "CIDR", "value": "10.0.0.0/8", "description": "Corporate network"}]
                },
                "security_group_aliases": {"web": "sg-web", "db": "sg-db"},
                "proxy_host": "proxy.internal",
                "proxy_port": 8080,
                "proxy_url": "http://proxy.internal:8080",
                "no_proxy": "*.internal,10.0.0.0/8",
                "name_servers": ["8.8.4.4", "1.0.0.1"],
                "tags": {"Environment": "staging", "Region": "us-east-1"},
            }
        },
        "tags": {"ZoneType": "staging", "Owner": "platform-team"},
    },
    {
        "client": client_slug,  # slug
        "zone": "core-automation-development",
        "account_facts": {
            "organizational_unit": "Core",
            "aws_account_id": "123456789012",
            "account_name": "Core Automation Development",
            "environment": "dev",
            "kms": {
                "aws_account_id": "123456789012",
                "delegate_aws_account_ids": ["123456789012"],
                "allow_sns": True,
            },
            "resource_namespace": "core-automation",
            "network_name": "core-automation-network",
            "vpc_aliases": ["vpc-main"],
            "subnet_aliases": ["subnet-public", "subnet-private"],
            "tags": {"Environment": "development", "Owner": "platform-team"},
        },
        "region_facts": {
            "us-east-1": {
                "aws_region": "us-east-1",
                "az_count": 2,
                "image_aliases": {"ubuntu-22": "ami-ubuntu22", "amazon-linux-2": "ami-amzn2"},
                "min_successful_instances_percent": 75,
                "security_aliases": {
                    "corporate-cidrs": [{"type": "CIDR", "value": "10.0.0.0/8", "description": "Corporate network"}]
                },
                "security_group_aliases": {"web": "sg-web", "db": "sg-db"},
                "proxy_host": "proxy.internal",
                "proxy_port": 8080,
                "proxy_url": "http://proxy.internal:8080",
                "no_proxy": "*.internal,10.0.0.0/8",
                "name_servers": ["9.9.9.9", "149.112.112.112"],
                "tags": {"Environment": "development", "Region": "us-east-1"},
            }
        },
        "tags": {"ZoneType": "development", "Owner": "platform-team"},
    },
    {
        "client": "acme",  # slug
        "zone": "acme-production",
        "account_facts": {
            "organizational_unit": "Acme",
            "aws_account_id": "210987654321",
            "account_name": "Acme Production",
            "environment": "prod",
            "kms": {
                "aws_account_id": "210987654321",
                "delegate_aws_account_ids": ["210987654321"],
                "allow_sns": True,
            },
            "resource_namespace": "acme",
            "network_name": "acme-network",
            "vpc_aliases": ["vpc-main"],
            "subnet_aliases": ["subnet-public", "subnet-private"],
            "tags": {"Environment": "production", "Owner": "platform-team"},
        },
        "region_facts": {
            "us-east-1": {
                "aws_region": "us-east-1",
                "az_count": 3,
                "image_aliases": {"ubuntu-22": "ami-ubuntu22", "amazon-linux-2": "ami-amzn2"},
                "min_successful_instances_percent": 100,
                "security_aliases": {
                    "corporate-cidrs": [{"type": "CIDR", "value": "10.0.0.0/8", "description": "Corporate network"}]
                },
                "security_group_aliases": {"web": "sg-web", "db": "sg-db"},
                "proxy_host": "proxy.internal",
                "proxy_port": 8080,
                "proxy_url": "http://proxy.internal:8080",
                "no_proxy": "*.internal,10.0.0.0/8",
                "name_servers": ["8.8.8.8", "1.1.1.1"],
                "tags": {"Environment": "production", "Region": "us-east-1"},
            }
        },
        "tags": {"ZoneType": "production", "Owner": "platform-team"},
    },
    {
        "client": "beta",  # slug
        "zone": "beta-development",
        "account_facts": {
            "organizational_unit": "Beta",
            "aws_account_id": "345678901234",
            "account_name": "Beta Development",
            "environment": "dev",
            "kms": {
                "aws_account_id": "345678901234",
                "delegate_aws_account_ids": ["345678901234"],
                "allow_sns": True,
            },
            "resource_namespace": "beta",
            "network_name": "beta-network",
            "vpc_aliases": ["vpc-main"],
            "subnet_aliases": ["subnet-public", "subnet-private"],
            "tags": {"Environment": "development", "Owner": "platform-team"},
        },
        "region_facts": {
            "us-east-1": {
                "aws_region": "us-east-1",
                "az_count": 2,
                "image_aliases": {"ubuntu-22": "ami-ubuntu22", "amazon-linux-2": "ami-amzn2"},
                "min_successful_instances_percent": 75,
                "security_aliases": {
                    "corporate-cidrs": [{"type": "CIDR", "value": "10.0.0.0/8", "description": "Corporate network"}]
                },
                "security_group_aliases": {"web": "sg-web", "db": "sg-db"},
                "proxy_host": "proxy.internal",
                "proxy_port": 8080,
                "proxy_url": "http://proxy.internal:8080",
                "no_proxy": "*.internal,10.0.0.0/8",
                "name_servers": ["9.9.9.9", "149.112.112.112"],
                "tags": {"Environment": "development", "Region": "us-east-1"},
            }
        },
        "tags": {"ZoneType": "development", "Owner": "platform-team"},
    },
]


################################
# Application Definitions
################################

portfolio_facts = [
    {
        "client": client_slug,  # slug
        "portfolio": "core-automation",  # slug
        "name": "Core Automation Engine",
        "contacts": [
            {"name": "Tech Lead", "email": "techlead@eits.com.sg", "enabled": True},
            {"name": "Product Manager", "email": "pm@eits.com.sg", "enabled": True},
        ],
        "approvers": [
            {"sequence": 1, "name": "Manager", "email": "mgr@eits.com.sg", "roles": ["deployment"], "enabled": True},
            {
                "sequence": 2,
                "name": "Director",
                "email": "dir@eits.com.sg",
                "depends_on": [1],
                "roles": ["deployment", "approval"],
                "enabled": True,
            },
        ],
        "project": {
            "code": "CORE",
            "name": "Core Automation",
            "repository": "https://github.com/eitssg/simple-cloud-kit",
            "description": "Core Automation Engine",
            "attributes": {"category": "platform"},
        },
        "domain": "automation.eits.com.sg",
        "bizapp": {
            "code": "CORE-APP",
            "name": "Core Business App",
            "description": "Business-facing application for Core Automation",
            "attributes": {"owner": "platform"},
        },
        "owner": {"name": "Platform Team", "email": "platform@eits.com.sg", "phone": "+65-0000-0000"},
        "tags": {"Environment": "production", "Team": "platform"},
        "metadata": {"CostCenter": "CORE", "Owner": "platform"},
        "attributes": {"Tier": "1", "Confidentiality": "internal"},
        "user_instantiated": "seed-data",
    },
    {
        "client": client_slug,  # slug
        "portfolio": "ocp",  # slug
        "name": "OpenShift Cloud Platform",
        "contacts": [
            {"name": "OCP Lead", "email": "ocp-lead@eits.com.sg", "enabled": True},
            {"name": "SRE", "email": "sre@eits.com.sg", "enabled": True},
        ],
        "approvers": [
            {"sequence": 1, "name": "OCP Manager", "email": "ocp-mgr@eits.com.sg", "roles": ["deployment"], "enabled": True},
            {
                "sequence": 2,
                "name": "CTO",
                "email": "cto@eits.com.sg",
                "depends_on": [1],
                "roles": ["deployment", "approval"],
                "enabled": True,
            },
        ],
        "project": {
            "code": "OCP",
            "name": "OpenShift Cloud Platform",
            "repository": "https://github.com/eitssg/openshift-cloud-platform",
            "description": "OpenShift-based application platform",
            "attributes": {"category": "platform"},
        },
        "domain": "ocp.eits.com.sg",
        "bizapp": {
            "code": "OCP-APP",
            "name": "OCP Business App",
            "description": "Business-facing application on OCP",
            "attributes": {"owner": "cloud"},
        },
        "owner": {"name": "Cloud Team", "email": "cloud@eits.com.sg", "phone": "+65-0000-0001"},
        "tags": {"Environment": "staging", "Team": "cloud"},
        "metadata": {"CostCenter": "OCP", "Owner": "cloud"},
        "attributes": {"Tier": "2", "Confidentiality": "internal"},
        "user_instantiated": "seed-data",
    },
]

############################
# Deployments
############################

prod_app_facts = [
    {
        "client": client_slug,  # slug
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
        "client": client_slug,  # slug
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
        "client": client_slug,  # slug
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
        "client": client_slug,  # slug
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
        "client": client_slug,  # slug
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
        "client": client_slug,  # slug
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
        "client": client_slug,  # slug
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
        "client": client_slug,  # slug
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
        "client": client_slug,  # slug
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
        "client": client_slug,  # slug
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
        "client": client_slug,  # slug
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
        "client": client_slug,  # slug
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
        "client": client_slug,  # slug
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
        "client": client_slug,  # slug
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
        "client": client_slug,  # slug
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
        "client": client_slug,  # slug
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
    "preferred_region": "us-east-1",
    "old_permissions": {
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
    "permissions": {
        "roles": ["tenant_admin", "portfolio_editor"],  # symbolic bundles
        "grants": [  # explicit fine-grained allowances
            {
                "resource_type": "portfolio",
                "resource_id": "*",  # wildcard or concrete key
                "actions": ["read", "write", "admin"],  # action verbs
                "effect": "allow",
            },
            {
                "resource_type": "app",
                "resource_id": "billing-ui",
                "actions": ["read"],
                "effect": "allow",
            },
        ],
        "denies": [  # optional explicit denies (wins over allow)
            {
                "resource_type": "portfolio",
                "resource_id": "secret-ops",
                "actions": ["read", "write"],
                "effect": "deny",
            },
        ],
        "effective_hash": "sha256-of-expanded-set",  # server-generated; lets you short-circuit recompute
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


if __name__ == "__main__":
    test_seed_data()  # pragma: no cover
