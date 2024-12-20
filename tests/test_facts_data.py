api_paths: list[tuple[tuple[str, str, dict], tuple[int, dict]]] = [
    # Registry of Clients
    # Case 0
    (
        (
            "POST",
            "/api/v1/registry/clients",
            {
                "client": "eits",
                "organization_id": "o-1234567890",
                "organization_name": "My Organization",
                "organization_account": "1234566890",
                "audit_account": "1234566890",
                "master_region": "ap-southeast-1",
                "docs_bucket": "core-automation-docs",
                "client_region": "ap-southeast-1",
                "automation_bucket": "core-automation-master",
                "bucket_region": "ap-southeast-1",
                "automation_account": "1234566890",
                "security_account": "1234566890",
                "scope_prefix": "",
                "ui_bucket": "core-automation-ui",
            },
        ),
        (200, {"status": "ok", "code": 200, "data": {"client": "eits"}}),
    ),
    # Registry of Portfolios
    # Case 1
    (
        (
            "POST",
            "/api/v1/registry/eits/portfolios",
            {
                "portfolio": "simple-cloud-kit",
                "owner": {"email": "boss@gmail.com", "name": "The Boss"},
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "client": "eits",
                    "portfolio": "simple-cloud-kit",
                    "owner": {"email": "boss@gmail.com", "name": "The Boss"},
                },
            },
        ),
    ),
    # Registry of Apps
    # Case 2
    (
        (
            "POST",
            "/api/v1/registry/eits/simple-cloud-kit/app",
            {
                "AppRegex": "^prn:simple-cloud-kit:api:.*:.*$",
                "Zone": "simple-cloud-kit-api-production",
                "Region": "sin",
                "Environment": "prod",
                "Tags": {
                    "Name": "simple-cloud-kit-api",
                    "Client": "eits",
                    "Portfolio": "simple-cloud-kit",
                    "App": "api",
                    "Color": "Blue",
                },
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "ClientPortfolio": "eits:simple-cloud-kit",
                    "AppRegex": "^prn:simple-cloud-kit:api:.*:.*$",
                    "Region": "sin",
                    "Environment": "prod",
                    "Zone": "simple-cloud-kit-api-production",
                    "Tags": {
                        "Name": "simple-cloud-kit-api",
                        "Client": "eits",
                        "Portfolio": "simple-cloud-kit",
                        "App": "api",
                        "Color": "Blue",
                    },
                },
            },
        ),
    ),
    # Registry of Zones
    # Case 3
    (
        (
            "POST",
            "/api/v1/registry/eits/simple-cloud-kit/zone",
            {
                "Zone": "simple-cloud-kit-api-production",
                "AccountFacts": {
                    "AwsAccountId": "123456789012",
                    "Kms": {"DelegateAwsAccountIds": ["123456789012"]},
                },
                "RegionFacts": {"sin": {"AwsRegion": "ap-southeast-1"}},
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "ClientPortfolio": "eits:simple-cloud-kit",
                    "Zone": "simple-cloud-kit-api-production",
                    "AccountFacts": {
                        "AwsAccountId": "123456789012",
                        "Kms": {"DelegateAwsAccountIds": ["123456789012"]},
                    },
                    "RegionFacts": {"sin": {"AwsRegion": "ap-southeast-1"}},
                },
            },
        ),
    ),
    # Get The Facts
    # Case 53
    (
        ("GET", "/api/v1/facts/eits?prn=prn:simple-cloud-kit:api:main:1", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
]
