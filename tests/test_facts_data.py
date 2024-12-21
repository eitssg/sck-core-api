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
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {"client": "eits", "organization_id": "o-1234567890"},
            },
        ),
    ),
    # Registry of Portfolios or Business Applications
    # Case 1
    (
        (
            "POST",
            "/api/v1/registry/eits/portfolios",
            {
                "portfolio": "simple-cloud-kit",
                "owner": {"email": "boss@gmail.com", "name": "The Boss"},
                "contacts": [{"name": "Contact 1", "email": "contact1@gmail.com"}],
                "approvers": [
                    {
                        "sequence": 1,
                        "name": "Approver 1",
                        "email": "contact2@gmail.com",
                        "depends_on": [],
                    },
                    {
                        "sequence": 2,
                        "name": "Approver 1",
                        "email": "contact2@gmail.com",
                        "depends_on": [1],
                    },
                ],
                "project": {
                    "name": "My Big Buisness Project",
                    "code": "MBBP",
                    "repository": "https://github.com/eits/mbbp.git",
                    "description": "This business project will impact people in a big way with big blue colors",
                },
                "bizapp": {
                    "name": "CMDB Record Name",
                    "code": "Big Prj",
                    "description": "This is the Big Boss project",
                },
                "attributes": {
                    "key1": "value1",
                },
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "approvers": [
                        {
                            "email": "contact2@gmail.com",
                            "enabled": True,
                            "name": "Approver 1",
                        },
                        {
                            "sequence": 2,
                            "name": "Approver 1",
                            "email": "contact2@gmail.com",
                            "depends_on": [1],
                        },
                    ],
                    "attributes": {"key1": "value1"},
                    "bizapp": {
                        "code": "Big Prj",
                        "description": "This is the Big Boss project",
                        "name": "CMDB Record Name",
                    },
                    "client": "eits",
                    "contacts": [
                        {
                            "email": "contact1@gmail.com",
                            "enabled": True,
                            "name": "Contact 1",
                        }
                    ],
                    "owner": {"email": "boss@gmail.com", "name": "The Boss"},
                    "portfolio": "simple-cloud-kit",
                    "project": {
                        "code": "MBBP",
                        "description": "This business project will impact people in a big way with big blue colors",
                        "name": "My Big Buisness Project",
                        "repository": "https://github.com/eits/mbbp.git",
                    },
                },
            },
        ),
    ),
    # After we register a Client and Portfolio we can register the Zone for the Portfolio
    # Case 2
    (
        (
            "POST",
            "/api/v1/registry/eits/simple-cloud-kit/zone",
            {
                "Zone": "simple-cloud-kit-api-production",
                "AccountFacts": {
                    "AwsAccountId": "123456789012",
                    "Kms": {"DelegateAwsAccountIds": ["123456789012"]},
                    "ResourceNamespace": "core-network-dev-ss",
                    "VpcAliases": {
                        "public": "SharedServicesVpc",
                        "private": "SharedServicesVpc",
                    },
                    "SubnetAliases": {
                        "public": "PublicSubnet",
                        "app": "PrivateSubnet",
                        "private": "PrivateSubnet",
                    },
                    "Tags": {"AppGroup": "SharedServices", "CostCenter": "TCSE0344"},
                },
                "RegionFacts": {
                    "sin": {
                        "AwsRegion": "ap-southeast-1",
                        "AzCount": 2,
                        "ImageAliases": {
                            "amazon-linux-2": "ami-0e2e44c03b85f58b3",
                            "amazon-linux-2_1": "ami-03faaf9cde2b38e9f",
                            "rhel-7-linux-latest": "ami-0a65c2a629181e55e",
                        },
                        "MinSuccessfulInstancesPercent": 100,
                        "SecurityAliases": {
                            "public-internet": [
                                {
                                    "Type": "cidr",
                                    "Value": "0.0.0.0/0",
                                    "Description": "Internet",
                                }
                            ],
                            "intranet": [
                                {
                                    "Type": "cidr",
                                    "Value": "10.0.0.0/8",
                                    "Description": "Summary route to on-prem",
                                }
                            ],
                        },
                        "ProxyHost": "squid-dev-proxy-squid.dmz.dev.aws.sg.simplegroup.net",
                        "ProxyPort": "3128",
                        "ProxyUrl": "http://squid-dev-proxy-squid.dmz.dev.aws.sg.simplegroup.net:3128",
                        "NoProxy": "127.0.0.1,logs.ap-southeast-1.amazonaws.com,localhost,169.254.169.253,169.254.169.254,s3.ap-southeast-1.amazonaws.com,dynamodb.ap-southeast-1.amazonaws.com,s3-ap-southeast-1.amazonaws.com,cloudformation.ap-southeast-1.amazonaws.com,amazonlinux.ap-southeast-1.amazonaws.com,10.*",
                        "SecurityGroupAliases": {},
                        "NameServers": [
                            "10.175.112.133",
                            "10.175.112.5",
                            "10.175.112.69",
                        ],
                    }
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
    # Registry of Apps
    # Case 3
    (
        (
            "POST",
            "/api/v1/registry/eits/simple-cloud-kit/app",
            {
                "AppRegex": "^prn:simple-cloud-kit:api:.*:.*$",
                "Zone": "simple-cloud-kit-api-production",
                "Region": "sin",
                "Environment": "prod",
                "Metadata": {
                    "StaticWebsiteImageAlias": "amazonlinux-2",
                },
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
                    "Zone": "simple-cloud-kit-api-production",
                    "Environment": "prod",
                    "Metadata": {"StaticWebsiteImageAlias": "amazonlinux-2"},
                    "Region": "sin",
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
    # Get The Facts
    # Case 4
    (
        ("GET", "/api/v1/facts/eits?prn=prn:simple-cloud-kit:api:main:1", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "AwsAccountId": "123456789012",
                    "Kms": {"DelegateAwsAccountIds": ["123456789012"]},
                    "ResourceNamespace": "core-network-dev-ss",
                    "SubnetAliases": {
                        "public": "PublicSubnet",
                        "app": "PrivateSubnet",
                        "private": "PrivateSubnet",
                    },
                    "Tags": {
                        "CostCenter": "TCSE0344",
                        "AppGroup": "SharedServices",
                        "App": "api",
                        "Client": "eits",
                        "Name": "simple-cloud-kit-api",
                        "Portfolio": "simple-cloud-kit",
                        "Color": "Blue",
                        "Environment": "prod",
                        "Region": "sin",
                        "Owner": "The Boss <boss@gmail.com>",
                        "Contacts": "Contact 1 <contact1@gmail.com>",
                    },
                    "VpcAliases": {
                        "public": "SharedServicesVpc",
                        "private": "SharedServicesVpc",
                    },
                    "MinSuccessfulInstancesPercent": 100,
                    "ProxyUrl": "http://squid-dev-proxy-squid.dmz.dev.aws.sg.simplegroup.net:3128",
                    "NoProxy": "127.0.0.1,logs.ap-southeast-1.amazonaws.com,localhost,169.254.169.253,169.254.169.254,s3.ap-southeast-1.amazonaws.com,dynamodb.ap-southeast-1.amazonaws.com,s3-ap-southeast-1.amazonaws.com,cloudformation.ap-southeast-1.amazonaws.com,amazonlinux.ap-southeast-1.amazonaws.com,10.*",
                    "ImageAliases": {
                        "amazon-linux-2_1": "ami-03faaf9cde2b38e9f",
                        "rhel-7-linux-latest": "ami-0a65c2a629181e55e",
                        "amazon-linux-2": "ami-0e2e44c03b85f58b3",
                    },
                    "SecurityAliases": {
                        "public-internet": [
                            {
                                "Value": "0.0.0.0/0",
                                "Type": "cidr",
                                "Description": "Internet",
                            }
                        ],
                        "intranet": [
                            {
                                "Value": "10.0.0.0/8",
                                "Type": "cidr",
                                "Description": "Summary route to on-prem",
                            }
                        ],
                    },
                    "AwsRegion": "ap-southeast-1",
                    "ProxyHost": "squid-dev-proxy-squid.dmz.dev.aws.sg.simplegroup.net",
                    "SecurityGroupAliases": {},
                    "NameServers": ["10.175.112.133", "10.175.112.5", "10.175.112.69"],
                    "AzCount": 2,
                    "ProxyPort": "3128",
                    "AppRegex": "^prn:simple-cloud-kit:api:.*:.*$",
                    "ClientPortfolio": "eits:simple-cloud-kit",
                    "Environment": "prod",
                    "Metadata": {"StaticWebsiteImageAlias": "amazonlinux-2"},
                    "Region": "sin",
                    "Zone": "simple-cloud-kit-api-production",
                    "Approvers": [
                        {
                            "depends_on": [],
                            "email": "contact2@gmail.com",
                            "enabled": True,
                            "name": "Approver 1",
                            "sequence": 1,
                        },
                        {
                            "depends_on": [1],
                            "email": "contact2@gmail.com",
                            "enabled": True,
                            "name": "Approver 1",
                            "sequence": 2,
                        },
                    ],
                    "Contacts": [
                        {
                            "email": "contact1@gmail.com",
                            "enabled": True,
                            "name": "Contact 1",
                        }
                    ],
                    "Owner": {"email": "boss@gmail.com", "name": "The Boss"},
                },
            },
        ),
    ),
]
