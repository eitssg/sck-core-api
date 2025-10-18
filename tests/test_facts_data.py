import os

volume = os.getenv("VOLUME", "/core-data")

api_endpoints: list[tuple[tuple[str, str, dict], tuple[int, dict]]] = [
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
                "client_region": "ap-southeast-1",
                "master_region": "ap-southeast-1",
                "automation_account": "1234566890",
                "automation_bucket": "core-automation-master",
                "automation_bucket_region": "ap-southeast-1",
                "audit_account": "1234566890",
                "docs_bucket": "core-automation-docs",
                "security_account": "1234566890",
                "ui_bucket": "core-automation-ui",
                "scope_prefix": "",
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {"Client": "eits", "OrganizationId": "o-1234567890"},
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
                "owner": {"Email": "boss@gmail.com", "Name": "The Boss"},
                "contacts": [{"Name": "Contact 1", "Email": "contact1@gmail.com"}],
                "approvers": [
                    {
                        "Sequence": 1,
                        "Name": "Approver 1",
                        "Email": "contact2@gmail.com",
                        "DependsOn": [],
                    },
                    {
                        "Sequence": 2,
                        "Name": "Approver 1",
                        "Email": "contact2@gmail.com",
                        "DependsOn": [1],
                    },
                ],
                "project": {
                    "Name": "My Big Buisness Project",
                    "Code": "MBBP",
                    "Repository": "https://github.com/eits/mbbp.git",
                    "Description": "This business project will impact people in a big way with big blue colors",
                },
                "bizapp": {
                    "Name": "CMDB Record Name",
                    "Code": "Big Prj",
                    "Description": "This is the Big Boss project",
                },
                "Attributes": {
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
                    "Approvers": [
                        {
                            "Email": "contact2@gmail.com",
                            "Enabled": True,
                            "Name": "Approver 1",
                        },
                        {
                            "Sequence": 2,
                            "Name": "Approver 1",
                            "Email": "contact2@gmail.com",
                            "DependsOn": [1],
                        },
                    ],
                    "Attributes": {"key1": "value1"},
                    "Bizapp": {
                        "Code": "Big Prj",
                        "Description": "This is the Big Boss project",
                        "Name": "CMDB Record Name",
                    },
                    "Client": "eits",
                    "Contacts": [
                        {
                            "Email": "contact1@gmail.com",
                            "Enabled": True,
                            "Name": "Contact 1",
                        }
                    ],
                    "Owner": {"Email": "boss@gmail.com", "Name": "The Boss"},
                    "Portfolio": "simple-cloud-kit",
                    "Project": {
                        "Code": "MBBP",
                        "Description": "This business project will impact people in a big way with big blue colors",
                        "Name": "My Big Buisness Project",
                        "Repository": "https://github.com/eits/mbbp.git",
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
            "/api/v1/registry/eits/zone",
            {
                "Zone": "simple-cloud-kit-api-production",
                "AccountFacts": {
                    "AwsAccountId": "123456789012",
                    "Kms": {
                        "AwsAccountId": "123456789012",
                        "DelegateAwsAccountIds": ["123456789012"],
                    },
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
                    "Client": "eits",
                    "Zone": "simple-cloud-kit-api-production",
                    "AccountFacts": {
                        "AwsAccountId": "123456789012",
                        "Kms": {
                            "AwsAccountId": "123456789012",
                            "DelegateAwsAccountIds": ["123456789012"],
                        },
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
                    "Kms": {
                        "AwsAccountId": "123456789012",
                        "DelegateAwsAccountIds": ["123456789012"],
                    },
                    "ResourceNamespace": "core-network-dev-ss",
                    "SubnetAliases": {
                        "public": "PublicSubnet",
                        "app": "PrivateSubnet",
                        "private": "PrivateSubnet",
                    },
                    "Tags": {
                        "CostCenter": "TCSE0344",
                        "AppGroup": "SharedServices",
                        "Environment": "prod",
                        "Region": "sin",
                        "Owner": "The Boss <boss@gmail.com>",
                        "Contacts": "Contact 1 <contact1@gmail.com>",
                        "App": "api",
                        "Client": "eits",
                        "Name": "simple-cloud-kit-api",
                        "Portfolio": "simple-cloud-kit",
                        "Color": "Blue",
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
                    "Approvers": [
                        {
                            "DependsOn": [],
                            "Email": "contact2@gmail.com",
                            "Enabled": True,
                            "Name": "Approver 1",
                            "Sequence": 1,
                        },
                        {
                            "DependsOn": [1],
                            "Email": "contact2@gmail.com",
                            "Enabled": True,
                            "Name": "Approver 1",
                            "Sequence": 2,
                        },
                    ],
                    "Attributes": {"key1": "value1"},
                    "Bizapp": {
                        "Code": "Big Prj",
                        "Description": "This is the Big Boss project",
                        "Name": "CMDB Record Name",
                    },
                    "Client": "eits",
                    "Contacts": [
                        {
                            "Email": "contact1@gmail.com",
                            "Enabled": True,
                            "Name": "Contact 1",
                        }
                    ],
                    "Owner": {"Email": "boss@gmail.com", "Name": "The Boss"},
                    "Portfolio": "simple-cloud-kit",
                    "Project": {
                        "Code": "MBBP",
                        "Description": "This business project will impact people in a big way with big blue colors",
                        "Name": "My Big Buisness Project",
                        "Repository": "https://github.com/eits/mbbp.git",
                    },
                    "AppRegex": "^prn:simple-cloud-kit:api:.*:.*$",
                    "ClientPortfolio": "eits:simple-cloud-kit",
                    "Environment": "prod",
                    "Metadata": {"StaticWebsiteImageAlias": "amazonlinux-2"},
                    "Region": "sin",
                    "Zone": "simple-cloud-kit-api-production",
                    "App": "api",
                    "Branch": "main",
                    "BranchShortName": "main",
                    "Build": "1",
                    "Scope": "build",
                    "DeliveredBy": "automation",
                    "ArtefactsBucketName": "eits-core-automation-master",
                    "ArtefactsBucketRegion": "us-east-1",
                    "ArtefactsBucketUrl": os.path.join(volume, "core", "eits-core-automation-master"),
                    "ArtefactsPrefix": os.path.join("artefacts", "simple-cloud-kit", "api", "main", "1"),
                    "ArtifactBucketName": "eits-core-automation-master",
                    "ArtifactBucketRegion": "us-east-1",
                    "ArtifactBaseUrl": os.path.join(volume, "core", "eits-core-automation-master"),
                    "ArtifactKeyPrefix": os.path.join("artefacts", "simple-cloud-kit", "api", "main", "1"),
                    "ArtifactKeyBuildPrefix": os.path.join("artefacts", "simple-cloud-kit", "api", "main", "1"),
                    "FilesBucketName": "eits-core-automation-master",
                    "FilesBucketRegion": "us-east-1",
                    "FilesBucketUrl": os.path.join(volume, "core", "eits-core-automation-master"),
                    "PortfolioFilesPrefix": os.path.join("files", "simple-cloud-kit"),
                    "AppFilesPrefix": os.path.join("files", "simple-cloud-kit", "api"),
                    "BranchFilesPrefix": os.path.join("files", "simple-cloud-kit", "api", "main"),
                    "BuildFilesPrefix": os.path.join("files", "simple-cloud-kit", "api", "main", "1"),
                    "ArtifactKeyPortfolioPrefix": os.path.join("artefacts", "simple-cloud-kit"),
                    "ArtifactKeyAppPrefix": os.path.join("artefacts", "simple-cloud-kit", "api"),
                    "ArtifactKeyBranchPrefix": os.path.join("artefacts", "simple-cloud-kit", "api", "main"),
                    "SharedFilesPrefix": os.path.join("files", "shared"),
                },
            },
        ),
    ),
]
