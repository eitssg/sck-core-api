import os

volume = os.getenv("VOLUME", "/core-data")

api_endpoints: list[tuple[tuple[str, str, dict], tuple[int, dict]]] = [
    # Registry of Clients (client_id comes from the user authentication token)
    # Case 0
    (
        (
            "PUT",  # Updaate the current seed data to below
            "/api/v1/registry/clients/core",
            {
                "client_id": "core_669a5fdd8be7",
                "client": "core",
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
                "data": {"client": "core", "organization_id": "o-1234567890"},
            },
        ),
    ),
    # Registry of Portfolios or Business Applications
    # Case 1 (client_id comes from the user authentication token)
    (
        (
            "POST",
            "/api/v1/registry/clients/core/portfolios",
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
                    "repository": "https://github.com/core/mbbp.git",
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
            201,
            {
                "status": "ok",
                "code": 201,
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
                        "repository": "https://github.com/core/mbbp.git",
                    },
                },
            },
        ),
    ),
    # After we register a Client and Portfolio we can register the Zone for the Portfolio
    # Case 2 (client_id comes from the user authentication token)
    (
        (
            "POST",
            "/api/v1/registry/clients/core/zones",
            {
                "zone": "simple-cloud-kit-api-production",
                "account_facts": {
                    "aws_account_id": "123456789012",
                    "kms": {
                        "aws_account_id": "123456789012",
                        "delegate_aws_account_ids": ["123456789012"],
                    },
                    "resource_namespace": "{{ context.ResourceNamespace | d('core-network') }}-dev-ss",
                    "vpc_aliases": {
                        "public": {"name": "SharedServicesVpc", "vpc_id": "vpc-12345678", "cidr": ["192.168.1.0/24"]},
                        "private": {"name": "SharedServicesVpc", "vpc_id": "vpc-12345679", "cidr": ["192.168.2.0/24"]},
                    },
                    "subnet_aliases": {
                        "public": [{"name": "PublicSubnet", "subnet_id": "sn-public", "cidr": "192.168.1.0/24"}],
                        "app": [{"name": "PrivateSubnet", "subnet_id": "sn-app", "cidr": "192.168.2.0/24"}],
                        "private": [{"name": "PrivateSubnet", "subnet_id": "sn-private", "cidr": "192.168.3.0/24"}],
                    },
                    "tags": {"AppGroup": "SharedServices", "CostCenter": "TCSE0344"},
                },
                "region_facts": {
                    "sin": {
                        "aws_region": "ap-southeast-1",
                        "az_count": 2,
                        "image_aliases": {
                            "amazon-linux-2": "ami-0e2e44c03b85f58b3",
                            "amazon-linux-2_1": "ami-03faaf9cde2b38e9f",
                            "rhel-7-linux-latest": "ami-0a65c2a629181e55e",
                        },
                        "min_successful_instances_percent": 100,
                        "security_aliases": {
                            "public-internet": [
                                {
                                    "type": "cidr",
                                    "value": "0.0.0.0/0",
                                    "description": "Internet",
                                }
                            ],
                            "intranet": [
                                {
                                    "type": "cidr",
                                    "value": "10.0.0.0/8",
                                    "description": "Summary route to on-prem",
                                }
                            ],
                        },
                        "proxy_host": "squid-dev-proxy-squid.dmz.dev.aws.sg.simplegroup.net",
                        "proxy_port": "3128",
                        "proxy_url": "http://squid-dev-proxy-squid.dmz.dev.aws.sg.simplegroup.net:3128",
                        "no_proxy": "127.0.0.1,logs.ap-southeast-1.amazonaws.com,localhost,169.254.169.253,169.254.169.254,s3.ap-southeast-1.amazonaws.com,dynamodb.ap-southeast-1.amazonaws.com,s3-ap-southeast-1.amazonaws.com,cloudformation.ap-southeast-1.amazonaws.com,amazonlinux.ap-southeast-1.amazonaws.com,10.*",
                        "security_group_aliases": {},
                        "name_servers": [
                            "10.175.112.133",
                            "10.175.112.5",
                            "10.175.112.69",
                        ],
                    }
                },
            },
        ),
        (
            201,
            {
                "status": "ok",
                "code": 201,
                "data": {
                    "zone": "simple-cloud-kit-api-production",
                    "account_facts": {
                        "aws_account_id": "123456789012",
                        "kms": {
                            "aws_account_id": "123456789012",
                            "delegate_aws_account_ids": ["123456789012"],
                        },
                    },
                    "region_facts": {"sin": {"aws_region": "ap-southeast-1"}},
                },
            },
        ),
    ),
    # Registry of Apps (client_id comes from the user authentication token)
    # Case 3
    (
        (
            "POST",
            "/api/v1/registry/clients/core/portfolios/simple-cloud-kit/apps",
            {
                "app": "api",
                "app_regex": "^prn:simple-cloud-kit:api:.*:.*$",
                "zone": "simple-cloud-kit-api-production",
                "region": "sin",
                "environment": "prod",
                "metadata": {
                    "static_website_image_alias": "amazonlinux-2",
                },
                "tags": {
                    "Name": "simple-cloud-kit-api",
                    "Client": "core",
                    "Portfolio": "simple-cloud-kit",
                    "App": "api",
                    "Color": "Blue",
                },
            },
        ),
        (
            201,
            {
                "status": "ok",
                "code": 201,
                "data": {
                    "portfolio": "simple-cloud-kit",
                    "app": "api",
                    "app_regex": "^prn:simple-cloud-kit:api:.*:.*$",
                    "zone": "simple-cloud-kit-api-production",
                    "environment": "prod",
                    "metadata": {"static_website_image_alias": "amazonlinux-2"},
                    "region": "sin",
                    "tags": {
                        "Name": "simple-cloud-kit-api",
                        "Client": "core",
                        "Portfolio": "simple-cloud-kit",
                        "App": "api",
                        "Color": "Blue",
                    },
                },
            },
        ),
    ),
    # Get The Facts (client and client_id come from the user authentication token)
    # Case 4
    (
        ("GET", "/api/v1/facts?prn=prn:simple-cloud-kit:api:main:1", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    'AwsAccountId': '123456789012', 
                    'Kms': {
                        'AwsAccountId': '123456789012'
                    }, 
                    'ResourceNamespace': "{{ context.ResourceNamespace | d('core-network') }}-dev-ss", 
                    'VpcAliases': {
                        'public': {'Name': 'SharedServicesVpc', 'Cidr': ['192.168.1.0/24'], 'VpcId': 'vpc-12345678'}, 
                        'private': {'Name': 'SharedServicesVpc', 'Cidr': ['192.168.2.0/24'], 'VpcId': 'vpc-12345679'}
                    }, 
                    'SubnetAliases': {
                        'public': [{'Name': 'PublicSubnet', 'Cidr': '192.168.1.0/24', 'SubnetId': 'sn-public'}], 
                        'app': [{'Name': 'PrivateSubnet', 'Cidr': '192.168.2.0/24', 'SubnetId': 'sn-app'}], 
                        'private': [{'Name': 'PrivateSubnet', 'Cidr': '192.168.3.0/24', 'SubnetId': 'sn-private'}]
                    }, 
                    'Tags': {
                        'CostCenter': 'TCSE0344', 
                        'AppGroup': 'SharedServices', 
                        'App': 'api', 
                        'Client': 'core', 
                        'Name': 'simple-cloud-kit-api', 
                        'Portfolio': 'simple-cloud-kit', 
                        'Color': 'Blue', 
                        'Environment': 'prod', 
                        'Region': 'sin', 
                        'Owner': 'The Boss <boss@gmail.com>', 
                        'Contacts': 'Contact 1 <contact1@gmail.com>'
                    }, 
                    'AwsRegion': 'ap-southeast-1', 
                    'AzCount': 2, 'ImageAliases': {
                        'amazon-linux-2_1': 'ami-03faaf9cde2b38e9f', 
                        'rhel-7-linux-latest': 'ami-0a65c2a629181e55e', 
                        'amazon-linux-2': 'ami-0e2e44c03b85f58b3'
                    }, 
                    'MinSuccessfulInstancesPercent': 100, 
                    'SecurityAliases': {
                        'public-internet': [{'Type': 'cidr', 'Value': '0.0.0.0/0', 'Description': 'Internet'}], 
                        'intranet': [{'Type': 'cidr', 'Value': '10.0.0.0/8', 'Description': 'Summary route to on-prem'}]
                    }, 
                    'SecurityGroupAliases': {}, 
                    'ProxyHost': 'squid-dev-proxy-squid.dmz.dev.aws.sg.simplegroup.net', 
                    'ProxyPort': 3128, 
                    'ProxyUrl': 'http://squid-dev-proxy-squid.dmz.dev.aws.sg.simplegroup.net:3128', 
                    'NoProxy': '127.0.0.1,logs.ap-southeast-1.amazonaws.com,localhost,169.254.169.253,169.254.169.254,s3.ap-southeast-1.amazonaws.com,dynamodb.ap-southeast-1.amazonaws.com,s3-ap-southeast-1.amazonaws.com,cloudformation.ap-southeast-1.amazonaws.com,amazonlinux.ap-southeast-1.amazonaws.com,10.*', 
                    'NameServers': ['10.175.112.133', '10.175.112.5', '10.175.112.69'], 
                    'Portfolio': 'simple-cloud-kit', 
                    'Contacts': [{'Name': 'Contact 1', 'Email': 'contact1@gmail.com', 'Enabled': True}], 
                    'Approvers': [
                        {'Sequence': 1, 'Name': 'Approver 1', 'Email': 'contact2@gmail.com', 
                          'Enabled': True}, 
                        {'Sequence': 2, 'Name': 'Approver 1', 'Email': 'contact2@gmail.com', 
                          'Enabled': True}
                    ], 
                    'Project': {
                        'Name': 'My Big Buisness Project', 
                        'Code': 'MBBP', 
                        'Repository': 'https://github.com/core/mbbp.git', 
                        'Description': 'This business project will impact people in a big way with big blue colors'
                    }, 
                    'Bizapp': {
                        'Name': 'CMDB Record Name', 
                        'Code': 'Big Prj', 
                        'Description': 'This is the Big Boss project'
                    }, 
                    'Owner': {
                        'Name': 'The Boss', 'Email': 'boss@gmail.com'
                    }, 
                    'Attributes': {
                        'key1': 'value1'
                    }, 
                    'AppCount': 0, 
                    'App': 'api', 
                    'AppRegex': '^prn:simple-cloud-kit:api:.*:.*$', 
                    'Name': 'api', 
                    'Environment': 'prod', 
                    'Zone': 'simple-cloud-kit-api-production', 
                    'Region': 'sin', 
                    'Metadata': {
                        'static_website_image_alias': 'amazonlinux-2'
                    }, 
                    'ClientId': 'core_669a5fdd8be7', 
                    'Client': 'core', 
                    'Branch': 'main', 
                    'BranchShortName': 'main', 
                    'Build': '1', 
                    'Scope': 'build', 
                    'ArtefactsBucketName': 'art-core-automation-ap-southeast-1', 
                    'ArtefactsBucketRegion': 'ap-southeast-1', 
                    'ArtefactsBucketUrl': '/Users/jbarwick/core/art-core-automation-ap-southeast-1', 
                    'ArtefactsPrefix': 'artefacts/simple-cloud-kit/api/main/1', 
                    'ArtefactKeyBuildPrefix': 'artefacts/simple-cloud-kit/api/main/1', 
                    'ArtifactBucketName': 'art-core-automation-ap-southeast-1', 
                    'ArtifactBucketRegion': 'ap-southeast-1', 
                    'ArtifactBaseUrl': '/Users/jbarwick/core/art-core-automation-ap-southeast-1', 
                    'ArtifactKeyPrefix': 'artefacts/simple-cloud-kit/api/main/1', 
                    'ArtifactKeyBuildPrefix': 'artefacts/simple-cloud-kit/api/main/1', 
                    'FilesBucketName': 'art-core-automation-ap-southeast-1', 
                    'FilesBucketRegion': 'ap-southeast-1', 
                    'FilesBucketUrl': '/Users/jbarwick/core/art-core-automation-ap-southeast-1', 
                    'PortfolioFilesPrefix': 'files/simple-cloud-kit', 
                    'AppFilesPrefix': 'files/simple-cloud-kit/api', 
                    'BranchFilesPrefix': 'files/simple-cloud-kit/api/main', 
                    'BuildFilesPrefix': 'files/simple-cloud-kit/api/main/1', 
                    'ArtifactKeyPortfolioPrefix': 'artefacts/simple-cloud-kit', 
                    'ArtifactKeyAppPrefix': 'artefacts/simple-cloud-kit/api',
                    'SharedFilesPrefix': 'files/shared',
                    'OrganizationId': 'o-1234567890',
                    'OrganizationName': 'My Organization',
                    'OrganizationAccount': '1234566890',
                    'AuditAccount': '1234566890',
                    'AutomationAccount': '1234566890',
                    'SecurityAccount': '1234566890',
                    'MasterRegion': 'ap-southeast-1',
                    'ClientRegion': 'ap-southeast-1',
                    'UiBucket': 'core-automation-ui'
                }
            },
        ),
    ),
]
