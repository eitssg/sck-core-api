api_paths: list[tuple[tuple[str, str, dict], tuple[int, dict]]] = [
    # Events
    # Case 0
    (
        ("PUT", "/api/v1/event", {"prn": "prn:simple-cloud-kit:api:main:1"}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "event_type": "STATUS",
                    "item_type": "build",
                    "prn": "prn:simple-cloud-kit:api:main:1",
                },
            },
        ),
    ),
    # Case 1
    (
        # When getting all events, you must provide a PRN to get the events only for a specific PRN
        # There is currently no way to get all events without a PRN
        ("GET", "/api/v1/events?prn=prn%3Asimple-cloud-kit%3Aapi%3Amain%3A1", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": [
                    {
                        "event_type": "STATUS",
                        "item_type": "build",
                        "prn": "prn:simple-cloud-kit:api:main:1",
                    }
                ],
            },
        ),
    ),
    # Case 2
    (
        ("DELETE", "/api/v1/event?prn=prn%3Asimple-cloud-kit%3Aapi%3Amain%3A1", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": "Event deleted: prn:simple-cloud-kit:api:main:1",
            },
        ),
    ),
    # Portfolios Deployed
    # Case 3
    (
        (
            "POST",
            "/api/v1/item/portfolio",
            {
                "prn": "prn:simple-cloud-kit",
                "name": "simple-cloud-kit",
                "contact_email": "simple@gmail.com",
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "contact_email": "simple@gmail.com",
                    "item_type": "portfolio",
                    "name": "simple-cloud-kit",
                    "parent_prn": "prn",
                    "prn": "prn:simple-cloud-kit",
                },
            },
        ),
    ),
    # Case 4
    (
        ("GET", "/api/v1/item/portfolios", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": [
                    {
                        "contact_email": "simple@gmail.com",
                        "item_type": "portfolio",
                        "name": "simple-cloud-kit",
                        "parent_prn": "prn",
                        "prn": "prn:simple-cloud-kit",
                    }
                ],
            },
        ),
    ),
    # Case 5
    (
        ("GET", "/api/v1/item/portfolio?prn=prn%3Asimple-cloud-kit", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "contact_email": "simple@gmail.com",
                    "item_type": "portfolio",
                    "name": "simple-cloud-kit",
                    "parent_prn": "prn",
                    "prn": "prn:simple-cloud-kit",
                },
            },
        ),
    ),
    # Case 6
    (
        (
            "PUT",
            "/api/v1/item/portfolio",
            {
                "prn": "prn:simple-cloud-kit",
                "name": "simple-cloud-kit",
                "contact_email": "simple@gmail.com",
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "contact_email": "simple@gmail.com",
                    "item_type": "portfolio",
                    "name": "simple-cloud-kit",
                    "parent_prn": "prn",
                    "prn": "prn:simple-cloud-kit",
                },
            },
        ),
    ),
    # Case 7
    (
        ("DELETE", "/api/v1/item/portfolio?prn=prn%3Asimple-cloud-kit", {}),
        (
            200,
            {"status": "ok", "code": 200, "data": "Item deleted: prn:simple-cloud-kit"},
        ),
    ),
    # Apps Deployed
    # Case 8
    (
        (
            "POST",
            "/api/v1/items/app",
            {
                "prn": "prn:simple-cloud-kit:core-api",
                "name": "core-api",
                "contact_email": "simple@gmail.com",
                "portfolio_prn": "prn:simple-cloud-kit",
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "contact_email": "simple@gmail.com",
                    "item_type": "app",
                    "name": "core-api",
                    "parent_prn": "prn:simple-cloud-kit",
                    "portfolio_prn": "prn:simple-cloud-kit",
                    "prn": "prn:simple-cloud-kit:core-api",
                },
            },
        ),
    ),
    # Case 9
    (
        ("GET", "/api/v1/items/apps?prn=prn:simple-cloud-kit", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": [
                    {
                        "contact_email": "simple@gmail.com",
                        "item_type": "app",
                        "name": "core-api",
                        "parent_prn": "prn:simple-cloud-kit",
                        "portfolio_prn": "prn:simple-cloud-kit",
                        "prn": "prn:simple-cloud-kit:core-api",
                    }
                ],
            },
        ),
    ),
    # Case 10
    (
        ("GET", "/api/v1/items/app?prn=prn%3Asimple-cloud-kit%3Acore-api", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "contact_email": "simple@gmail.com",
                    "item_type": "app",
                    "name": "core-api",
                    "parent_prn": "prn:simple-cloud-kit",
                    "portfolio_prn": "prn:simple-cloud-kit",
                    "prn": "prn:simple-cloud-kit:core-api",
                },
            },
        ),
    ),
    # Case 11
    (
        (
            "PUT",
            "/api/v1/items/app",
            {
                "prn": "prn:simple-cloud-kit:core-api",
                "name": "core-api",
                "contact_email": "simple@gmail.com",
                "portfolio_prn": "prn:simple-cloud-kit",
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "contact_email": "simple@gmail.com",
                    "item_type": "app",
                    "name": "core-api",
                    "parent_prn": "prn:simple-cloud-kit",
                    "portfolio_prn": "prn:simple-cloud-kit",
                    "prn": "prn:simple-cloud-kit:core-api",
                },
            },
        ),
    ),
    # Case 12
    (
        ("DELETE", "/api/v1/items/app?prn=prn%3Asimple-cloud-kit%3Acore-api", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": "Item deleted: prn:simple-cloud-kit:core-api",
            },
        ),
    ),
    # Branches Deployed
    # Case 13
    (
        (
            "POST",
            "/api/v1/item/branches",
            {
                "prn": "prn:simple-cloud-kit:api:main",
                "name": "main",
                "portfolio_prn": "prn:simple-cloud-kit",
                "app_prn": "prn:simple-cloud-kit:api",
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "app_prn": "prn:simple-cloud-kit:api",
                    "item_type": "branch",
                    "name": "main",
                    "parent_prn": "prn:simple-cloud-kit:api",
                    "portfolio_prn": "prn:simple-cloud-kit",
                    "prn": "prn:simple-cloud-kit:api:main",
                    "short_name": "main",
                },
            },
        ),
    ),
    # Case 14
    (
        ("GET", "/api/v1/item/branches?prn=prn:simple-cloud-kit:api", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": [
                    {
                        "app_prn": "prn:simple-cloud-kit:api",
                        "item_type": "branch",
                        "name": "main",
                        "parent_prn": "prn:simple-cloud-kit:api",
                        "portfolio_prn": "prn:simple-cloud-kit",
                        "prn": "prn:simple-cloud-kit:api:main",
                        "short_name": "main",
                    }
                ],
            },
        ),
    ),
    # Case 15
    (
        ("GET", "/api/v1/item/branch?prn=prn%3Asimple-cloud-kit%3Aapi%3Amain", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "app_prn": "prn:simple-cloud-kit:api",
                    "item_type": "branch",
                    "name": "main",
                    "parent_prn": "prn:simple-cloud-kit:api",
                    "portfolio_prn": "prn:simple-cloud-kit",
                    "prn": "prn:simple-cloud-kit:api:main",
                    "short_name": "main",
                },
            },
        ),
    ),
    # Case 16
    (
        (
            "PUT",
            "/api/v1/item/branch",
            {
                "prn": "prn:simple-cloud-kit:api:main",
                "name": "main",
                "portfolio_prn": "prn:simple-cloud-kit",
                "app_prn": "prn:simple-cloud-kit:api",
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "app_prn": "prn:simple-cloud-kit:api",
                    "item_type": "branch",
                    "name": "main",
                    "parent_prn": "prn:simple-cloud-kit:api",
                    "portfolio_prn": "prn:simple-cloud-kit",
                    "prn": "prn:simple-cloud-kit:api:main",
                    "short_name": "main",
                },
            },
        ),
    ),
    # Case 17
    (
        ("DELETE", "/api/v1/item/branch?prn=prn%3Asimple-cloud-kit%3Aapi%3Amain", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": "Item deleted: prn:simple-cloud-kit:api:main",
            },
        ),
    ),
    # Case 18, put the branch back for the build processing
    (
        (
            "POST",
            "/api/v1/item/branches",
            {
                "prn": "prn:simple-cloud-kit:api:main",
                "name": "main",
                "portfolio_prn": "prn:simple-cloud-kit",
                "app_prn": "prn:simple-cloud-kit:api",
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "app_prn": "prn:simple-cloud-kit:api",
                    "item_type": "branch",
                    "name": "main",
                    "parent_prn": "prn:simple-cloud-kit:api",
                    "portfolio_prn": "prn:simple-cloud-kit",
                    "prn": "prn:simple-cloud-kit:api:main",
                    "short_name": "main",
                },
            },
        ),
    ),
    # Builds Deployed
    # Case 19
    (
        (
            "POST",
            "/api/v1/item/build",
            {
                "prn": "prn:simple-cloud-kit:api:main:1",
                "name": "1",
                "portfolio_prn": "prn:simple-cloud-kit",
                "app_prn": "prn:simple-cloud-kit:api",
                "branch_prn": "prn:simple-cloud-kit:api:main",
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "app_prn": "prn:simple-cloud-kit:api",
                    "branch_prn": "prn:simple-cloud-kit:api:main",
                    "item_type": "build",
                    "name": "1",
                    "parent_prn": "prn:simple-cloud-kit:api:main",
                    "portfolio_prn": "prn:simple-cloud-kit",
                    "prn": "prn:simple-cloud-kit:api:main:1",
                    "status": "INIT",
                },
            },
        ),
    ),
    # Case 20
    (
        ("GET", "/api/v1/item/builds?prn=prn:simple-cloud-kit:api:main", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": [
                    {
                        "app_prn": "prn:simple-cloud-kit:api",
                        "branch_prn": "prn:simple-cloud-kit:api:main",
                        "item_type": "build",
                        "name": "1",
                        "parent_prn": "prn:simple-cloud-kit:api:main",
                        "portfolio_prn": "prn:simple-cloud-kit",
                        "prn": "prn:simple-cloud-kit:api:main:1",
                        "status": "INIT",
                    }
                ],
            },
        ),
    ),
    # Case 21
    (
        ("GET", "/api/v1/item/build?prn=prn%3Asimple-cloud-kit%3Aapi%3Amain%3A1", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "app_prn": "prn:simple-cloud-kit:api",
                    "branch_prn": "prn:simple-cloud-kit:api:main",
                    "item_type": "build",
                    "name": "1",
                    "parent_prn": "prn:simple-cloud-kit:api:main",
                    "portfolio_prn": "prn:simple-cloud-kit",
                    "prn": "prn:simple-cloud-kit:api:main:1",
                    "status": "INIT",
                },
            },
        ),
    ),
    # Case 22
    (
        (
            "PUT",
            "/api/v1/item/build",
            {
                "prn": "prn:simple-cloud-kit:api:main:1",
                "name": "1",
                "portfolio_prn": "prn:simple-cloud-kit",
                "app_prn": "prn:simple-cloud-kit:api",
                "branch_prn": "prn:simple-cloud-kit:api:main",
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "app_prn": "prn:simple-cloud-kit:api",
                    "branch_prn": "prn:simple-cloud-kit:api:main",
                    "item_type": "build",
                    "name": "1",
                    "parent_prn": "prn:simple-cloud-kit:api:main",
                    "portfolio_prn": "prn:simple-cloud-kit",
                    "prn": "prn:simple-cloud-kit:api:main:1",
                    "status": "INIT",
                },
            },
        ),
    ),
    # Case 23
    (
        (
            "POST",
            "/api/v1/item/build/teardown",
            {"prn": "prn:simple-cloud-kit:api:main:1"},
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": "Build prn:simple-cloud-kit:api:main:1 teardown requested",
            },
        ),
    ),
    # Case 24
    (
        (
            "POST",
            "/api/v1/item/build/release",
            {"prn": "prn:simple-cloud-kit:api:main:1"},
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": "Build prn:simple-cloud-kit:api:main:1 release requested",
            },
        ),
    ),
    # Case 25
    (
        (
            "DELETE",
            "/api/vi/item/build?prn=prn%3Asimple-cloud-kit%3Aapi%3Amain%3A1",
            {},
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": "Item deleted: prn:simple-cloud-kit:api:main:1",
            },
        ),
    ),
    # Components Deployed
    # Case 26
    (
        (
            "POST",
            "/api/v1/items/component",
            {
                "prn": "prn:simple-cloud-kit:api:main:1:webserver",
                "name": "webserver",
                "portfolio_prn": "prn:simple-cloud-kit",
                "app_prn": "prn:simple-cloud-kit:api",
                "branch_prn": "prn:simple-cloud-kit:api:main",
                "build_prn": "prn:simple-cloud-kit:api:main:1",
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "app_prn": "prn:simple-cloud-kit:api",
                    "branch_prn": "prn:simple-cloud-kit:api:main",
                    "build_prn": "prn:simple-cloud-kit:api:main:1",
                    "item_type": "component",
                    "name": "webserver",
                    "parent_prn": "prn:simple-cloud-kit:api:main:1",
                    "portfolio_prn": "prn:simple-cloud-kit",
                    "prn": "prn:simple-cloud-kit:api:main:1:webserver",
                    "status": "INIT",
                },
            },
        ),
    ),
    # Case 27
    (
        ("GET", "/api/v1/items/components?prn=prn:simple-cloud-kit:api:main:1", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": [
                    {
                        "app_prn": "prn:simple-cloud-kit:api",
                        "branch_prn": "prn:simple-cloud-kit:api:main",
                        "build_prn": "prn:simple-cloud-kit:api:main:1",
                        "item_type": "component",
                        "name": "webserver",
                        "parent_prn": "prn:simple-cloud-kit:api:main:1",
                        "portfolio_prn": "prn:simple-cloud-kit",
                        "prn": "prn:simple-cloud-kit:api:main:1:webserver",
                        "status": "INIT",
                    }
                ],
            },
        ),
    ),
    # Case 28
    (
        (
            "GET",
            "/api/v1/items/component?prn=prn%3Asimple-cloud-kit%3Aapi%3Amain%3A1%3Awebserver",
            {},
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "app_prn": "prn:simple-cloud-kit:api",
                    "branch_prn": "prn:simple-cloud-kit:api:main",
                    "build_prn": "prn:simple-cloud-kit:api:main:1",
                    "item_type": "component",
                    "name": "webserver",
                    "parent_prn": "prn:simple-cloud-kit:api:main:1",
                    "portfolio_prn": "prn:simple-cloud-kit",
                    "prn": "prn:simple-cloud-kit:api:main:1:webserver",
                    "status": "INIT",
                },
            },
        ),
    ),
    # Case 29
    (
        (
            "PUT",
            "/api/v1/items/component",
            {
                "prn": "prn:simple-cloud-kit:api:main:1:webserver",
                "name": "webserver",
                "portfolio_prn": "prn:simple-cloud-kit",
                "app_prn": "prn:simple-cloud-kit:api",
                "branch_prn": "prn:simple-cloud-kit:api:main",
                "build_prn": "prn:simple-cloud-kit:api:main:1",
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "app_prn": "prn:simple-cloud-kit:api",
                    "branch_prn": "prn:simple-cloud-kit:api:main",
                    "build_prn": "prn:simple-cloud-kit:api:main:1",
                    "item_type": "component",
                    "name": "webserver",
                    "parent_prn": "prn:simple-cloud-kit:api:main:1",
                    "portfolio_prn": "prn:simple-cloud-kit",
                    "prn": "prn:simple-cloud-kit:api:main:1:webserver",
                    "status": "INIT",
                },
            },
        ),
    ),
    # Case 30
    (
        (
            "DELETE",
            "/api/v1/items/component?prn=prn%3Asimple-cloud-kit%3Aapi%3Amain%3A1%3Awebserver",
            {},
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": "Item deleted: prn:simple-cloud-kit:api:main:1:webserver",
            },
        ),
    ),
    # Registry of Clients
    # Case 31
    (
        ("POST", "/api/v1/registry/clients", {"client": "eits"}),
        (200, {"status": "ok", "code": 200, "data": {"client": "eits"}}),
    ),
    # Case 32
    (
        ("GET", "/api/v1/registry/clients", {}),
        (200, {"status": "ok", "code": 200, "data": ["eits"]}),
    ),
    # Case 33
    (
        ("GET", "/api/v1/registry/client/eits", {}),
        (200, {"status": "ok", "code": 200, "data": {"client": "eits"}}),
    ),
    # Case 34
    (
        (
            "PUT",
            "/api/v1/registry/client/eits",
            {"client": "eits", "scope_prefix": "alternate"},
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {"client": "eits", "scope_prefix": "alternate"},
            },
        ),
    ),
    # Case 35
    (
        (
            "PATCH",
            "/api/v1/registry/client/eits",
            {"bucket_region": "ap-southeast-2", "master_region": "us-east-1"},
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "bucket_region": "ap-southeast-2",
                    "client": "eits",
                    "master_region": "us-east-1",
                    "scope_prefix": "alternate",
                },
            },
        ),
    ),
    # Case 36
    (
        ("DELETE", "/api/v1/registry/client/eits", {}),
        (200, {"status": "ok", "code": 200, "data": "Client eits deleted"}),
    ),
    # Registry of Portfolios
    # Case 37
    (
        ("POST", "/api/v1/registry/eits/portfolios", {"portfolio": "simple-cloud-kit"}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {"client": "eits", "portfolio": "simple-cloud-kit"},
            },
        ),
    ),
    # Case 38
    (
        ("GET", "/api/v1/registry/eits/portfolios", {}),
        (200, {"status": "ok", "code": 200, "data": ["simple-cloud-kit"]}),
    ),
    # Case 39
    (
        ("GET", "/api/v1/registry/eits/portfolio/simple-cloud-kit", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {"client": "eits", "portfolio": "simple-cloud-kit"},
            },
        ),
    ),
    # Case 40
    (
        (
            "PUT",
            "/api/v1/registry/eits/portfolio/simple-cloud-kit",
            {"owner": {"name": "the_big_boss", "email": "boss@gmail.com"}},
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "client": "eits",
                    "owner": {"email": "boss@gmail.com", "name": "the_big_boss"},
                    "portfolio": "simple-cloud-kit",
                },
            },
        ),
    ),
    # Case 41
    (
        (
            "PATCH",
            "/api/v1/registry/eits/portfolio/simple-cloud-kit",
            {"bizapp_name": "the awesome cloud kit"},
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "bizapp_name": "the awesome cloud kit",
                    "client": "eits",
                    "owner": {"email": "boss@gmail.com", "name": "the_big_boss"},
                    "portfolio": "simple-cloud-kit",
                },
            },
        ),
    ),
    # Case 42
    (
        ("DELETE", "/api/v1/registry/eits/portfolio/simple-cloud-kit", {}),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": "Portfolio deleted: eits:simple-cloud-kit",
            },
        ),
    ),
    # Registry of Apps
    # Case 43
    (
        (
            "POST",
            "/api/v1/registry/eits/simple-cloud-kit/app",
            {
                "AppRegex": "^prn:simple-cloud-kit:api:.*:.*$",
                "Region": "sin",
                "Zone": "my-landing-zone",
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "AppRegex": "^prn:simple-cloud-kit:api:.*:.*$",
                    "ClientPortfolio": "eits:simple-cloud-kit",
                    "Region": "sin",
                    "Zone": "my-landing-zone",
                },
            },
        ),
    ),
    # Case 44
    (
        ("GET", "/api/v1/registry/eits/simple-cloud-kit/apps", {}),
        (
            200,
            {"status": "ok", "code": 200, "data": ["^prn:simple-cloud-kit:api:.*:.*$"]},
        ),
    ),
    # Case 45
    (
        (
            "PUT",
            "/api/v1/registry/eits/simple-cloud-kit/app",
            {"AppRegex": "^prn:simple-cloud-kit:api:.*:.*$", "Environment": "dev"},
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "AppRegex": "^prn:simple-cloud-kit:api:.*:.*$",
                    "ClientPortfolio": "eits:simple-cloud-kit",
                    "Environment": "dev",
                    "Region": "sin",
                    "Zone": "my-landing-zone",
                },
            },
        ),
    ),
    # Case 46
    (
        (
            "PATCH",
            "/api/v1/registry/eits/simple-cloud-kit/app",
            {"AppRegex": "^prn:simple-cloud-kit:api:.*:.*$", "Environment": "prod"},
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "AppRegex": "^prn:simple-cloud-kit:api:.*:.*$",
                    "ClientPortfolio": "eits:simple-cloud-kit",
                    "Environment": "prod",
                    "Region": "sin",
                    "Zone": "my-landing-zone",
                },
            },
        ),
    ),
    # Case 47
    (
        (
            "DELETE",
            "/api/v1/registry/eits/simple-cloud-kit/app?AppRegex=%5Eprn%3Asimple-cloud-kit%3Aapi%3A.%2A%3A.%2A%24",
            {},
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": "App [eits:simple-cloud-kit:^prn:simple-cloud-kit:api:.*:.*$] deleted",
            },
        ),
    ),
    # Registry of Zones
    # Case 48
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
                    "AccountFacts": {
                        "AwsAccountId": "123456789012",
                        "Kms": {"DelegateAwsAccountIds": ["123456789012"]},
                    },
                    "ClientPortfolio": "eits:simple-cloud-kit",
                    "RegionFacts": {"sin": {"AwsRegion": "ap-southeast-1"}},
                    "Zone": "simple-cloud-kit-api-production",
                },
            },
        ),
    ),
    # Case 49
    (
        ("GET", "/api/v1/registry/eits/simple-cloud-kit/zones", {}),
        (
            200,
            {"status": "ok", "code": 200, "data": ["simple-cloud-kit-api-production"]},
        ),
    ),
    # Case 50
    (
        (
            "PUT",
            "/api/v1/registry/eits/simple-cloud-kit/zone/simple-cloud-kit-api-production",
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
                    "AccountFacts": {
                        "AwsAccountId": "123456789012",
                        "Kms": {"DelegateAwsAccountIds": ["123456789012"]},
                    },
                    "ClientPortfolio": "eits:simple-cloud-kit",
                    "RegionFacts": {"sin": {"AwsRegion": "ap-southeast-1"}},
                    "Zone": "simple-cloud-kit-api-production",
                },
            },
        ),
    ),
    # Case 51
    (
        (
            "PATCH",
            "/api/v1/registry/eits/simple-cloud-kit/zone/simple-cloud-kit-api-production",
            {
                "AccountFacts": {"Kms": {"KmsKeyArn": "arn:kms:key"}},
                "RegionFacts": {"sin": {"AzCount": 3}},
            },
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": {
                    "AccountFacts": {
                        "AwsAccountId": "123456789012",
                        "Kms": {
                            "Kms": {
                                "KmsKeyArn": "arn:kms:key",
                                "DelegateAwsAccountIds": ["123456789012"],
                            }
                        },
                    },
                    "ClientPortfolio": "eits:simple-cloud-kit",
                    "RegionFacts": {
                        "sin": {"AwsRegion": "ap-southeast-1", "AzCount": 3}
                    },
                    "Zone": "simple-cloud-kit-api-production",
                },
            },
        ),
    ),
    # Case 52
    (
        (
            "DELETE",
            "/api/v1/registry/eits/simple-cloud-kit/zone/simple-cloud-kit-api-production",
            {},
        ),
        (
            200,
            {
                "status": "ok",
                "code": 200,
                "data": "Zone deleted: simple-cloud-kit-api-production",
            },
        ),
    ),
]
