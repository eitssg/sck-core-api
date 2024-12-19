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
        (200, {"status": "ok", "code": 200, "data": [1, 2, 3, 4, 5, 6]}),
    ),
    # Case 2
    (
        ("DELETE", "/api/v1/event?prn=prn%3Asimple-cloud-kit%3Aapi%3Amain%3A1", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Portfolios Deployed
    # Case 3
    (
        ("POST", "/api/v1/item/portfolio", {"prn": "prn:simple-cloud-kit"}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 4
    (
        ("GET", "/api/v1/item/portfolios", {}),
        (200, {"status": "ok", "code": 200, "data": [1, 2]}),
    ),
    # Case 5
    (
        ("GET", "/api/v1/item/portfolio?prn=prn%3Asimple-cloud-kit", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 6
    (
        ("PUT", "/api/v1/item/portfolio", {"prn": "prn:simple-cloud-kit"}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 7
    (
        ("DELETE", "/api/v1/item/portfolio?prn=prn%3Asimple-cloud-kit", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Apps Deployed
    # Case 8
    (
        ("POST", "/api/v1/items/app", {"prn": "prn:simple-cloud-kit:core-api"}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 9
    (
        ("GET", "/api/v1/items/apps", {}),
        (200, {"status": "ok", "code": 200, "data": [1, 2, 3, 4]}),
    ),
    # Case 10
    (
        ("GET", "/api/v1/items/app?prn=prn%3Asimple-cloud-kit%3Acore-api", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 11
    (
        ("PUT", "/api/v1/items/app", {"prn": "prn:simple-cloud-kit:core-api"}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 12
    (
        ("DELETE", "/api/v1/items/app?prn=prn%3Asimple-cloud-kit%3Acore-api", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Branches Deployed
    # Case 13
    (
        ("POST", "/api/v1/item/branches", {"prn": "prn:simple-cloud-kit:api:main"}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 14
    (
        ("GET", "/api/v1/item/branches", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 15
    (
        ("GET", "/api/v1/item/branch?prn=prn%3Asimple-cloud-kit%3Aapi%3Amain", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 16
    (
        ("PUT", "/api/v1/item/branch", {"prn": "prn:simple-cloud-kit:api:main"}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 17
    (
        ("DELETE", "/api/v1/item/branch?prn=prn%3Asimple-cloud-kit%3Aapi%3Amain", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Builds Deployed
    # Case 18
    (
        ("POST", "/api/v1/item/build", {"prn": "prn:simple-cloud-kit:api:main:1"}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 19
    (
        ("GET", "/api/v1/item/builds", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 20
    (
        ("GET", "/api/v1/item/build?prn=prn%3Asimple-cloud-kit%3Aapi%3Amain%3A1", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 21
    (
        ("PUT", "/api/v1//item/build", {"prn": "prn:simple-cloud-kit:api:main:1"}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 22
    (
        (
            "POST",
            "/api/v1/item/build/teardown",
            {"prn": "prn:simple-cloud-kit:api:main:1"},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 23
    (
        (
            "POST",
            "/api/v1/item/build/release",
            {"prn": "prn:simple-cloud-kit:api:main:1"},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 24
    (
        (
            "DELETE",
            "/api/vi/item/build?prn=prn%3Asimple-cloud-kit%3Aapi%3Amain%3A1",
            {},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Components Deployed
    # Case 25
    (
        (
            "POST",
            "/api/v1/items/component",
            {"prn": "prn:simple-cloud-kit:api:main:1:webserver"},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 26
    (
        ("GET", "/api/v1/items/components", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 27
    (
        (
            "GET",
            "/api/v1/items/component?prn=prn%3Asimple-cloud-kit%3Aapi%3Amain%3A1%3Awebserver",
            {},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 28
    (
        (
            "PUT",
            "/api/v1/items/component",
            {"prn": "prn:simple-cloud-kit:api:main:1:webserver"},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 29
    (
        (
            "DELETE",
            "/api/v1/items/component?prn=prn%3Asimple-cloud-kit%3Aapi%3Amain%3A1%3Awebserver",
            {},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Registry of Clients
    # Case 30
    (
        ("POST", "/api/v1/registry/clients", {"client": "eits"}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 31
    (
        ("GET", "/api/v1/registry/clients", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 32
    (
        ("GET", "/api/v1/registry/client/eits", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 33
    (
        (
            "PUT",
            "/api/v1/registry/client/eits",
            {"client": "eits", "scope_prefix": "alternate"},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 34
    (
        ("PATCH", "/api/v1/registry/client/eits", {"bucket_region": "ap-southeast-1"}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 35
    (
        ("DELETE", "/api/v1/registry/client/eits", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Registry of Portfolios
    # Case 36
    (
        ("POST", "/api/v1/registry/eits/portfolios", {"portfolio": "simple-cloud-kit"}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 37
    (
        ("GET", "/api/v1/registry/eits/portfolios", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 38
    (
        ("GET", "/api/v1/registry/eits/portfolio/simple-cloud-kit", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 39
    (
        (
            "PUT",
            "/api/v1/registry/eits/portfolio/simple-cloud-kit",
            {"owner": "the_big_boss"},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 40
    (
        (
            "PATCH",
            "/api/v1/registry/eits/portfolio/simple-cloud-kit",
            {"bizapp_name": "the awesome cloud kit"},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 41
    (
        ("DELETE", "/api/v1/registry/eits/portfolio/simple-cloud-kit", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Registry of Apps
    # Case 42
    (
        (
            "POST",
            "/api/v1/registry/eits/simple-cloud-kit/app",
            {"AppRegex": "^prn:simple-cloud-kit:api:.*:.*$"},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 43
    (
        ("GET", "/api/v1/registry/eits/simple-cloud-kit/apps", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 44
    (
        (
            "PUT",
            "/api/v1/registry/eits/simple-cloud-kit/app",
            {"AppRegex": "^prn:simple-cloud-kit:api:.*:.*$"},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 45
    (
        (
            "PATCH",
            "/api/v1/registry/eits/simple-cloud-kit/app",
            {"AppRegex": "^prn:simple-cloud-kit:api:.*:.*$"},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 46
    (
        (
            "DELETE",
            "/api/v1/registry/eits/simple-cloud-kit/app?AppRegex=%5Eprn%3Asimple-cloud-kit%3Aapi%3A.%2A%3A.%2A%24",
            {},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Registry of Zones
    # Case 47
    (
        (
            "POST",
            "/api/v1/registry/eits/simple-cloud-kit/zone",
            {"Zone": "simple-cloud-kit-api-production"},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 48
    (
        ("GET", "/api/v1/registry/eits/simple-cloud-kit/zones", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 49
    (
        (
            "PUT",
            "/api/v1/registry/eits/simple-cloud-kit/zone/simple-cloud-kit-core-api-prod",
            {"Zone": "simple-cloud-kit-api-production"},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 50
    (
        (
            "DELETE",
            "/api/v1/registry/eits/simple-cloud-kit/zone/simple-cloud-kit-core-api-prod",
            {},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Case 51
    (
        (
            "PATCH",
            "/api/v1/registry/eits/simple-cloud-kit/zone/simple-cloud-kit-core-api-prod",
            {"Zone": "simple-cloud-kit-api-production"},
        ),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
    # Get and Generate the FACTS context for a PRN
    # Case 52
    (
        ("GET", "/api/v1/facts/eits?prn=prn%3Asimple-cloud-kit%3Aapi%3Amain%3A1", {}),
        (200, {"status": "ok", "code": 200, "data": {}}),
    ),
]
