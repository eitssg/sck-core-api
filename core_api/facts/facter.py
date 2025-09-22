"""
The Factor object is the "FACTS" database.  This object is DEPRECATED and should not be used.
This FACTS database should come from DynamoDB.  Not 'accounts.yaml' and 'apps.yaml' files.

(In re-rewrite.  We need to use DynamoDB instead of FACTS YAML files)
"""

from collections import ChainMap

from core_db.facter.actions import FactsActions

from ..request import RouteEndpoint
from ..response import Response

from ..actions import ApiActions


class ApiFactsActions(ApiActions, FactsActions):
    pass


def get_facts_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
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
                "AwsAccountId": "123456789012",
                "AwsAccountName": "example-account"
                "AwsRegion": "ap-southeast-1",
                "RegionAlias": "sin"
                "Tags": {
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
    qsp = query_params or {}
    pp = path_params or {}
    body = body or {}
    return ApiFactsActions.get(**dict(ChainMap(body, pp, qsp)))


# Define API Gateway routes
facts_actions: dict[str, RouteEndpoint] = {
    "GET:/api/v1/facts/{client}": RouteEndpoint(get_facts_action, permissions=["read:facts"]),
}
