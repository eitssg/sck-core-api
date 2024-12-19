# Current version of the REST API (.e.g:  https://www.myserver.com/api/v1/{proxy+})
API_VERSION = "v1"
API_PREFIX = f"/api/{API_VERSION}"

# API Gateway event fields
QUERY_STRING_PARAMETERS = "queryStringParameters"
PATH_PARAMETERS = "pathParameters"
BODY_PARAMETER = "body"

# Facts Fields / And Table Types for the Registry
CLIENT_FACTS = "ClientFacts"
PORTFOLIO_FACTS = "PortfolioFacts"
ZONE_FACTS = "ZoneFacts"
APP_FACTS = "AppFacts"

# Type Types for the Events and Deployments
EVENTS = "Events"
ITEMS = "Items"

PRN = "prn"
ITEM_TYPE = "item_type"
EVENT_TYPE = "event_type"

# Attributes of Portfolio Facts
APPROVERS = "Approvers"
CONTACTS = "Contacts"
OWNER = "Owner"
REGION = "Region"
ENVIRONMENT = "Environment"

# Registry Model Hash Keys (yes, client and portfoio are lowercase)
CLIENT_KEY = "client"
PORTFOLIO_KEY = "portfolio"
CLIENT_PORTFOLIO_KEY = "ClientPortfolio"

# Registry Range Keys
APP_KEY = "AppRegex"
ZONE_KEY = "Zone"

# These are fields in the items table "core-automation-items"
PRN = "prn"
PARENT_PRN = "parent_prn"
NAME = "name"
ITEM_TYPE = "item_type"
CONTACT_EMAIL = "contact_email"

# MapAttribute fields
APP_PRN = "app_prn"
PORTFOLIO_PRN = "portfolio_prn"
BUILD_PRN = "build_prn"
BRANCH_PRN = "branch_prn"
COMPONENT_PRN = "component_prn"
SHORT_NAME = "short_name"

# Fields For build and component releases
STATUS = "status"
RELEASED_BUILD_PRN = "released_build_prn"
RELEASED_BUILD = "released_build"

# Date fields
UPDATED_AT = "updated_at"
CREATED_AT = "created_at"

# Query tags (for pagenation)
EARLIEST_TIME = "earliest_time"
LATEST_TIME = "latest_time"
DATA_PAGINATOR = "data_paginator"
SORT = "sort"
LIMIT = "limit"
ASCENDING = "ascending"
