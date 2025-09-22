"""
This module contains the schemas for the core API for the APP Fact.

Each deployment will be conducted for a "client_portfolio" and will need to match
the regular expressions provided within the defintion.

typically the user will always perform action_get_list() to retrieve all the deployment defintions (There wont be many).

The user will then perform action_get_item() to retrieve the deployment definition for a specific app.

"""

from collections import ChainMap
from botocore.exceptions import ClientError
from botocore.config import Config

import core_logging as log

import core_framework as util
import core_helper.aws as aws

from core_db.registry.portfolio import PortfolioActions, PortfolioFact

from ..security import Permission
from ..request import ActionHandlerRoutes, RouteEndpoint
from ..actions import ApiActions
from ..response import Response, SuccessResponse, ErrorResponse, RedirectResponse


class ApiRegPortfolioActions(ApiActions, PortfolioActions):
    pass


def _merge_map(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> dict:
    pp = path_params or {}
    body = body or {}
    qsp = query_params or {}
    return dict(ChainMap(body, pp, qsp))


def list_portfolios_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    """
    Returns a list of all portfolios for the client.

    Specify client as a path parameter.

    The cilent is a slug.

    Ex:
        event = {
            PATH_PARAMETERS: {
                "client": "the_client"
            }
        }

    Args:
        event (): Http Request Object from API Gateway to lambda (lambda event)

    Returns:
        Response: AWS Api Gateway Response
    """
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = (path_params or {}).get("client")
    if "client" in merged:
        del merged["client"]

    log.debug(
        "List portfolios request",
        details={
            "client": client,
            "filters": merged,
        },
    )

    try:
        result = ApiRegPortfolioActions.list(client=client, **merged)

        # Minimal fields for the list view (snake_case names from PortfolioFact)
        include_fields = {
            "portfolio",  # unique id/slug
            "name",  # display title
            "project",  # optional description
            "icon_url",  # icon for card/list
            "category",  # facet/category
            "labels",  # chips/facets
            "portfolio_version",  # optional version tag
            "lifecycle_status",  # status pill
            "business_owner",  # owner summary
            "technical_owner",  # owner summary
            "domain",  # optional domain
            "app_count",  # number of apps in portfolio
            "updated_at",  # for sorting
        }

        # The DB returns data in PascalCase, but we want to return in snake_case
        data = [PortfolioFact(**item).model_dump(by_alias=False, include=include_fields, mode="json") for item in result.data]

        log.debug(
            f"Listed {len(data)} portfolios",
            details={
                "client": client,
                "count": len(data),
                "include_fields": sorted(include_fields),
            },
        )

        return SuccessResponse(data=data, metadata=result.metadata)

    except Exception as e:
        log.error("List portfolios failed", details={"client": client, "error": str(e)}, exc_info=True)
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def get_portfolio_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    """
    Returns a portfolio for the client.
    """
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = (path_params or {}).get("client")
    portfolio = (path_params or {}).get("portfolio")

    if "client" in merged:
        del merged["client"]
    if "portfolio" in merged:
        del merged["portfolio"]

    try:
        log.debug(
            "Get portfolio request",
            details={"client": client, "portfolio": portfolio, "filters": merged},
        )
        result = ApiRegPortfolioActions.get(client=client, portfolio=portfolio, **merged)

        data = PortfolioFact(**result.data).model_dump(by_alias=False)

        log.debug(
            "Get portfolio success",
            details={"client": client, "portfolio": portfolio},
        )
        return SuccessResponse(data=data)
    except Exception as e:
        log.error(
            "Get portfolio failed",
            details={"client": client, "portfolio": portfolio, "error": str(e)},
            exc_info=True,
        )
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def create_portfolio_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = (path_params or {}).get("client")

    if "client" in merged:
        del merged["client"]

    try:
        log.debug("Create portfolio request", details={"client": client, "payload": merged})
        result = ApiRegPortfolioActions.create(client=client, **merged)

        data = PortfolioFact(**result.data).model_dump(by_alias=False)

        log.debug("Create portfolio success", details={"client": client, "portfolio": data.get("portfolio")})
        return SuccessResponse(data=data)
    except Exception as e:
        log.error("Create portfolio failed", details={"client": client, "error": str(e)}, exc_info=True)
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def update_portfolio_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = (path_params or {}).get("client")
    portfolio = (path_params or {}).get("portfolio")

    if "client" in merged:
        del merged["client"]
    if "portfolio" in merged:
        del merged["portfolio"]

    try:
        log.debug(
            "Update portfolio request",
            details={"client": client, "portfolio": portfolio, "payload": merged},
        )
        result = ApiRegPortfolioActions.update(client=client, portfolio=portfolio, **merged)

        data = PortfolioFact(**result.data).model_dump(by_alias=False)

        log.debug("Update portfolio success", details={"client": client, "portfolio": portfolio})
        return SuccessResponse(data=data)
    except Exception as e:
        log.error(
            "Update portfolio failed",
            details={"client": client, "portfolio": portfolio, "error": str(e)},
            exc_info=True,
        )
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def patch_portfolio_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = (path_params or {}).get("client")
    portfolio = (path_params or {}).get("portfolio")

    if "client" in merged:
        del merged["client"]
    if "portfolio" in merged:
        del merged["portfolio"]

    try:
        log.debug(
            "Patch portfolio request",
            details={"client": client, "portfolio": portfolio, "payload": merged},
        )
        result = ApiRegPortfolioActions.patch(client=client, portfolio=portfolio, **merged)

        data = PortfolioFact(**result.data).model_dump(by_alias=False)

        log.debug("Patch portfolio success", details={"client": client, "portfolio": portfolio})
        return SuccessResponse(data=data)

    except Exception as e:
        log.error(
            "Patch portfolio failed",
            details={"client": client, "portfolio": portfolio, "error": str(e)},
            exc_info=True,
        )
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def delete_portfolio_action(*, query_params: dict = None, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    merged = _merge_map(query_params=query_params, body=body, **kwargs)

    client = (path_params or {}).get("client")
    portfolio = (path_params or {}).get("portfolio")

    if "client" in merged:
        del merged["client"]
    if "portfolio" in merged:
        del merged["portfolio"]

    try:
        log.debug(
            "Delete portfolio request",
            details={"client": client, "portfolio": portfolio},
        )

        ApiRegPortfolioActions.delete(client=client, portfolio=portfolio, **merged)

        log.debug("Delete portfolio success", details={"client": client, "portfolio": portfolio})
        return SuccessResponse(message="Portfolio deleted successfully")

    except Exception as e:
        log.error(
            "Delete portfolio failed",
            details={"client": client, "portfolio": portfolio, "error": str(e)},
            exc_info=True,
        )
        return ErrorResponse(code=500, message="Internal server error", exception=e)


def _get_key(portfolio: str, ext: str) -> str:
    """return the key for the portfolio icon with the given extension"""
    return f"artefacts/{portfolio}/icons/icon{ext}"


def _icon_s3_bucket_and_key(client: str, portfolio: str, filename: str | None = None) -> tuple[str, str]:
    """Compute deterministic S3 key for a portfolio icon within the client's artefact bucket.

    Uses path: artefacts/{portfolio}/icons/icon[.ext]
    If filename provided and has an extension, keep it; otherwise default to .png
    """
    region = util.get_artefact_bucket_region()
    bucket = util.get_artefact_bucket_name(client, region)

    ext = ""
    if filename and "." in filename:
        # take last extension, sanitize simple
        ext = "." + filename.rsplit(".", 1)[-1].lower()
        # normalize common content types by extension
        if ext not in (".png", ".jpg", ".jpeg", ".webp", ".svg"):
            ext = ".png"
    else:
        ext = ".png"

    key = _get_key(portfolio, ext)
    return bucket, key


def upload_portfolio_icon_action(*, path_params: dict = None, body: dict = None, **kwargs) -> Response:
    """Generate a presigned S3 PUT URL for uploading a portfolio icon.

    Request body (JSON): { fileName, contentType, fileSize }
    Response: { uploadUrl, method: "PUT", headers: { Content-Type, Cache-Control }, s3Bucket, s3Key, iconUrl, expiresIn }
    """
    path_params = path_params or {}
    body = body or {}
    client = path_params.get("client")
    portfolio = path_params.get("portfolio")

    file_name = body.get("fileName") or body.get("filename") or "icon.png"
    content_type = body.get("contentType") or "image/png"
    file_size = int(body.get("fileSize") or 0)

    if not client or not portfolio:
        return ErrorResponse(code=400, message="Missing client or portfolio")

    # Compute bucket/key
    bucket, key = _icon_s3_bucket_and_key(client, portfolio, file_name)

    # Cap allowed size to 5MB for icons
    max_size = 5 * 1024 * 1024
    if file_size and file_size > max_size:
        return ErrorResponse(code=413, message="Icon too large (max 5MB)")

    # Generate presigned PUT URL
    try:
        session = aws.get_session(region=util.get_artefact_bucket_region())
        s3 = session.client("s3", config=Config(signature_version="s3v4"))

        expires_seconds = 15 * 60
        params = {
            "Bucket": bucket,
            "Key": key,
            "ContentType": content_type,
        }
        # Include cache control via headers on PUT (stored as object metadata for some types)
        put_headers = {
            "Content-Type": content_type,
            "Cache-Control": "public, max-age=31536000, immutable",
        }

        upload_url = s3.generate_presigned_url(
            "put_object",
            Params=params,
            ExpiresIn=expires_seconds,
        )

        # Icon GET will be via our redirect endpoint (safer) but also include direct s3 URL info
        icon_url = f"/api/v1/registry/clients/{client}/portfolios/{portfolio}/icon"

        data = {
            "uploadUrl": upload_url,
            "method": "PUT",
            "headers": put_headers,
            "s3Bucket": bucket,
            "s3Key": key,
            "iconUrl": icon_url,
            "expiresIn": expires_seconds,
        }

        log.debug(
            "Generated presigned icon upload URL", details={"client": client, "portfolio": portfolio, "bucket": bucket, "key": key}
        )
        return SuccessResponse(data=data)
    except ClientError as e:
        log.error(
            "Failed to generate presigned URL", details={"error": str(e), "client": client, "portfolio": portfolio}, exc_info=True
        )
        return ErrorResponse(code=500, message="Failed to generate upload URL", exception=e)


def get_portfolio_icon_action(*, path_params: dict = None, **kwargs) -> Response:
    """Redirect to a short-lived presigned GET for the portfolio icon in the private bucket.

    If object not found, return 404.
    """
    path_params = path_params or {}
    client = path_params.get("client")
    portfolio = path_params.get("portfolio")

    if not client or not portfolio:
        return ErrorResponse(code=400, message="Missing client or portfolio")

    # Try common extensions in order of preference
    exts = [".webp", ".png", ".svg", ".jpg", ".jpeg"]
    region = util.get_artefact_bucket_region()
    bucket = util.get_artefact_bucket_name(client, region)
    session = aws.get_session(region=region)
    s3 = session.client("s3", config=Config(signature_version="s3v4"))

    key_found = None
    for ext in exts:
        key = _get_key(portfolio, ext)
        try:
            s3.head_object(Bucket=bucket, Key=key)
            key_found = key
            break
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in ("404", "NotFound", "NoSuchKey"):
                continue
            # Other error -> log and return 500
            log.error(
                "Error checking icon object",
                details={"client": client, "portfolio": portfolio, "bucket": bucket, "key": key, "error": str(e)},
            )
            return ErrorResponse(code=500, message="Error checking icon object", exception=e)

    if not key_found:
        return ErrorResponse(code=404, message="Icon not found")

    try:
        get_url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": key_found},
            ExpiresIn=60,  # short TTL for browsers
        )
        # 302 redirect to the signed URL
        resp = RedirectResponse(url=get_url)
        return resp
    except ClientError as e:
        log.error("Failed to presign icon GET", details={"client": client, "portfolio": portfolio, "error": str(e)}, exc_info=True)
        return ErrorResponse(code=500, message="Failed to get icon", exception=e)


registry_portfolio_actions: ActionHandlerRoutes = {
    "GET:/api/v1/registry/clients/{client}/portfolios": RouteEndpoint(
        list_portfolios_action,
        required_permissions={Permission.DATA_READ},
    ),
    "POST:/api/v1/registry/clients/{client}/portfolios": RouteEndpoint(
        create_portfolio_action,
        required_permissions={Permission.DATA_WRITE},
    ),
    "GET:/api/v1/registry/clients/{client}/portfolios/{portfolio}": RouteEndpoint(
        get_portfolio_action,
        required_permissions={Permission.DATA_READ},
    ),
    "PUT:/api/v1/registry/clients/{client}/portfolios/{portfolio}": RouteEndpoint(
        update_portfolio_action,
        required_permissions={Permission.DATA_WRITE},
    ),
    "DELETE:/api/v1/registry/clients/{client}/portfolios/{portfolio}": RouteEndpoint(
        delete_portfolio_action,
        required_permissions={Permission.DATA_WRITE},
    ),
    "PATCH:/api/v1/registry/clients/{client}/portfolios/{portfolio}": RouteEndpoint(
        patch_portfolio_action,
        required_permissions={Permission.DATA_WRITE},
    ),
    # Icon upload: returns presigned PUT URL and derived icon URL
    "POST:/api/v1/registry/clients/{client}/portfolios/{portfolio}/icon/upload": RouteEndpoint(
        lambda **kwargs: upload_portfolio_icon_action(**kwargs),
        required_permissions={Permission.DATA_WRITE},
    ),
    # Icon fetch: 302 redirect to presigned GET for private bucket object
    "GET:/api/v1/registry/clients/{client}/portfolios/{portfolio}/icon": RouteEndpoint(
        lambda **kwargs: get_portfolio_icon_action(**kwargs),
        required_permissions={Permission.DATA_READ},
    ),
}
