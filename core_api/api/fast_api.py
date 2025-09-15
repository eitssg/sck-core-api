"""FastAPI application configuration and lifecycle management.

This module provides a singleton-based FastAPI application with integrated
static file serving for built React applications and proper API/frontend route separation.

The application serves:
- API routes under ``/api`` prefix with JSON responses
- Built React application files from npm build output
- Static assets from React build's ``assets`` folder
- SPA routing support for client-side navigation

Example:
    Basic usage::

        from core_api.api.fast_api import get_app

        app = get_app()

    Or with uvicorn::

        uvicorn core_api.api.fast_api:get_app --factory

Attributes:
    STATIC_DIR (str): Absolute path to the React build output directory
        containing index.html and assets folder from npm run build.
"""

from typing import Optional
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv, find_dotenv

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

import core_logging as log

from .router import get_api_router
from ..oauth.router import get_auth_router

from .headers import SimpleProxyHeadersMiddleware

# Static files are the built React application from npm run build


def get_static_dir() -> str:
    """Resolve the absolute path to the UI build (dist) folder.

    Resolution order (first existing wins):
    1. Env override SCK_UI_DIST or REACT_STATIC_DIR
    2. Monorepo default: <repo_root>/sck-core-ui/dist (calculated relative to this file)
    """

    # 1) Environment override
    env_static = os.getenv("SCK_UI_DIST") or os.getenv("REACT_STATIC_DIR")
    if env_static and os.path.exists(env_static):
        return os.path.abspath(env_static)

    # 2) Monorepo default: .../simple-cloud-kit/sck-core-ui/dist
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    candidate = os.path.join(repo_root, "sck-core-ui", "dist")
    return candidate


# Read allowed origins from env (comma-separated), fall back to known UI origins
def get_allow_origins() -> list[str]:

    return [
        o.strip()
        for o in os.getenv(
            "CORS_ALLOW_ORIGINS",
            "http://localhost:8080,http://127.0.0.1:8080,http://localhost:8090,http://127.0.0.1:8090,https://monster-jj.jvj28.com:2200",
        ).split(",")
        if o.strip()
    ]


def get_allow_credentials() -> bool:
    return os.getenv("CORS_ALLOW_CREDENTIALS", "True").lower() in ("true", "1", "yes")


__app: Optional[FastAPI] = None
__running: bool = False


def is_running() -> bool:
    """Check if the application is currently running.

    Returns:
        bool: True if the application is running, False otherwise.

    Example:
        .. code-block:: python

            if is_running():
                print("Application is active")
            else:
                print("Application is stopped")
    """

    return __running


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle events.

    This async context manager handles application startup and shutdown events,
    setting the running state appropriately during the application lifecycle.

    Args:
        app (FastAPI): The FastAPI application instance.

    Yields:
        None: Control is yielded back to FastAPI during normal operation.

    Note:
        This function is automatically called by FastAPI during application
        startup and shutdown. It should not be called directly.

    Example:
        The lifespan is automatically managed:

        .. code-block:: python

            # Application starts
            assert is_running() == True

            # Application runs normally
            # ...

            # Application shuts down
            assert is_running() == False
    """
    global __running

    __running = True
    log.info("FastAPI application started")

    yield

    __running = False
    log.info("FastAPI application shutdown")


def get_app() -> FastAPI:
    """Get or create the FastAPI application instance.

    Creates and configures a new FastAPI application if one doesn't exist,
    including API routes, static file mounting, and React SPA serving.

    The application configuration includes:
    - API routes mounted under ``/api`` prefix
    - React assets served from ``/assets`` path (matching React build output)
    - SPA routing support for React client-side navigation
    - Custom 404 handling for API vs frontend routes

    Returns:
        FastAPI: Configured FastAPI application instance.

    Note:
        This method is thread-safe and will always return the same
        application instance on subsequent calls.

    Example:
        .. code-block:: python

            app = AppSingleton.get_app()
            # Subsequent calls return the same instance
            same_app = AppSingleton.get_app()
            assert app is same_app  # True
    """
    global __app

    if __app is not None:
        return __app

    load_dotenv(find_dotenv(), override=False)

    __app = FastAPI(
        title="SCK Core API",
        description="Simple Cloud Kit Core API",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Must come early so downstream middleware sees the correct scheme/host/client
    __app.add_middleware(SimpleProxyHeadersMiddleware)

    __app.add_middleware(
        CORSMiddleware,
        allow_origins=get_allow_origins(),
        allow_credentials=get_allow_credentials(),
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
        max_age=86400,
    )

    # Include API routes with /api prefix (FIRST - highest priority). AWS API Gateway API proxy_forward to lambda handler
    __app.include_router(get_api_router(), prefix="/api", tags=["API"])

    # OAUTH server endpoints and authentication
    __app.include_router(get_auth_router(), prefix="/auth", tags=["Login", "OAuth", "Github", "Users"])

    # Dev-only metrics endpoint (Prometheus compatible)
    dev_metrics_enabled = os.getenv("SCK_DEV_METRICS", "0").lower() in ("1", "true", "yes")
    if dev_metrics_enabled:
        try:
            from core_api.dev.metrics import add_dev_metrics_endpoint  # type: ignore

            add_dev_metrics_endpoint(__app)
        except Exception as e:
            # Provide a stub /metrics in dev if prometheus_client isn't available
            log.warning(f"Dev metrics not enabled: {e}")

            @__app.get("/metrics")
            def metrics_disabled():  # type: ignore
                return PlainTextResponse(
                    "metrics disabled: set SCK_DEV_METRICS=true and install prometheus-client",
                    status_code=503,
                )

    static_dir = get_static_dir()

    @__app.get("/.well-known/oauth-authorization-server")
    async def oauth_discovery(request: Request) -> Response:
        """OAuth 2.0 Authorization Server Metadata (RFC 8414)"""
        return handle_oauth_discovery(request)

    # Health check endpoint (SECOND - before catch-all)
    @__app.get("/health", include_in_schema=False)
    async def health_check() -> Response:
        """Application health check endpoint.

        Returns system health information including React build status,
        static file directory existence, and application running state.

        Returns:
            Dict[str, Any]: Health status information with build verification.

        Example:
            .. code-block:: python

                # Access health check
                # GET /health

                # Response:
                {
                    "status": "healthy",
                    "running": true,
                    "react_build_exists": true,
                    "react_index_exists": true,
                    "react_assets_exists": true,
                    "static_dir": "/path/to/sck-core-ui/dist",
                    "assets_count": 3
                }
        """
        assets_dir = os.path.join(static_dir, "assets")
        index_path = os.path.join(static_dir, "index.html")

        return {
            "status": "healthy",
            "running": __running,
            "react_build_exists": os.path.exists(static_dir),
            "react_index_exists": os.path.exists(index_path),
            "react_assets_exists": os.path.exists(assets_dir),
            "static_dir": static_dir,
            "assets_count": (len(os.listdir(assets_dir)) if os.path.exists(assets_dir) else 0),
        }

    # Mount React assets folder for JS, CSS, images (THIRD)
    assets_dir = os.path.join(static_dir, "assets")
    if os.path.exists(assets_dir):
        log.info(f"Mounting React assets from: {assets_dir}")
        __app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")
    else:
        log.warning(f"React assets folder not found: {assets_dir}")

    # Custom 404 handler for API routes
    @__app.exception_handler(404)
    async def custom_404_handler(request: Request, exc: HTTPException):
        """Handle 404 errors specifically for API routes."""
        log.debug(f"404 Not Found: {request.url.path}")
        if request.url.path.startswith("/api/"):
            return JSONResponse(
                status_code=404,
                content={
                    "detail": "API endpoint not found",
                    "path": request.url.path,
                    "method": request.method,
                },
            )
        # Let the catch-all route handle non-API 404s
        raise exc

    log.info(f"Static files directory: {static_dir}")

    # Catch-all route for React SPA (MUST be last - lowest priority)
    @__app.get("/{full_path:path}", response_class=FileResponse, include_in_schema=False)
    async def serve_react_app(request: Request, full_path: str):
        """Serve React SPA for all non-API routes.

        This implements React client-side routing by serving the appropriate
        file for each request type:

        - Static assets: Served directly from disk
        - API routes: Return 404 (handled by API router)
        - Health endpoint: Already handled above
        - All other routes: Serve index.html for SPA routing

        Args:
            request (Request): The incoming HTTP request.
            full_path (str): The requested path (without leading slash).

        Returns:
            FileResponse: Either the requested file or React index.html.

        Raises:
            HTTPException: 404 if files are not found.
        """
        # Skip API routes - they should be handled by the API router with /api prefix
        if full_path.startswith("api"):  # Note: full_path doesn't include leading /
            raise HTTPException(status_code=404, detail="API endpoint not found")

        # Skip health route - it's already handled above
        if full_path == "health":
            raise HTTPException(status_code=404, detail="Health endpoint should be handled above")

        # Assets: serve directly as a fallback (StaticFiles mount should handle this first)
        if full_path.startswith("assets/"):
            asset_file = os.path.join(static_dir, full_path)
            if os.path.exists(asset_file):
                return FileResponse(asset_file)
            raise HTTPException(status_code=404, detail="Asset not found")

        # Check for root-level files first (favicon.ico, robots.txt, etc.)
        requested_file = os.path.join(static_dir, full_path)
        if os.path.isfile(requested_file):
            log.debug(f"Serving static file: {full_path}")
            return FileResponse(requested_file)

        # For all other routes (including root /), serve React index.html for SPA routing
        index_path = os.path.join(static_dir, "index.html")
        if os.path.exists(index_path):
            log.debug(f"Serving React SPA for route: /{full_path}")
            return FileResponse(
                index_path,
                media_type="text/html",
                headers={"Cache-Control": "no-cache"},  # Prevent caching of SPA routes
            )

        log.error(f"React application not found at: {index_path}")
        raise HTTPException(
            status_code=404,
            detail="React application not found. Run 'npm run build' in sck-core-ui first.",
        )

    return __app


# (Dev metrics implementation moved to core_api/dev/metrics.py)


def handle_oauth_discovery(request: Request) -> Response:
    """OAuth 2.0 Authorization Server Metadata (RFC 8414)."""

    # Get the host and protocol from headers
    host = request.headers.get("Host", "")
    # Check for forwarded protocol (common in reverse proxies/load balancers)
    protocol = request.headers.get("X-Forwarded-Proto", "https")
    base_url = f"{protocol}://{host}"

    # OAuth discovery data (RFC 8414 compliant)
    discovery_data = {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/auth/v1/authorize",
        "token_endpoint": f"{base_url}/auth/v1/token",
        "revocation_endpoint": f"{base_url}/auth/v1/revoke",
        "introspection_endpoint": f"{base_url}/auth/v1/introspect",
        "userinfo_endpoint": f"{base_url}/auth/v1/userinfo",
        "jwks_uri": f"{base_url}/auth/v1/jwks",
        "end_session_endpoint": f"{base_url}/auth/v1/logout",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        # ✅ UPDATED: Complete scopes list matching your Permission enum
        "scopes_supported": [
            # Profile scopes (OAuth format - what your frontend expects)
            "read:profile",
            "write:profile",
            # Portfolio scopes (OAuth format)
            "read:portfolio",
            "write:portfolio",
            "admin:portfolio",
            # Registry scopes (OAuth format)
            "read:registry",
            "write:registry",
            "admin:registry",
            "read:registry-client",
            "write:registry-client",
            "read:registry-portfolio",
            "write:registry-portfolio",
            # Application scopes (OAuth format)
            "read:app",
            "write:app",
            "admin:app",
            # Component scopes (OAuth format)
            "read:component",
            "write:component",
            "admin:component",
            # User management scopes (OAuth format)
            "read:user",
            "write:user",
            "manage:user",
            # Client management scopes (OAuth format)
            "read:client",
            "write:client",
            "manage:client",
            # AWS scopes (OAuth format)
            "read:aws",
            "write:aws",
            "admin:aws",
            "read:aws-billing",
            # System scopes (OAuth format)
            "config:system",
            "monitor:system",
            # Data scopes (OAuth format)
            "read:data",
            "write:data",
            "admin:data",
            # Wildcard scopes
            "*:read",
            "*:write",
            "*:admin",
            # Legacy scopes (for backward compatibility)
            "registry-clients:read",
            "registry-clients:write",
        ],
        "claims_supported": [
            "sub",
            "email",
            "name",
            "given_name",
            "family_name",
            "preferred_username",
            "updated_at",
            # ✅ Add profile-related claims
            "profile",
            "picture",
            "locale",
            "zoneinfo",
        ],
        # ✅ Add additional OAuth 2.0 metadata
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "request_uri_parameter_supported": False,
        "require_request_uri_registration": False,
        "claims_parameter_supported": False,
        "request_parameter_supported": False,
    }

    # Return discovery data directly (not wrapped)
    return JSONResponse(
        content=discovery_data,
        headers={"Cache-Control": "public, max-age=3600", "Content-Type": "application/json"},  # Cache for 1 hour
    )
