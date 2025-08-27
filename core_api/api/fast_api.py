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
from fastapi.responses import FileResponse, JSONResponse

import core_logging as log

from .router import get_api_router
from ..oauth.router import get_auth_router

from .headers import SimpleProxyHeadersMiddleware

# Static files are the built React application from npm run build


def get_static_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "sck-core-ui", "dist"))


# Read allowed origins from env (comma-separated), fall back to known UI origins
def get_origins() -> list[str]:

    return [
        o.strip()
        for o in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:8080,http://127.0.0.1:8080,http://localhost:8090,http://127.0.0.1:8090,https://monster-jj.jvj28.com:2200",
        ).split(",")
        if o.strip()
    ]


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
        allow_origins=get_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
        max_age=86400,
    )

    # Include API routes with /api prefix (FIRST - highest priority). AWS API Gateway API proxy_forward to lambda handler
    __app.include_router(get_api_router(), prefix="/api", tags=["API"])

    # OAUTH server endpoints and authentication
    __app.include_router(get_auth_router(), prefix="/auth", tags=["Login", "OAuth", "Github", "Users"])

    static_dir = get_static_dir()

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

        # Skip assets routes - they're handled by the StaticFiles mount
        if full_path.startswith("assets/"):
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
