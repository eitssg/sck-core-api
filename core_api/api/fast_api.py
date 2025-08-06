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

import os
import core_logging as log
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from core_api.api.apis import get_fast_api_router

# Static files are the built React application from npm run build
STATIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "sck-core-ui", "dist"))


class AppSingleton:
    """Singleton class for managing the FastAPI application instance.

    This class ensures only one FastAPI application instance exists throughout
    the application lifecycle, providing thread-safe access to the application
    and tracking its running state.

    Attributes:
        __app (FastAPI | None): Private FastAPI application instance.
        running (bool): Flag indicating if the application is currently running.
    """

    __app: Optional[FastAPI] = None
    running: bool = False

    @classmethod
    def get_app(cls) -> FastAPI:
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
        if cls.__app is None:
            cls.__app = FastAPI(title="SCK Core API", description="Simple Cloud Kit Core API", version="1.0.0", lifespan=lifespan)

            # Include API routes with /api prefix (FIRST - highest priority)
            cls.__app.include_router(get_fast_api_router(), prefix="/api", tags=["API"])

            # Health check endpoint (SECOND - before catch-all)
            @cls.__app.get("/health", include_in_schema=False)
            async def health_check():
                """Application health check endpoint.

                Returns system health information including React build status,
                static file directory existence, and application running state.

                Returns:
                    Dict[str, Any]: Health status information with build verification.

                Example:
                    .. code-block:: python

                        # Access health check
                        # GET http://localhost:8000/health

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
                assets_dir = os.path.join(STATIC_DIR, "assets")
                index_path = os.path.join(STATIC_DIR, "index.html")

                return {
                    "status": "healthy",
                    "running": cls.running,
                    "react_build_exists": os.path.exists(STATIC_DIR),
                    "react_index_exists": os.path.exists(index_path),
                    "react_assets_exists": os.path.exists(assets_dir),
                    "static_dir": STATIC_DIR,
                    "assets_count": len(os.listdir(assets_dir)) if os.path.exists(assets_dir) else 0,
                }

            # Mount React assets folder for JS, CSS, images (THIRD)
            assets_dir = os.path.join(STATIC_DIR, "assets")
            if os.path.exists(assets_dir):
                log.info(f"Mounting React assets from: {assets_dir}")
                cls.__app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")
            else:
                log.warning(f"React assets folder not found: {assets_dir}")

            # Custom 404 handler for API routes
            @cls.__app.exception_handler(404)
            async def custom_404_handler(request: Request, exc: HTTPException):
                """Handle 404 errors specifically for API routes."""
                log.debug(f"404 Not Found: {request.url.path}")
                if request.url.path.startswith("/api/"):
                    return JSONResponse(
                        status_code=404,
                        content={"detail": "API endpoint not found", "path": request.url.path, "method": request.method},
                    )
                # Let the catch-all route handle non-API 404s
                raise exc

            log.info(f"Static files directory: {STATIC_DIR}")

            # Catch-all route for React SPA (MUST be last - lowest priority)
            @cls.__app.get("/{full_path:path}", response_class=FileResponse, include_in_schema=False)
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
                requested_file = os.path.join(STATIC_DIR, full_path)
                if os.path.isfile(requested_file):
                    log.debug(f"Serving static file: {full_path}")
                    return FileResponse(requested_file)

                # For all other routes (including root /), serve React index.html for SPA routing
                index_path = os.path.join(STATIC_DIR, "index.html")
                if os.path.exists(index_path):
                    log.debug(f"Serving React SPA for route: /{full_path}")
                    return FileResponse(
                        index_path, media_type="text/html", headers={"Cache-Control": "no-cache"}  # Prevent caching of SPA routes
                    )
                else:
                    log.error(f"React application not found at: {index_path}")
                    raise HTTPException(
                        status_code=404, detail="React application not found. Run 'npm run build' in sck-core-ui first."
                    )

        return cls.__app


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
    return AppSingleton.running


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
    AppSingleton.running = True
    log.info("FastAPI application started")
    yield
    AppSingleton.running = False
    log.info("FastAPI application shutdown")


def get_app() -> FastAPI:
    """Get the FastAPI application instance.

    This is the main factory function that should be used to obtain the
    FastAPI application instance. It delegates to the AppSingleton class
    to ensure consistent application configuration.

    The returned application serves your exact React build structure:

    .. code-block:: text

        sck-core-ui/dist/
        ├── index.html          → Served for SPA routes
        ├── robots.txt          → Served directly
        ├── placeholder.svg     → Served directly
        ├── assets/             → Mounted at /assets
        │   ├── index-abc123.js → http://localhost:8000/assets/index-abc123.js
        │   ├── index-def456.css→ http://localhost:8000/assets/index-def456.css
        │   └── logo-ghi789.png → http://localhost:8000/assets/logo-ghi789.png
        └── favicon.ico         → Served directly

    Returns:
        FastAPI: Configured FastAPI application instance.

    Note:
        This function is suitable for use with uvicorn's ``--factory`` flag
        and other ASGI servers that expect a factory function.

    Example:
        Build and serve React application::

            # Build React app first
            cd sck-core-ui
            npm run build

            # Start FastAPI server
            uvicorn core_api.api.fast_api:get_app --factory --host 0.0.0.0 --port 8000

        Access points for your structure::

            # React application (SPA routes)
            http://localhost:8000/                    → index.html
            http://localhost:8000/dashboard           → index.html (client routing)
            http://localhost:8000/portfolios/123      → index.html (client routing)

            # API endpoints
            http://localhost:8000/api/portfolios      → API routes
            http://localhost:8000/api/health          → Health check

            # Static assets (from assets/ folder)
            http://localhost:8000/assets/index-abc123.js   → JS bundle
            http://localhost:8000/assets/index-def456.css  → CSS bundle
            http://localhost:8000/assets/logo-ghi789.png   → Images

            # Root-level files
            http://localhost:8000/favicon.ico         → Favicon
            http://localhost:8000/robots.txt          → Robots file
            http://localhost:8000/placeholder.svg     → SVG file
    """
    return AppSingleton.get_app()
