"""FastAPI application configuration and lifecycle management.

This module provides a singleton-based FastAPI application with integrated
static file serving for React applications and proper API/frontend route separation.

The application serves:
- API routes under ``/api`` prefix with JSON responses
- Static React application files with SPA routing support
- Custom 404 handling for API vs frontend routes

Example:
    Basic usage::

        from core_api.api.fast_api import get_app

        app = get_app()

    Or with uvicorn::

        uvicorn core_api.api.fast_api:get_app --factory

Attributes:
    STATIC_DIR (str): Absolute path to the static files directory containing
        the built React application files.
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from core_api.api.apis import get_fast_api_router

# Static files are located in core_api/static/
STATIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "static"))


class AppSingleton:
    """Singleton class for managing the FastAPI application instance.

    This class ensures only one FastAPI application instance exists throughout
    the application lifecycle, providing thread-safe access to the application
    and tracking its running state.

    Attributes:
        __app (FastAPI | None): Private FastAPI application instance.
        running (bool): Flag indicating if the application is currently running.
    """

    __app: FastAPI | None = None
    running: bool = False

    @classmethod
    def get_app(cls) -> FastAPI:
        """Get or create the FastAPI application instance.

        Creates and configures a new FastAPI application if one doesn't exist,
        including API routes, static file mounting, and custom error handlers.

        The application configuration includes:
        - API routes mounted under ``/api`` prefix
        - Static assets served from ``/assets`` endpoint
        - Custom 404 handling for API vs frontend routes
        - SPA routing support for React applications

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
            cls.__app.include_router(get_fast_api_router())

            # Custom 404 handler for API routes
            @cls.__app.exception_handler(404)
            async def custom_404_handler(request: Request, exc: HTTPException):
                print(f"404 Not Found: {request.url.path}")
                if request.url.path.startswith("/api/"):
                    return JSONResponse(status_code=404, content={"detail": "API endpoint not found", "path": request.url.path})
                # Let the static files mount handle non-API 404s
                raise exc

            # Serve index.html for root and SPA routes
            @cls.__app.get("/{full_path:path}", response_class=FileResponse)
            async def serve_react_app(full_path: str):
                # Skip API routes - let them go to the API router
                if full_path.startswith("api"):  # Note: no trailing slash, full_path doesn't include leading /
                    raise HTTPException(status_code=404, detail="API endpoint not found")

                # For all other routes, serve the React app
                index_path = os.path.join(STATIC_DIR, "index.html")
                if os.path.exists(index_path):
                    return FileResponse(index_path)
                else:
                    raise HTTPException(status_code=404, detail="Application not found")

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
    yield
    AppSingleton.running = False


def get_app() -> FastAPI:
    """Get the FastAPI application instance.

    This is the main factory function that should be used to obtain the
    FastAPI application instance. It delegates to the AppSingleton class
    to ensure consistent application configuration.

    Returns:
        FastAPI: Configured FastAPI application instance.

    Note:
        This function is suitable for use with uvicorn's ``--factory`` flag
        and other ASGI servers that expect a factory function.

    Example:
        Command-line usage with uvicorn::

            uvicorn core_api.api.fast_api:get_app --factory --host 0.0.0.0 --port 8000

        Programmatic usage::

            from core_api.api.fast_api import get_app
            import uvicorn

            app = get_app()
            uvicorn.run(app, host="0.0.0.0", port=8000)
    """
    return AppSingleton.get_app()
