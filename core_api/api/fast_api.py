"""FastAPI application configuration and lifecycle management."""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from core_api.api.apis import get_fast_api_router

# Assume your React build output is in a 'build' folder inside a 'frontend' directory
# at the same level as your 'core_api' directory.
# Adjust this path if your project structure is different.
FRONTEND_BUILD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class AppSingleton:
    __app: FastAPI | None = None
    running: bool = False

    @classmethod
    def get_app(cls) -> FastAPI:
        """Get or create FastAPI application instance."""
        if cls.__app is None:
            cls.__app = FastAPI(lifespan=lifespan)
            cls.__app.include_router(get_fast_api_router())

            # Mount the static files directory for your React app's assets (JS, CSS)
            cls.__app.mount(
                "/static",
                StaticFiles(directory=os.path.join(FRONTEND_BUILD_DIR, "static")),
                name="static",
            )

            # Add a catch-all route to serve the React app's index.html
            # This must be after all other API routes.
            @cls.__app.get("/{full_path:path}", response_class=FileResponse)
            async def serve_react_app(full_path: str):
                """Serve the React application for any path not caught by the API."""
                return os.path.join(FRONTEND_BUILD_DIR, "index.html")

        return cls.__app


def is_running() -> bool:
    """Check if the application is currently running."""
    return AppSingleton.running


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle.

    Args:
        app: FastAPI application instance
    """
    AppSingleton.running = True
    yield
    AppSingleton.running = False


def get_app() -> FastAPI:
    """Get FastAPI application instance."""
    return AppSingleton.get_app()


# Example usage: Create the app instance only when needed
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("core_automation.api.fast_api:get_app", factory=True, host="0.0.0.0", port=8000)
