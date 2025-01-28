"""FastAPI application configuration and lifecycle management."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from core_api.api.apis import get_fast_api_router


class AppSingtletone:
    __app: FastAPI | None = None
    running: bool = False

    @classmethod
    def get_app(cls) -> FastAPI:
        """Get or create FastAPI application instance."""
        if cls.__app is None:
            cls.__app = FastAPI(lifespan=lifespan)
            cls.__app.include_router(get_fast_api_router())
        return cls.__app


def is_running() -> bool:
    """Check if the application is currently running."""
    return AppSingtletone.running


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle.

    Args:
        app: FastAPI application instance
    """
    AppSingtletone.running = True
    yield
    AppSingtletone.running = False


def get_app() -> FastAPI:
    """Get FastAPI application instance."""
    return AppSingtletone.get_app()


# Example usage: Create the app instance only when needed
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "core_automation.api.fast_api:get_app", factory=True, host="0.0.0.0", port=8000
    )
