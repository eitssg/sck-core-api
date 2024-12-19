from contextlib import asynccontextmanager
from fastapi import FastAPI
from core_api.api.apis import get_fast_api_router

static_content_models = {}


def is_running():
    return "running" in static_content_models


@asynccontextmanager
async def lifespan(app: FastAPI):
    static_content_models["running"] = True
    yield
    static_content_models.clear()


def get_app() -> FastAPI:
    app = FastAPI(lifespan=lifespan)
    app.include_router(get_fast_api_router())
    return app


# Example usage: Create the app instance only when needed
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "core_automation.api.fast_api:get_app", factory=True, host="0.0.0.0", port=8000
    )
