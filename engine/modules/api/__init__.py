"""
modules/api/__init__.py
------------------------
FastAPI application factory.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from engine.modules.api.routes import ALL_ROUTERS
from engine.modules.api.middleware.logging_middleware import LoggingMiddleware
from engine.config.settings import FRAMEWORK_NAME, FRAMEWORK_VERSION


def create_app() -> FastAPI:
    app = FastAPI(
        title=FRAMEWORK_NAME,
        version=FRAMEWORK_VERSION,
        description="Hybrid AI Red Team Simulation Framework — REST API",
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Request logging
    app.add_middleware(LoggingMiddleware)

    # Register all routers
    for router in ALL_ROUTERS:
        app.include_router(router)

    @app.get("/")
    async def root():
        return {"framework": FRAMEWORK_NAME, "version": FRAMEWORK_VERSION, "status": "running"}

    @app.get("/health")
    async def health():
        from engine.config.database import ping
        return {"status": "ok", "db": ping()}

    return app
