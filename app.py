"""
app.py — FastAPI Application Entry Point
=========================================

Run with:

    uvicorn app:app --host 0.0.0.0 --port 8000 --reload

Swagger UI:
    http://localhost:8000/docs

ReDoc:
    http://localhost:8000/redoc
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from engine.config.settings import (
    API_HOST,
    API_PORT,
    CORS_ORIGINS,
    FRAMEWORK_NAME,
    FRAMEWORK_VERSION,
)

from engine.config.database import (
    init_db,
    ping,
)

from engine.config.logging_config import (
    setup_logging,
)

# ============================================================
# Engine API Routers
# ============================================================

from engine.modules.api.routes.scan import (
    router as scan_router,
)

from engine.modules.api.routes.vulnerabilities import (
    router as vulnerabilities_router,
)

from engine.modules.api.routes.mitre import (
    router as mitre_router,
)

from engine.modules.api.routes.analytics import (
    router as analytics_router,
)

from engine.modules.api.routes.attack_chain import (
    router as attack_chain_router,
)

from engine.modules.api.routes.attack_graph import (
    router as attack_graph_router,
)

from engine.modules.api.routes.threat_intelligence import (
    router as threat_intelligence_router,
)

from engine.modules.api.routes.report_routes import (
    router as report_router,
)

# ============================================================
# Backend Dashboard Routers
# ============================================================

from backend.api.dashboard import (
    router as dashboard_router,
)

from backend.api.activity import (
    router as activity_router,
)


# ============================================================
# Logging
# ============================================================

setup_logging()


# ============================================================
# FastAPI Application
# ============================================================

app = FastAPI(
    title=FRAMEWORK_NAME,
    version=FRAMEWORK_VERSION,
    description=(
        "Hybrid AI Red Team Framework — "
        "Offensive Security Assessment Platform. "
        "UCAS Cyber Security Engineering 2026. "
        "Authorized academic use only."
    ),
    contact={
        "name": "Hybrid AI Red Team Research",
        "email": "research@ucas.edu",
    },
    license_info={
        "name": "MIT",
    },
    docs_url="/docs",
    redoc_url="/redoc",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=(
        CORS_ORIGINS
        if CORS_ORIGINS
        else [
            "http://localhost:3000",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]
    ),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Router Registration
# ============================================================

app.include_router(scan_router)

app.include_router(vulnerabilities_router)

app.include_router(mitre_router)

app.include_router(analytics_router)

app.include_router(attack_chain_router)

app.include_router(attack_graph_router)

app.include_router(threat_intelligence_router)

app.include_router(report_router)

app.include_router(dashboard_router)

app.include_router(activity_router)


# ============================================================
# Startup
# ============================================================

@app.on_event("startup")
async def startup_event() -> None:
    """
    Initialize the database and verify connectivity
    when the FastAPI application starts.
    """

    init_db()

    database_connected = ping()

    print(
        "[App] Database: "
        f"{'✓ connected' if database_connected else '✗ unreachable'}"
    )

    print(
        f"[App] {FRAMEWORK_NAME} "
        f"v{FRAMEWORK_VERSION} started."
    )

    print(
        f"[App] Docs: "
        f"http://{API_HOST}:{API_PORT}/docs"
    )


# ============================================================
# Health Endpoints
# ============================================================

@app.get(
    "/",
    tags=["Health"],
)
async def root() -> dict:
    return {
        "framework": FRAMEWORK_NAME,
        "version": FRAMEWORK_VERSION,
        "status": "running",
        "docs": "/docs",
        "endpoints": [
            "/api/scan/run",
            "/api/progress",
            "/api/vulnerabilities/",
            "/api/threat-intelligence/",
            "/api/mitre/techniques",
            "/api/mitre/heatmap",
            "/api/attack-chain/",
            "/api/attack-graph/",
            "/api/analytics/dashboard",
            "/api/report/latest",
            "/api/activity/",
        ],
    }


@app.get(
    "/health",
    tags=["Health"],
)
async def health() -> dict:
    return {
        "status": "ok",
        "database": (
            "connected"
            if ping()
            else "unreachable"
        ),
    }


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=API_HOST,
        port=API_PORT,
        reload=True,
    )
