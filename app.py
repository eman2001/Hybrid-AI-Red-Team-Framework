"""
app.py — FastAPI Application Entry Point
=========================================
Run with:
    uvicorn app:app --host 0.0.0.0 --port 8000 --reload

Swagger UI:  http://localhost:8000/docs
ReDoc:       http://localhost:8000/redoc
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from engine.config.settings  import FRAMEWORK_NAME, FRAMEWORK_VERSION, API_HOST, API_PORT
from engine.config.database  import init_db, ping
from engine.config.logging_config import setup_logging

from backend.api.dashboard import router as dashboard_router
from engine.modules.api.routes import (
    scan_router, vuln_router, mitre_router,
    analytics_router, chain_router, graph_router, ti_router,
)

# ── Logging ───────────────────────────────────────────────────
setup_logging()

# ── App ───────────────────────────────────────────────────────
app = FastAPI(
    title       = FRAMEWORK_NAME,
    version     = FRAMEWORK_VERSION,
    description = (
        "Hybrid AI Red Team Simulation Framework — "
        "UCAS Cyber Security Engineering 2026. "
        "Academic use only. No real exploitation."
    ),
    contact     = {"name": "Red Team AI Research", "email": "research@ucas.edu"},
    license_info= {"name": "MIT"},
    docs_url    = "/docs",
    redoc_url   = "/redoc",
)

# ── CORS (allow frontend on localhost:3000 / 5173) ────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins = ["*"],
    allow_methods   = ["*"],
    allow_headers   = ["*"],
    allow_credentials = True,
)

# ── Routers ───────────────────────────────────────────────────
for router in [scan_router, vuln_router, mitre_router,
               analytics_router, chain_router, graph_router, ti_router]:
    app.include_router(router)


# Dashboard API
app.include_router(dashboard_router)

# ── Startup / shutdown ────────────────────────────────────────
@app.on_event("startup")
async def startup():
    init_db()
    db_ok = ping()
    print(f"[App] Database: {'✓ connected' if db_ok else '✗ unreachable'}")
    print(f"[App] {FRAMEWORK_NAME} v{FRAMEWORK_VERSION} started.")
    print(f"[App] Docs: http://{API_HOST}:{API_PORT}/docs")

# ── Root ──────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
async def root():
    return {
        "framework": FRAMEWORK_NAME,
        "version":   FRAMEWORK_VERSION,
        "status":    "running",
        "docs":      "/docs",
        "endpoints": [
            "/api/scan/run",
            "/api/vulnerabilities/",
            "/api/threat-intelligence/",
            "/api/mitre/techniques",
            "/api/attack-chain/",
            "/api/attack-graph/",
            "/api/analytics/dashboard",
        ],
    }

@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "db": ping()}

# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=API_HOST, port=API_PORT, reload=True)
