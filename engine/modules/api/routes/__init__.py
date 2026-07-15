"""modules/api/routes/__init__.py"""
from engine.modules.api.routes.scan               import router as scan_router
from engine.modules.api.routes.vulnerabilities    import router as vuln_router
from engine.modules.api.routes.mitre              import router as mitre_router
from engine.modules.api.routes.analytics          import router as analytics_router
from engine.modules.api.routes.attack_chain       import router as chain_router
from engine.modules.api.routes.attack_graph       import router as graph_router
from engine.modules.api.routes.threat_intelligence import router as ti_router

ALL_ROUTERS = [scan_router, vuln_router, mitre_router, analytics_router,
               chain_router, graph_router, ti_router]
