"""
api/routes/attack_graph.py — Attack Graph API
"""
from fastapi import APIRouter
from engine.modules.api.schemas import AttackGraphResponse, GraphNodeOut
from engine.modules.attack_graph.graph_builder import GraphBuilder

router = APIRouter(prefix="/api/attack-graph", tags=["Attack Graph"])

DEMO_FINDINGS = [
    {"host":"192.168.1.100","port":21, "service":"ftp",  "risk_score":95,"cve":"CVE-2011-2523"},
    {"host":"192.168.1.100","port":445,"service":"smb",  "risk_score":88,"cve":"CVE-2007-2447"},
    {"host":"192.168.1.100","port":80, "service":"http", "risk_score":84,"cve":"CVE-2017-7679"},
    {"host":"192.168.1.100","port":22, "service":"ssh",  "risk_score":52,"cve":"CVE-2008-0166"},
]
DEMO_CHAIN = {
    "1": {"tactic":"initial-access",  "techniques":[{"id":"T1190","name":"Exploit Public-Facing App"}],"hosts":["192.168.1.100"]},
    "2": {"tactic":"lateral-movement","techniques":[{"id":"T1210","name":"Remote Services"}],          "hosts":["192.168.1.100"]},
    "3": {"tactic":"credential-access","techniques":[{"id":"T1003","name":"Credential Dumping"}],      "hosts":["192.168.1.100"]},
}


@router.get("/", response_model=AttackGraphResponse)
async def get_graph():
    """Return full attack graph nodes and edges."""
    builder = GraphBuilder()
    graph   = builder.build(DEMO_FINDINGS, DEMO_CHAIN)
    nodes   = [GraphNodeOut(id=n["id"], type=n.get("type","host"),
                            host=n.get("host",""), port=n.get("port",0),
                            service=n.get("service",""), risk=n.get("risk",0.0))
               for n in graph["nodes"]]
    return AttackGraphResponse(
        node_count    = len(graph["nodes"]),
        edge_count    = len(graph["edges"]),
        nodes         = nodes,
        edges         = graph["edges"],
        critical_path = ["ATTACKER", "192.168.1.100:21", "192.168.1.100"],
    )


@router.get("/nodes")
async def get_nodes():
    builder = GraphBuilder()
    graph   = builder.build(DEMO_FINDINGS, DEMO_CHAIN)
    return {"nodes": graph["nodes"], "count": len(graph["nodes"])}


@router.get("/edges")
async def get_edges():
    builder = GraphBuilder()
    graph   = builder.build(DEMO_FINDINGS, DEMO_CHAIN)
    return {"edges": graph["edges"], "count": len(graph["edges"])}


@router.get("/critical-nodes")
async def critical_nodes():
    """Return nodes with highest risk score (critical pivot points)."""
    critical = sorted(DEMO_FINDINGS, key=lambda f: f["risk_score"], reverse=True)[:3]
    return {
        "critical_nodes": [
            {"host": f["host"], "port": f["port"], "service": f["service"],
             "risk_score": f["risk_score"], "cve": f["cve"]}
            for f in critical
        ],
        "description": "Nodes that would give highest attacker leverage if compromised."
    }


@router.get("/export/json")
async def export_graph_json():
    """Export graph as D3.js / vis.js compatible JSON."""
    builder = GraphBuilder()
    graph   = builder.build(DEMO_FINDINGS, DEMO_CHAIN)
    return {
        "graph": graph,
        "meta": {"format": "d3-force", "version": "1.0", "framework": "Red Team AI"}
    }
