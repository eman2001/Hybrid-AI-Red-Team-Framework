"""
attack_graph/graph_builder.py
-------------------------------
Builds a directed attack graph (nodes = hosts/services, edges = exploit paths).
Uses networkx internally; Neo4j optional.
"""

try:
    import networkx as nx
    _NX = True
except ImportError:
    _NX = False


class GraphBuilder:

    def __init__(self):
        self.graph = nx.DiGraph() if _NX else None

    def build(self, findings: list[dict], attack_chain: dict) -> dict:
        """
        Returns a serialisable graph dict:
        {"nodes": [...], "edges": [...]}
        """
        nodes: dict[str, dict] = {}
        edges: list[dict] = []

        # Attacker node
        nodes["ATTACKER"] = {"id": "ATTACKER", "type": "attacker", "label": "Attacker"}

        for f in findings:
            nid = f"{f.get('host')}:{f.get('port')}"
            nodes[nid] = {
                "id":      nid,
                "host":    f.get("host"),
                "port":    f.get("port"),
                "service": f.get("service"),
                "type":    "target",
                "risk":    f.get("risk_score", 0),
            }

        # Edges from chain phases
        prev = "ATTACKER"
        for phase in sorted(attack_chain.values(), key=lambda p: p.get("tactic", "")):
            for host in phase.get("hosts", []):
                nid = host
                if nid not in nodes:
                    nodes[nid] = {"id": nid, "host": host, "type": "host"}
                edges.append({
                    "from":    prev,
                    "to":      nid,
                    "tactic":  phase.get("tactic"),
                    "technique": phase.get("techniques", [{}])[0].get("id", ""),
                })
                prev = nid

        # Build networkx graph if available
        if _NX and self.graph is not None:
            for nid, data in nodes.items():
                self.graph.add_node(nid, **data)
            for e in edges:
                self.graph.add_edge(e["from"], e["to"], **e)

        return {"nodes": list(nodes.values()), "edges": edges}
