"""
attack_graph/graph_analyzer.py
--------------------------------
Analyzes the attack graph for critical nodes, shortest paths, and centrality.
"""

try:
    import networkx as nx
    _NX = True
except ImportError:
    _NX = False


class GraphAnalyzer:

    def analyze(self, graph_data: dict) -> dict:
        nodes = [n["id"] for n in graph_data.get("nodes", [])]
        edges = [(e["from"], e["to"]) for e in graph_data.get("edges", [])]

        if not _NX or not nodes:
            return {"error": "networkx not available or empty graph"}

        G = nx.DiGraph()
        G.add_nodes_from(nodes)
        G.add_edges_from(edges)

        # Degree centrality — most connected nodes
        centrality = nx.degree_centrality(G)
        top_nodes  = sorted(centrality, key=centrality.get, reverse=True)[:5]

        # Shortest path from ATTACKER to each node
        paths = {}
        if "ATTACKER" in G:
            for node in nodes:
                if node == "ATTACKER":
                    continue
                try:
                    path = nx.shortest_path(G, "ATTACKER", node)
                    paths[node] = {"path": path, "hops": len(path) - 1}
                except nx.NetworkXNoPath:
                    paths[node] = {"path": [], "hops": -1}

        return {
            "total_nodes":   len(nodes),
            "total_edges":   len(edges),
            "top_nodes":     top_nodes,
            "centrality":    {k: round(v, 3) for k, v in centrality.items()},
            "shortest_paths": paths,
        }

    def critical_nodes(self, graph_data: dict) -> list[str]:
        analysis = self.analyze(graph_data)
        return analysis.get("top_nodes", [])
