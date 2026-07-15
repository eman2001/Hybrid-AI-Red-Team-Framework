"""
attack_graph/networkx_builder.py
----------------------------------
Builds a networkx DiGraph directly from scan + chain data.
Keeps graph_builder.py clean by isolating networkx specifics here.
"""

try:
    import networkx as nx
    _NX = True
except ImportError:
    _NX = False


class NetworkxBuilder:

    def build(self, graph_data: dict):
        """Returns a nx.DiGraph or None if networkx unavailable."""
        if not _NX:
            return None

        G = nx.DiGraph()
        for node in graph_data.get("nodes", []):
            G.add_node(node["id"], **node)
        for edge in graph_data.get("edges", []):
            G.add_edge(edge["from"], edge["to"],
                       tactic=edge.get("tactic", ""),
                       technique=edge.get("technique", ""))
        return G

    def to_dict(self, G) -> dict:
        if G is None:
            return {}
        return {
            "nodes": [{"id": n, **d} for n, d in G.nodes(data=True)],
            "edges": [{"from": u, "to": v, **d} for u, v, d in G.edges(data=True)],
        }

    def summary(self, G) -> dict:
        if G is None:
            return {}
        return {
            "nodes": G.number_of_nodes(),
            "edges": G.number_of_edges(),
            "is_dag": nx.is_directed_acyclic_graph(G),
            "density": round(nx.density(G), 4),
        }
