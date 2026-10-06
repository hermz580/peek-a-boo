"""OSINTGraph — NetworkX-based directed graph for storing and traversing investigation findings."""

import networkx as nx
from datetime import datetime


class OSINTGraph:
    """Stores every finding as a NODE and every connection as an EDGE in a directed graph."""

    def __init__(self):
        self.graph = nx.DiGraph()

    def add_node(self, node_id, node_type, evidence_url=None, **data):
        """Add a person, account, domain, email, phone, IP, organization, etc."""
        payload = {"type": node_type, "discovered_at": str(datetime.utcnow())}
        if evidence_url:
            payload["evidence_url"] = evidence_url
        payload.update(data)
        self.graph.add_node(node_id, **payload)

    def add_edge(self, source, target, relationship, evidence_url=None, confidence="medium", **extra):
        """Connect two nodes with a relationship and proof."""
        payload = {
            "relationship": relationship,
            "confidence": confidence,
            "discovered_at": str(datetime.utcnow()),
        }
        if evidence_url:
            payload["evidence_url"] = evidence_url
        payload.update(extra)
        self.graph.add_edge(source, target, **payload)

    def find_all_connected(self, node_id, max_depth=5):
        """BFS outward: return (node_id, node_data, depth) for every reachable node."""
        if node_id not in self.graph:
            return []
        visited = set()
        to_visit = [(node_id, 0)]
        results = []
        while to_visit:
            current, depth = to_visit.pop(0)
            if current in visited or depth > max_depth:
                continue
            visited.add(current)
            data = dict(self.graph.nodes[current])
            results.append((current, data, depth))
            for neighbor in self.graph.neighbors(current):
                if neighbor not in visited:
                    to_visit.append((neighbor, depth + 1))
        return results

    def find_path(self, source, target):
        """Shortest directed path between two nodes."""
        try:
            return nx.shortest_path(self.graph, source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def summary(self, node_id):
        """Details about a single node and its immediate relationships."""
        if node_id not in self.graph:
            return None
        node_data = dict(self.graph.nodes[node_id])
        in_edges = list(self.graph.in_edges(node_id, data=True))
        out_edges = list(self.graph.out_edges(node_id, data=True))
        return {
            "node": node_id,
            "type": node_data.get("type"),
            "data": node_data,
            "connected_to": len(in_edges) + len(out_edges),
            "incoming": len(in_edges),
            "outgoing": len(out_edges),
            "relationships": [e[2].get("relationship", "?") for e in in_edges + out_edges],
        }

    def stats(self):
        """Return basic graph statistics."""
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "node_types": {
                t: sum(1 for _, d in self.graph.nodes(data=True) if d.get("type") == t)
                for t in set(d.get("type", "unknown") for _, d in self.graph.nodes(data=True))
            },
        }

    def clear(self):
        self.graph.clear()