"""Peek-a-Boo Flask dashboard — browse evidence, visualize graph, manage findings."""

import json
import os
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from pyvis.network import Network

from .graph import OSINTGraph
from .db import EvidenceDB
from .analysis import detect_bad_actor_patterns, calculate_risk_score, red2_campaign

app = Flask(__name__)

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
app.template_folder = TEMPLATE_DIR

db = EvidenceDB()
graph = OSINTGraph()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/evidence", methods=["GET", "POST"])
def api_evidence():
    if request.method == "POST":
        data = request.get_json()
        db.add(
            source_url=data.get("source_url", ""),
            excerpt=data.get("excerpt", ""),
            relevance=data.get("relevance", ""),
            notes=data.get("notes", ""),
        )
        return jsonify({"status": "added"}), 201
    else:
        return jsonify(db.list_all())


@app.route("/api/graph/stats")
def api_graph_stats():
    return jsonify(graph.stats())


@app.route("/api/graph/connected/<node_id>")
def api_graph_connected(node_id):
    depth = request.args.get("depth", 3, type=int)
    results = graph.find_all_connected(node_id, max_depth=depth)
    return jsonify([{"node": n, "type": d.get("type"), "data": d, "depth": dep} for n, d, dep in results])


@app.route("/api/analysis/flags")
def api_analysis_flags():
    return jsonify(detect_bad_actor_patterns(graph))


@app.route("/api/analysis/risk/<node_id>")
def api_analysis_risk(node_id):
    result = calculate_risk_score(graph, node_id)
    return jsonify(result or {"error": "node not found"})


@app.route("/graph-viz")
def graph_viz():
    """Render PyVis interactive graph."""
    net = Network(directed=True, height="750px", width="100%", bgcolor="#222222", font_color="white")
    node_colors = {
        "person": "#FF6B6B", "account": "#4ECDC4", "email": "#45B7D1",
        "phone": "#FFA07A", "domain": "#98D8C8", "ip": "#F7DC6F",
        "organization": "#C39BD3", "payment": "#F1948A", "device": "#85C1E9",
    }
    for n, data in graph.graph.nodes(data=True):
        color = node_colors.get(data.get("type", ""), "#97C2FC")
        net.add_node(n, label=n[:20], title=json.dumps(data), color=color, size=20)
    for src, dst, data in graph.graph.edges(data=True):
        net.add_edge(src, dst, title=data.get("relationship", ""), color="#888888")
    return render_template("graph.html")


if __name__ == "__main__":
    app.run(debug=True, port=5000)