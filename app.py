import os
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for
import sqlite3
import networkx as nx
from pyvis.network import Network

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), 'osint.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_url TEXT NOT NULL,
            excerpt TEXT,
            date_checked TEXT,
            relevance TEXT,
            notes TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Simple in-memory graph for demo; in production persist to file if needed
graph = nx.DiGraph()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/evidence', methods=['GET', 'POST'])
def evidence():
    if request.method == 'POST':
        data = request.get_json()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('INSERT INTO evidence (source_url, excerpt, date_checked, relevance, notes) VALUES (?, ?, ?, ?, ?)',
                  (data.get('source_url'), data.get('excerpt'), data.get('date_checked', datetime.utcnow().isoformat()),
                   data.get('relevance'), data.get('notes')))
        conn.commit()
        conn.close()
        return jsonify({'status': 'added'}), 201
    else:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT * FROM evidence')
        rows = c.fetchall()
        conn.close()
        cols = ['id', 'source_url', 'excerpt', 'date_checked', 'relevance', 'notes']
        results = [dict(zip(cols, row)) for row in rows]
        return jsonify(results)

@app.route('/graph')
def view_graph():
    net = Network(directed=True, height='750px', width='100%')
    for n, data in graph.nodes(data=True):
        net.add_node(n, label=str(n), title=json.dumps(data), color='#97C2FC')
    for src, dst, data in graph.edges(data=True):
        net.add_edge(src, dst, title=data.get('relationship',''), color='#CCCCCC')
    html_path = os.path.join('templates', 'graph.html')
    net.show(html_path)
    return render_template('graph.html')

if __name__ == '__main__':
    app.run(debug=True)
