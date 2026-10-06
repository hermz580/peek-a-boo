# peek-a-boo

Advanced OSINT tool for investigating scam rings, botnets, phishing campaigns, and fraud operations.

## Features
- Search intake (name, username, business, website) with optional context
- Public‑source aggregation (WHOIS, DNS, social profiles, news, breach databases)
- Identity‑check heuristics to avoid false matches
- Evidence cards stored in SQLite (source URL, excerpt, date, relevance)
- Removal tracker for self‑footprint cleanup
- Graph‑based storage using NetworkX (nodes = persons/accounts/domains/etc.)
- Bad‑actor detection layer (reuse, IP clustering, account‑factory, etc.)
- Flask web UI to browse evidence and graph visualisation (PyVis)

## Quick start
```bash
# Clone the repo (already done)
cd peek-a-boo
python -m venv venv
venv\Scripts\activate   # Windows
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000 in a browser.

## License
MIT – feel free to customize for your own investigations.
