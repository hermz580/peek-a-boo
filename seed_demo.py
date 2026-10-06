"""Seed the Flask app's in-memory graph with demo investigation data for Herman Harp."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from peekaboo.app import app, db, graph
from peekaboo.sources import search_usernames, get_dns_records, get_whois
from peekaboo.analysis import detect_bad_actor_patterns, calculate_risk_score

# Person node
graph.add_node("person_harpstar", "person", name="Herman Harp", aliases="HarpStar")

# Domain
graph.add_node("domain_harpstarunlimited", "domain", domain="harpstarunlimited.com")
graph.add_edge("person_harpstar", "domain_harpstarunlimited", "owns_domain", confidence="high")

# DNS
dns = get_dns_records("harpstarunlimited.com")
for ip in dns.get("A", []):
    ip_id = f"ip_{ip.replace('.','_')}"
    graph.add_node(ip_id, "ip", address=ip)
    graph.add_edge("domain_harpstarunlimited", ip_id, "resolves_to", confidence="high")

# Whois
whois = get_whois("harpstarunlimited.com")
if "error" not in whois:
    graph.add_node("whois_harpstarunlimited", "person", **{k:v for k,v in whois.items() if k != "error"})
    graph.add_edge("domain_harpstarunlimited", "whois_harpstarunlimited", "registered_to", confidence="high")

# Username scan
profiles = search_usernames("harpstar")
for p in profiles:
    plat = p["platform"].replace(".", "_")
    nid = f"account_{plat}"
    graph.add_node(nid, "account", username="harpstar", platform=p["platform"])
    graph.add_edge("person_harpstar", nid, "owns_account", evidence_url=p["url"], confidence="high")

# Evidence DB
db.add(source_url="https://harpstarunlimited.com", excerpt="Personal portal", relevance="Own domain", node_type="domain", node_id="domain_harpstarunlimited")
for p in profiles:
    db.add(source_url=p["url"], excerpt=f"{p['platform']} profile", relevance="Own account", node_type="account", node_id=f"account_{p['platform'].replace('.','_')}")

print(f"Seeded graph: {graph.stats()}")
print(f"Seeded evidence: {len(db.list_all())} cards")
print(f"Flags: {len(detect_bad_actor_patterns(graph))}")