"""Bad-actor pattern detection, risk scoring, and Red2 campaign bridge."""

import os
import json
from datetime import datetime

RED2_LAB_DIR = os.environ.get(
    "RED2_LAB_DIR",
    os.path.expanduser("~/AppData/Local/hermes/cache/scratch/red2-lab"),
)
CAMPAIGNS_DIR = os.path.join(RED2_LAB_DIR, "campaigns")


# ── Bad-actor pattern detection ──

def detect_bad_actor_patterns(osint_graph):
    """Scan the graph for red flags: reused identifiers, IP clustering, account factories."""
    red_flags = []

    # FLAG 1: Same identifier reused across unrelated platforms
    account_nodes = [
        n for n, d in osint_graph.graph.nodes(data=True)
        if d.get("type") == "account"
    ]
    seen_usernames = {}
    for node in account_nodes:
        username = osint_graph.graph.nodes[node].get("username", "")
        if not username:
            continue
        seen_usernames.setdefault(username, []).append(node)

    for username, nodes in seen_usernames.items():
        if len(nodes) > 4:
            red_flags.append({
                "type": "username_reuse",
                "severity": "HIGH",
                "indicator": username,
                "appearances": len(nodes),
                "reason": f"Username '{username}' on {len(nodes)}+ platforms — operational identity",
            })

    # FLAG 2: Multiple identities pointing to same IP
    ip_nodes = [
        n for n, d in osint_graph.graph.nodes(data=True)
        if d.get("type") == "ip"
    ]
    for ip_node in ip_nodes:
        connected = osint_graph.find_all_connected(ip_node, max_depth=2)
        identity_count = len([
            n for n, _d, depth in connected
            if osint_graph.graph.nodes[n].get("type") in ("person", "email", "phone")
        ])
        if identity_count > 2:
            red_flags.append({
                "type": "ip_clustering",
                "severity": "CRITICAL",
                "indicator": ip_node,
                "identities": identity_count,
                "reason": f"{identity_count} identities from single IP — coordinated operation",
            })

    # FLAG 3: Timing anomalies — account creation bursts
    account_dates = []
    for n in account_nodes:
        created = osint_graph.graph.nodes[n].get("created_at")
        if created:
            try:
                dt = datetime.fromisoformat(created) if isinstance(created, str) else created
                account_dates.append((n, dt))
            except (ValueError, TypeError):
                pass
    account_dates.sort(key=lambda x: x[1])
    for i in range(len(account_dates) - 4):
        window = account_dates[i:i + 5]
        span = (window[-1][1] - window[0][1]).total_seconds()
        if span < 86400:  # 24 hours
            red_flags.append({
                "type": "account_factory",
                "severity": "HIGH",
                "indicator": [n for n, _ in window],
                "accounts_in_24h": 5,
                "reason": "5+ accounts created in under 24h — bot farming or ban evasion",
            })
            break  # One factory is enough

    return red_flags


# ── Risk scoring ──

def calculate_risk_score(osint_graph, target_node_id):
    """Generate a 0-100 risk score for a node based on graph patterns."""
    if target_node_id not in osint_graph.graph:
        return None

    score = 0
    evidence = []
    target = dict(osint_graph.graph.nodes[target_node_id])

    # +50: Found in breach database
    if target.get("in_breach"):
        score += 50
        evidence.append("Found in leaked database")

    # +30: Username reuse
    username = target.get("username", "")
    if username:
        account_nodes = [
            n for n, d in osint_graph.graph.nodes(data=True)
            if d.get("type") == "account" and d.get("username") == username
        ]
        if len(account_nodes) > 3:
            score += 30
            evidence.append(f"Username reused on {len(account_nodes)} platforms")

    # +40: Multiple identities from same IP
    connections = osint_graph.find_all_connected(target_node_id, max_depth=2)
    ip_count = len([
        n for n, _d, _depth in connections
        if osint_graph.graph.nodes[n].get("type") == "ip"
    ])
    identity_count = len([
        n for n, _d, _depth in connections
        if osint_graph.graph.nodes[n].get("type") in ("person", "email", "phone")
    ])
    if identity_count > 1 and ip_count > 1:
        score += 40
        evidence.append(f"{identity_count} identities from {ip_count} IPs — coordinated pattern")

    # +20: Co-appears with flagged nodes
    if target.get("co_appears_with_flagged"):
        score += 20
        evidence.append("Co-appears with flagged bad actors")

    # +15: VPN/proxy detected
    if target.get("vpn_detected"):
        score += 15
        evidence.append("Using VPN/proxy to mask IP")

    return {
        "node": target_node_id,
        "risk_score": min(score, 100),
        "risk_level": (
            "CRITICAL" if score >= 70 else
            "HIGH" if score >= 50 else
            "MEDIUM" if score >= 30 else
            "LOW"
        ),
        "evidence": evidence,
    }


# ── Red2 campaign bridge ──

def red2_campaign(osint_graph, target_node_id, output_dir=None):
    """Convert OSINT graph findings into a Red2 campaign JSON.

    The campaign JSON is consumed by Red2's executor for adversarial testing.
    """
    output_dir = output_dir or CAMPAIGNS_DIR
    os.makedirs(output_dir, exist_ok=True)

    target = dict(osint_graph.graph.nodes.get(target_node_id, {}))
    connections = osint_graph.find_all_connected(target_node_id, max_depth=3)

    # Extract targets for Red2
    domains = []
    ips = []
    emails = []
    accounts = []
    persons = []

    for n, data, depth in connections:
        node_type = data.get("type", "")
        if node_type == "domain":
            domains.append({"domain": n, "data": data, "depth": depth})
        elif node_type == "ip":
            ips.append({"ip": n, "data": data, "depth": depth})
        elif node_type == "email":
            emails.append({"email": n, "data": data, "depth": depth})
        elif node_type == "account":
            accounts.append({"account": n, "platform": data.get("platform", "?"), "depth": depth})
        elif node_type == "person":
            persons.append({"person": n, "name": data.get("name", data.get("value", n)), "depth": depth})

    campaign = {
        "campaign_name": f"peekaboo_{target_node_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
        "generated_by": "peek-a-boo",
        "source_node": target_node_id,
        "source_data": target,
        "generated_at": str(datetime.utcnow()),
        "total_targets": len(domains) + len(ips) + len(emails) + len(accounts),
        "targets": {
            "domains": [d["domain"] for d in domains],
            "ips": [i["ip"] for i in ips],
            "emails": [e["email"] for e in emails],
            "accounts": [f"{a['account']} ({a['platform']})" for a in accounts],
            "persons": [p["name"] for p in persons],
        },
        "attack_profile": {
            "phases": ["recon", "scan", "enumerate", "vuln_scan", "exploit", "post_exploit"],
            "priority_targets": domains[:3] + ips[:3],
        },
        "evidence_count": len(osint_graph.find_all_connected(target_node_id, max_depth=1)),
    }

    filename = f"{campaign['campaign_name']}.json"
    path = os.path.join(output_dir, filename)
    with open(path, "w") as f:
        json.dump(campaign, f, indent=2, default=str)

    return path, campaign