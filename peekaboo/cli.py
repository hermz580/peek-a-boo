"""peekaboo CLI — OSINT investigation from the terminal."""

import argparse
import json
import sys
import os

# Add parent dir to sys.path for standalone use
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def main():
    parser = argparse.ArgumentParser(description="peekaboo — Graph-based OSINT toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    # investigate
    inv = sub.add_parser("investigate", help="Deep-dig from a seed identifier")
    inv.add_argument("seed_type", choices=["name", "email", "username", "domain", "ip", "phone"])
    inv.add_argument("seed_value", help="The identifier to investigate")

    # graph
    g = sub.add_parser("graph", help="Show graph summary or connectivity")
    g.add_argument("node", nargs="?", help="Node ID to inspect")
    g.add_argument("--depth", type=int, default=3, help="BFS depth")

    # evidence
    ev = sub.add_parser("evidence", help="Manage evidence cards")
    ev.add_argument("action", choices=["list", "add", "delete", "removal-tracker"])
    ev.add_argument("--source-url", help="Evidence URL")
    ev.add_argument("--excerpt", help="Relevant text excerpt")
    ev.add_argument("--relevance", help="Why it matches")
    ev.add_argument("--id", type=int, dest="ev_id", help="Evidence ID")

    # red2-campaign
    rc = sub.add_parser("red2-campaign", help="Generate Red2 campaign from graph findings")
    rc.add_argument("target_node", help="Node ID to generate campaign for")
    rc.add_argument("--output-dir", help="Output directory (default: RED2_LAB_DIR/campaigns)")

    # risk
    risk = sub.add_parser("risk", help="Risk score a node")
    risk.add_argument("node_id", help="Node to score")

    # web
    web = sub.add_parser("web", help="Launch the Flask web dashboard")
    web.add_argument("--port", type=int, default=5000, help="Port to bind")

    # stats
    sub.add_parser("stats", help="Graph statistics")

    args = parser.parse_args()

    # Lazy imports so CLI stays fast for simple queries
    from peekaboo.graph import OSINTGraph
    from peekaboo.db import EvidenceDB
    from peekaboo.analysis import detect_bad_actor_patterns, calculate_risk_score, red2_campaign
    from peekaboo.sources import get_whois, get_dns_records, search_usernames, check_breaches, geoip_lookup

    graph = OSINTGraph()
    db = EvidenceDB()

    if args.command == "investigate":
        print(f"[*] Investigating {args.seed_type}: {args.seed_value}")
        node_id = f"{args.seed_type}_{args.seed_value.replace('@', '_at_').replace('.', '_dot_')}"
        graph.add_node(node_id, args.seed_type, value=args.seed_value)

        if args.seed_type == "domain":
            whois_data = get_whois(args.seed_value)
            graph.add_node(f"whois_{args.seed_value}", "person", **{k: v for k, v in whois_data.items() if k != "error"})
            graph.add_edge(node_id, f"whois_{args.seed_value}", "registered_to", confidence="high")

            dns = get_dns_records(args.seed_value)
            print(f"  DNS: {json.dumps(dns, default=str, indent=2)}")

        if args.seed_type == "email":
            breaches = check_breaches(args.seed_value)
            if breaches:
                print(f"  [!] Found in {len(breaches)} breaches")
                for b in breaches[:5]:
                    print(f"      - {b.get('Name', '?')} ({b.get('Domain', '?')})")

        if args.seed_type == "username":
            profiles = search_usernames(args.seed_value)
            print(f"  Accounts found: {len(profiles)}")
            for p in profiles:
                acct_id = f"account_{args.seed_value}_{p['platform'].replace('.', '_')}"
                graph.add_node(acct_id, "account", username=args.seed_value, platform=p["platform"])
                graph.add_edge(node_id, acct_id, "owns_account", evidence_url=p["url"], confidence="high")
                print(f"    {p['platform']}: {p['url']}")

        stats = graph.stats()
        print(f"\n[+] Graph: {stats['nodes']} nodes, {stats['edges']} edges")

        # Run detection automatically
        flags = detect_bad_actor_patterns(graph)
        if flags:
            print(f"\n[!] Red flags ({len(flags)}):")
            for f in flags:
                print(f"  [{f['severity']}] {f['type']}: {f['reason']}")

    elif args.command == "graph":
        if args.node:
            summary = graph.summary(args.node)
            if summary:
                print(json.dumps(summary, indent=2, default=str))
            else:
                connected = graph.find_all_connected(args.node, max_depth=args.depth)
                if connected:
                    print(f"Connections from {args.node} (depth {args.depth}):")
                    for n, data, d in connected:
                        print(f"  [{d}] {n} ({data.get('type', '?')})")
                else:
                    print(f"Node '{args.node}' not found or has no connections")
        else:
            stats = graph.stats()
            print(json.dumps(stats, indent=2))

    elif args.command == "evidence":
        if args.action == "list":
            rows = db.list_all()
            print(f"Evidence cards ({len(rows)}):")
            for r in rows:
                print(f"  #{r['id']} | {r['source_url'][:60]}... | {r['date_checked'][:10]}")
        elif args.action == "add":
            db.add(source_url=args.source_url or "", excerpt=args.excerpt or "",
                   relevance=args.relevance or "")
            print("Evidence added")
        elif args.action == "delete":
            if args.ev_id:
                db.delete(args.ev_id)
                print(f"Deleted #{args.ev_id}")
        elif args.action == "removal-tracker":
            rows = [e for e in db.list_all() if e.get("notes") == "REMOVAL_REQUESTED"]
            print(f"Items marked for removal ({len(rows)}):")
            for r in rows:
                print(f"  #{r['id']} | {r['source_url'][:60]}... | {r['date_checked'][:10]}")

    elif args.command == "red2-campaign":
        path, campaign = red2_campaign(graph, args.target_node, output_dir=args.output_dir)
        print(f"Campaign written to: {path}")
        print(f"  Name: {campaign['campaign_name']}")
        print(f"  Targets: {campaign['total_targets']}")

    elif args.command == "risk":
        result = calculate_risk_score(graph, args.node_id)
        if result:
            print(f"Risk for {result['node']}: {result['risk_score']}/100 ({result['risk_level']})")
            for ev in result["evidence"]:
                print(f"  - {ev}")
        else:
            print(f"Node '{args.node_id}' not found")

    elif args.command == "web":
        print(f"[*] Starting Flask dashboard on :{args.port}")
        from peekaboo.app import app
        app.run(debug=False, port=args.port)

    elif args.command == "stats":
        print(json.dumps(graph.stats(), indent=2))


if __name__ == "__main__":
    main()