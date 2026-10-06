"""Data source modules — each function hits a different public OSINT source."""

import requests
import whois
import dns.resolver
from datetime import datetime

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


def get_whois(domain):
    """Domain -> registrant name, email, phone, dates."""
    try:
        w = whois.whois(domain)
        return {
            "registrant_name": w.registrant_name,
            "registrant_email": w.registrant_email,
            "registrant_phone": w.registrant_phone,
            "creation_date": str(w.creation_date) if hasattr(w.creation_date, "isoformat") else str(w.creation_date),
            "name_servers": w.name_servers,
            "raw": str(w),
        }
    except Exception as e:
        return {"error": str(e)}


def get_dns_records(domain):
    """A, MX, TXT, NS, CNAME records."""
    records = {}
    for rtype in ("A", "MX", "TXT", "NS", "CNAME", "AAAA"):
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            pass
    return records


def search_usernames(username):
    """Check username presence on major platforms."""
    platforms = [
        ("twitter.com", f"https://twitter.com/{username}"),
        ("github.com", f"https://github.com/{username}"),
        ("reddit.com", f"https://reddit.com/u/{username}"),
        ("instagram.com", f"https://instagram.com/{username}"),
        ("twitch.tv", f"https://twitch.tv/{username}"),
        ("tiktok.com", f"https://tiktok.com/@{username}"),
    ]
    results = []
    for platform, url in platforms:
        try:
            r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=10, allow_redirects=False)
            if r.status_code in (200, 301, 302):
                results.append({"platform": platform, "url": url, "exists": True})
        except Exception:
            pass
    return results


def check_breaches(email):
    """Check email against Have I Been Pwned (v3, no key needed for breach names)."""
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return []


def geoip_lookup(ip):
    """IP -> location, ISP, ASN."""
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", headers={"User-Agent": USER_AGENT}, timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def web_search(query, limit=5):
    """Web search via configured Hermes backend (returns description snippets)."""
    # Placeholder: in practice this would call an API like SerpAPI or Google Custom Search
    return {"query": query, "results": [], "note": "Requires search API key"}


def check_removal_tracker(evidence_db):
    """List evidence marked for removal/correction."""
    return [e for e in evidence_db.list_all() if e.get("notes") == "REMOVAL_REQUESTED"]