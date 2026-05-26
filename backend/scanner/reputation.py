import requests
from urllib.parse import urlparse
import os

API_KEY = os.getenv("VT_API_KEY")

cache = {}

def get_domain(url: str):
    return urlparse(url).hostname


def get_reputation(domain: str):
    # 🔥 FIX IMPORTANTE
    if not domain or not API_KEY:
        return None

    if domain in cache:
        return cache[domain]

    try:
        res = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": API_KEY},
            timeout=5   # 👈 leggermente meglio di 3
        )

        if res.status_code != 200:
            return None

        data = res.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        cache[domain] = stats
        return stats

    except Exception:
        return None


def reputation_penalty(stats):
    if not stats:
        return 0

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    return (malicious * 15) + (suspicious * 7)