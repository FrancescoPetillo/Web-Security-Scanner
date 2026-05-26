import requests
from urllib.parse import urlparse
import os

# 🔐 meglio usare env variable
API_KEY = os.getenv("VT_API_KEY")

# cache semplice in memoria
cache = {}


def get_domain(url: str):
    return urlparse(url).hostname


def get_reputation(domain: str):
    if not domain:
        return None

    # cache hit
    if domain in cache:
        return cache[domain]

    try:
        res = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": API_KEY},
            timeout=3
        )

        if res.status_code != 200:
            return None

        data = res.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        # salva in cache
        cache[domain] = stats

        return stats

    except Exception:
        return None


def reputation_penalty(stats):
    if not stats:
        return 0

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    # pesi realistici (non troppo aggressivi)
    penalty = (malicious * 15) + (suspicious * 7)

    return penalty