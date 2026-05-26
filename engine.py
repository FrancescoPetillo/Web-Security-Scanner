import requests
from urllib.parse import urlparse

from scanner.scoring import calculate_score, calculate_risk
from scanner.reputation import get_reputation


def run_scan(url: str):
    findings = []

    try:
        # 🔹 normalizza URL
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        response = requests.get(url, timeout=5)
        headers = response.headers

        # 🔹 CHECKS BASE
        if "Content-Security-Policy" not in headers:
            findings.append({
                "title": "Missing CSP",
                "severity": "Medium",
                "confidence": "low"
            })

        if "Strict-Transport-Security" not in headers:
            findings.append({
                "title": "Missing HSTS",
                "severity": "Medium",
                "confidence": "medium"
            })

        if "Server" in headers:
            findings.append({
                "title": f"Server exposed: {headers['Server']}",
                "severity": "Low",
                "confidence": "high"
            })

        #  DOMAIN
        domain = urlparse(url).hostname

        #  REPUTATION
        try:
            stats = get_reputation(domain)
        except:
            stats = None

        #  SCORING
        score = calculate_score(
            findings,
            reputation=stats,
            domain=domain
        )

        #  RISK
        risk_data = calculate_risk(score, findings)

        return {
            "status": "done",
            "url": url,
            "score": score,
            **risk_data,
            "findings": findings,
            "reputation": {
                "malicious": stats.get("malicious", 0) if stats else 0,
                "suspicious": stats.get("suspicious", 0) if stats else 0
            }
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }
