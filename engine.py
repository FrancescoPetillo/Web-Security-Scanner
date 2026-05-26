import requests
from urllib.parse import urlparse

from scanner.scoring import calculate_score, calculate_risk
from scanner.reputation import get_reputation


def build_scan_summary(score, findings, stats):
    vulnerabilities = sum(1 for f in findings if f.get("type") == "vulnerability")
    hardening = sum(1 for f in findings if f.get("type") == "hardening")
    malicious = stats.get("malicious", 0) if stats else 0
    suspicious = stats.get("suspicious", 0) if stats else 0

    if malicious or suspicious:
        reputation_status = "Reputation warnings found"
    elif stats:
        reputation_status = "Reputation clean"
    else:
        reputation_status = "Reputation unavailable"

    if vulnerabilities == 0 and score >= 90:
        message = "No confirmed critical vulnerabilities were detected. The remaining findings are mostly hardening improvements."
    elif vulnerabilities == 0:
        message = "No confirmed critical vulnerabilities were detected, but several hardening improvements are recommended."
    else:
        message = "Confirmed security issues were detected and should be reviewed before hardening recommendations."

    return {
        "message": message,
        "vulnerabilities": vulnerabilities,
        "hardening": hardening,
        "reputation_status": reputation_status
    }


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
                "type": "hardening",
                "category": "headers",
                "severity": "Medium",
                "confidence": "low",
                "impact": "low"
            })

        if "Strict-Transport-Security" not in headers:
            findings.append({
                "title": "Missing HSTS",
                "type": "hardening",
                "category": "headers",
                "severity": "Medium",
                "confidence": "low",
                "impact": "low"
            })

        if "Server" in headers:
            findings.append({
                "title": f"Server exposed: {headers['Server']}",
                "type": "hardening",
                "category": "headers",
                "severity": "Low",
                "confidence": "high",
                "impact": "low"
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
        summary = build_scan_summary(score, findings, stats)

        return {
            "status": "done",
            "url": url,
            "score": score,
            **risk_data,
            "summary": summary,
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
