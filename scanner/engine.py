import requests

from scanner.checks.headers import check_headers
from scanner.checks.https import check_https
from scanner.checks.cookies import check_cookies
from scanner.checks.security_headers import check_security_headers
from scanner.checks.exposed_files import check_exposed_files
from scanner.checks.http_methods import check_http_methods

from scanner.scoring import calculate_score, calculate_risk


def run_scan(url: str):
    findings = []

    try:
        original_url = url

        # Fix URL
        if not url.startswith("http"):
            url = "https://" + url

        # Request
        response = requests.get(url, timeout=5)
        headers = response.headers

        # Checks
        findings.extend(check_https(original_url, response))
        findings.extend(check_headers(headers))
        findings.extend(check_cookies(response))
        findings.extend(check_security_headers(headers))
        findings.extend(check_exposed_files(url))
        findings.extend(check_http_methods(url))

        # 🔥 Ordina per gravità
        severity_order = {"High": 3, "Medium": 2, "Low": 1}
        findings = sorted(
            findings,
            key=lambda x: severity_order.get(x["severity"], 0),
            reverse=True
        )

        # Score + Risk
        score = calculate_score(findings)
        risk_data = calculate_risk(score, findings)

        return {
            "status": "done",
            "score": score,
            **risk_data,
            "findings": findings
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }