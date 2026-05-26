from scanner.browser import fetch_page

from scanner.checks.headers import check_headers
from scanner.checks.https import check_https
from scanner.checks.cookies import check_cookies
from scanner.checks.security_headers import check_security_headers
from scanner.checks.exposed_files import check_exposed_files
from scanner.checks.http_methods import check_http_methods

from scanner.checks.xss_check import check_xss
from scanner.checks.sqli_check import check_sqli
from scanner.checks.exposure_check import check_exposed_paths

from scanner.scoring import calculate_score, calculate_risk
from scanner.reputation import get_reputation, get_domain


def group_findings(findings):
    grouped = {
        "headers": [],
        "cookies": [],
        "https": [],
        "other": []
    }

    for f in findings:
        category = f.get("category", "").lower()
        title = f.get("title", "").lower()

        if category == "cookies" or "cookie" in title:
            grouped["cookies"].append(f)

        elif category == "https" or "https" in title or "hsts" in title or "ssl" in title:
            grouped["https"].append(f)

        elif (
            category == "headers"
            or "csp" in title
            or "content security policy" in title
            or "x-frame-options" in title
            or "x-content-type-options" in title
            or "referrer-policy" in title
            or "header" in title
            or "server" in title
        ):
            grouped["headers"].append(f)

        else:
            grouped["other"].append(f)

    return grouped


def run_scan(url: str):
    findings = []

    try:
        original_url = url

        # 🔹 normalizzazione base
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        # 🔹 fetch con Playwright
        data = fetch_page(url)

        headers = data["headers"]
        cookies = data["cookies"]
        final_url = data["url"]

        # 🔹 CHECKS
        findings.extend(check_https(original_url, final_url))
        findings.extend(check_headers(headers))
        findings.extend(check_cookies(cookies))
        findings.extend(check_security_headers(headers))
        findings.extend(check_exposed_files(final_url))
        findings.extend(check_http_methods(final_url))

        findings.extend(check_xss(final_url))
        findings.extend(check_sqli(final_url))
        findings.extend(check_exposed_paths(final_url))

        # REPUTATION (VirusTotal)
        try:
            domain = get_domain(final_url)
            stats = get_reputation(domain)
        except:
            domain = None
            stats = None

        # 🔹 ordinamento per severità
        severity_order = {
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1,
            "Info": 0
        }

        findings = sorted(
            findings,
            key=lambda x: severity_order.get(x.get("severity"), 0),
            reverse=True
        )

        # 🔹 scoring contestuale
        score = calculate_score(findings, reputation=stats, domain=domain)

        # 🔹 rischio
        risk_data = calculate_risk(score, findings)

        # 🔹 grouping
        grouped = group_findings(findings)

        return {
            "status": "done",
            "url": original_url,
            "final_url": final_url,
            "score": score,
            **risk_data,
            "findings": findings,
            "grouped_findings": grouped,
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
