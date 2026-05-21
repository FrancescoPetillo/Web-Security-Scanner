from scanner.browser import fetch_page

from scanner.checks.headers import check_headers
from scanner.checks.https import check_https
from scanner.checks.cookies import check_cookies
from scanner.checks.security_headers import check_security_headers
from scanner.checks.exposed_files import check_exposed_files
from scanner.checks.http_methods import check_http_methods

from scanner.scoring import calculate_score, calculate_risk


def group_findings(findings):
    grouped = {
        "headers": [],
        "cookies": [],
        "https": [],
        "other": []
    }

    for f in findings:
        title = f.get("title", "").lower()

        if "cookie" in title:
            grouped["cookies"].append(f)

        elif "https" in title or "hsts" in title or "ssl" in title:
            grouped["https"].append(f)

        elif (
            "csp" in title
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

        if not url.startswith("http"):
            url = "https://" + url

        data = fetch_page(url)

        headers = data["headers"]
        cookies = data["cookies"]
        final_url = data["url"]

        findings.extend(check_https(original_url, final_url))
        findings.extend(check_headers(headers))
        findings.extend(check_cookies(cookies))
        findings.extend(check_security_headers(headers))
        findings.extend(check_exposed_files(final_url))
        findings.extend(check_http_methods(final_url))

        severity_order = {"High": 3, "Medium": 2, "Low": 1}

        findings = sorted(
            findings,
            key=lambda x: severity_order.get(x.get("severity"), 0),
            reverse=True
        )

        score = calculate_score(findings)
        risk_data = calculate_risk(score, findings)

        grouped = group_findings(findings)

        return {
            "status": "done",
            "url": original_url,
            "final_url": final_url,
            "score": score,
            **risk_data,
            "findings": findings,
            "grouped_findings": grouped
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }