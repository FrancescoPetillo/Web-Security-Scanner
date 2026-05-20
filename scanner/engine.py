import requests
from scanner.checks.headers import check_headers
from scanner.checks.https import check_https
from scanner.scoring import calculate_score
from scanner.checks.cookies import check_cookies
from scanner.checks.security_headers import check_security_headers


def run_scan(url: str):
    findings = []

    try:
        original_url = url

        # Fix URL se manca schema
        if not url.startswith("http"):
            url = "https://" + url

        # Request con timeout (importante)
        response = requests.get(url, timeout=5)
        headers = response.headers

        # HTTPS checks 
        findings.extend(check_https(original_url, response))

        # Header checks
        findings.extend(check_headers(headers))

        #cookies
        findings.extend(check_cookies(response))

        # Security headers extra
        findings.extend(check_security_headers(headers))

        # Score
        score = calculate_score(findings)



        return {
            "status": "done",
            "score": score,
            "findings": findings
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }