import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def check_xss(url: str):
    findings = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    payload = "<script>alert(1)</script>"

    for param in params:
        test_params = params.copy()
        test_params[param] = payload

        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            res = requests.get(test_url, timeout=8)

            if payload in res.text:
                findings.append({
                    "category": "OTHER",
                    "title": "Possible reflected XSS",
                    "type": "vulnerability",
                    "severity": "High",
                    "confidence": "high",
                    "impact": "high",
                    "description": f"Parameter '{param}' reflects user input without proper encoding.",
                    "recommendation": "Sanitize and encode user input before rendering it in HTML."
                })

        except requests.RequestException:
            continue

    return findings
