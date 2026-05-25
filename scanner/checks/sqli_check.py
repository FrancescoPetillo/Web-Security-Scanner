import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

SQL_ERRORS = [
    "sql syntax",
    "mysql",
    "postgresql",
    "sqlite",
    "ora-",
    "syntax error",
    "unclosed quotation",
]

def check_sqli(url: str):
    findings = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    payload = "'"

    for param in params:
        test_params = params.copy()
        test_params[param] = payload

        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            res = requests.get(test_url, timeout=8)
            body = res.text.lower()

            if any(error in body for error in SQL_ERRORS):
                findings.append({
                    "category": "OTHER",
                    "title": "Possible SQL Injection",
                    "severity": "High",
                    "description": f"Parameter '{param}' may trigger SQL error messages.",
                    "recommendation": "Use prepared statements and avoid exposing database errors."
                })

        except requests.RequestException:
            continue

    return findings