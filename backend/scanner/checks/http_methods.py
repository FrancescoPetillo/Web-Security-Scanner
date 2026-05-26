import requests

def check_http_methods(url):
    findings = []

    try:
        response = requests.options(url, timeout=5)
        allow = response.headers.get("Allow", "")

        dangerous_methods = ["PUT", "DELETE", "PATCH"]

        for method in dangerous_methods:
            if method in allow:
                findings.append({
                    "title": "Dangerous HTTP method enabled",
                    "type": "vulnerability",
                    "category": "other",
                    "severity": "Medium",
                    "confidence": "high",
                    "impact": "moderate",
                    "description": f"Method {method} is allowed by the server.",
                    "recommendation": "Disable unnecessary HTTP methods."
                })

    except:
        pass

    return findings
