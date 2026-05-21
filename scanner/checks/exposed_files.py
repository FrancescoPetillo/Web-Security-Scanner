import requests

def check_exposed_files(base_url):
    findings = []

    paths = [
        "/.env",
        "/.git",
        "/admin",
        "/backup"
    ]

    for path in paths:
        try:
            url = base_url.rstrip("/") + path
            response = requests.get(url, timeout=3)

            if response.status_code == 200:
                findings.append({
                    "title": "Exposed sensitive file or endpoint",
                    "severity": "High",
                    "description": f"Accessible path found: {path}",
                    "recommendation": "Restrict access to sensitive files and directories."
                })

        except:
            continue

    return findings
