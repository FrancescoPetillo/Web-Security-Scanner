import requests
from urllib.parse import urljoin

EXPOSED_PATHS = [
    "/admin",
    "/backup",
    "/backups",
    "/.git/",
    "/.env",
    "/config",
    "/phpinfo.php",
]

def check_exposed_paths(url: str):
    findings = []

    for path in EXPOSED_PATHS:
        test_url = urljoin(url, path)

        try:
            res = requests.get(test_url, timeout=8)

            if res.status_code in [200, 301, 302, 403]:
                findings.append({
                    "category": "OTHER",
                    "title": f"Potential exposed path: {path}",
                    "severity": "Medium" if res.status_code == 200 else "Low",
                    "description": f"The path '{path}' returned HTTP {res.status_code}.",
                    "recommendation": "Restrict access to sensitive paths and remove exposed files."
                })

        except requests.RequestException:
            continue

    return findings