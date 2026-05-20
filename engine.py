import requests

def run_scan(url: str):
    findings = []

    try:
        response = requests.get(url)
        headers = response.headers

        if "Content-Security-Policy" not in headers:
            findings.append({
                "title": "Missing CSP",
                "severity": "Medium"
            })

        if "Strict-Transport-Security" not in headers:
            findings.append({
                "title": "Missing HSTS",
                "severity": "Medium"
            })

        if "Server" in headers:
            findings.append({
                "title": f"Server exposed: {headers['Server']}",
                "severity": "Low"
            })

        return {
            "status": "done",
            "findings": findings
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }
