import requests

def run_scan(url: str):
    findings = []

    try:
        # Fix URL se manca https
        if not url.startswith("http"):
            url = "https://" + url

        response = requests.get(url)
        headers = response.headers


        # CSP
        if "Content-Security-Policy" not in headers:
            findings.append({
                "title": "Missing Content Security Policy",
                "severity": "Medium",
                "description": "The site does not define a Content Security Policy.",
                "recommendation": "Add a CSP header to mitigate XSS attacks."
            })

        # HSTS
        if "Strict-Transport-Security" not in headers:
            findings.append({
                "title": "Missing HSTS",
                "severity": "Medium",
                "description": "The site does not enforce HTTPS via HSTS.",
                "recommendation": "Add Strict-Transport-Security header."
            })

        # Server disclosure
        if "Server" in headers:
            findings.append({
                "title": "Server Information Disclosure",
                "severity": "Low",
                "description": f"Server reveals version: {headers['Server']}",
                "recommendation": "Hide or obfuscate server headers."
            })

         #  CALCOLO SCORE
        score = 100

        for finding in findings:
            if finding["severity"] == "Medium":
                score -= 20
            elif finding["severity"] == "Low":
                score -= 10

        if score < 0:
            score = 0

        return {
            "status": "done",
            "findings": findings,
            "score": score
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }
