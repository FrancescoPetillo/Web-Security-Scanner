def check_headers(headers):
    findings = []

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

    return findings
