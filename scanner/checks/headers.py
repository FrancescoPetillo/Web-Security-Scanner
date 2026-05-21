def check_headers(headers):
    findings = []

    # CSP
    csp = headers.get("Content-Security-Policy")
    if not csp:
        findings.append({
            "title": "Missing Content Security Policy",
            "severity": "Medium",
            "description": "The site does not define a Content Security Policy.",
            "recommendation": "Add a CSP header to mitigate XSS attacks."
        })
    else:
        if "unsafe-inline" in csp:
            findings.append({
                "title": "Weak CSP: unsafe-inline allowed",
                "severity": "High",
                "description": "CSP allows 'unsafe-inline', increasing XSS risk.",
                "recommendation": "Remove 'unsafe-inline' from CSP."
            })

        if "unsafe-eval" in csp:
            findings.append({
                "title": "Weak CSP: unsafe-eval allowed",
                "severity": "High",
                "description": "CSP allows 'unsafe-eval', which is dangerous.",
                "recommendation": "Remove 'unsafe-eval' from CSP."
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
    server = headers.get("Server")
    if server:
        findings.append({
            "title": "Server Information Disclosure",
            "severity": "Low",
            "description": f"Server reveals version: {server}",
            "recommendation": "Hide or obfuscate server headers."
        })

    return findings