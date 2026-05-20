def check_security_headers(headers):
    findings = []

    # X-Frame-Options
    if "X-Frame-Options" not in headers:
        findings.append({
            "title": "Missing X-Frame-Options",
            "severity": "Medium",
            "description": "The site does not protect against clickjacking.",
            "recommendation": "Add X-Frame-Options header (e.g., DENY or SAMEORIGIN)."
        })

    # X-Content-Type-Options
    if "X-Content-Type-Options" not in headers:
        findings.append({
            "title": "Missing X-Content-Type-Options",
            "severity": "Low",
            "description": "The site may be vulnerable to MIME sniffing.",
            "recommendation": "Add X-Content-Type-Options: nosniff."
        })

    # Referrer-Policy
    if "Referrer-Policy" not in headers:
        findings.append({
            "title": "Missing Referrer-Policy",
            "severity": "Low",
            "description": "The site does not control referrer information leakage.",
            "recommendation": "Add a strict Referrer-Policy."
        })

    return findings
