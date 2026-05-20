def check_https(url, response):
    findings = []

    # HTTPS check
    if not url.startswith("https"):
        findings.append({
            "title": "Site not using HTTPS",
            "severity": "High",
            "description": "The website is not using HTTPS.",
            "recommendation": "Use HTTPS to encrypt communications."
        })

    # Redirect check
    if response.history:
        redirected = response.url
        if not redirected.startswith("https"):
            findings.append({
                "title": "No HTTPS redirect",
                "severity": "Medium",
                "description": "The site does not properly redirect to HTTPS.",
                "recommendation": "Force HTTPS redirection."
            })

    return findings
