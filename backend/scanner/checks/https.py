def check_https(original_url, final_url):
    findings = []

    # ❗ Caso 1: URL finale non è HTTPS
    if not final_url.startswith("https"):
        findings.append({
            "title": "Site not using HTTPS",
            "type": "vulnerability",
            "category": "https",
            "severity": "High",
            "confidence": "high",
            "impact": "high",
            "description": "The website is not using HTTPS.",
            "recommendation": "Use HTTPS to encrypt communications."
        })

    # ❗ Caso 2: nessun redirect da HTTP → HTTPS
    if original_url.startswith("http://") and not final_url.startswith("https://"):
        findings.append({
            "title": "No HTTPS redirect",
            "type": "hardening",
            "category": "https",
            "severity": "Medium",
            "confidence": "medium",
            "impact": "moderate",
            "description": "The site does not properly redirect to HTTPS.",
            "recommendation": "Force HTTPS redirection."
        })

    return findings
