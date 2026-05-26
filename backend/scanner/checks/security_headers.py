def check_security_headers(headers):
    findings = []

    # X-Frame-Options
    xfo = headers.get("X-Frame-Options")
    if not xfo:
        findings.append({
            "title": "Missing X-Frame-Options",
            "type": "hardening",
            "category": "headers",
            "severity": "Medium",
            "confidence": "low",
            "impact": "low",
            "description": "The site does not protect against clickjacking.",
            "recommendation": "Add X-Frame-Options header (DENY or SAMEORIGIN)."
        })
    elif xfo not in ["DENY", "SAMEORIGIN"]:
        findings.append({
            "title": "Weak X-Frame-Options configuration",
            "type": "hardening",
            "category": "headers",
            "severity": "Low",
            "confidence": "medium",
            "impact": "low",
            "description": f"X-Frame-Options is set to '{xfo}'.",
            "recommendation": "Use DENY or SAMEORIGIN."
        })

    # X-Content-Type-Options
    xcto = headers.get("X-Content-Type-Options")
    if not xcto:
        findings.append({
            "title": "Missing X-Content-Type-Options",
            "type": "hardening",
            "category": "headers",
            "severity": "Low",
            "confidence": "low",
            "impact": "low",
            "description": "The site may be vulnerable to MIME sniffing.",
            "recommendation": "Add X-Content-Type-Options: nosniff."
        })
    elif xcto.lower() != "nosniff":
        findings.append({
            "title": "Improper X-Content-Type-Options",
            "type": "hardening",
            "category": "headers",
            "severity": "Low",
            "confidence": "medium",
            "impact": "low",
            "description": f"Header is set to '{xcto}'.",
            "recommendation": "Set X-Content-Type-Options to 'nosniff'."
        })

    # Referrer-Policy
    referrer = headers.get("Referrer-Policy")
    if not referrer:
        findings.append({
            "title": "Missing Referrer-Policy",
            "type": "hardening",
            "category": "headers",
            "severity": "Low",
            "confidence": "low",
            "impact": "low",
            "description": "The site does not control referrer information leakage.",
            "recommendation": "Add a strict Referrer-Policy."
        })

    return findings
