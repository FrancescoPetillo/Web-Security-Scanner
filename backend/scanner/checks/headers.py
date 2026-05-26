def parse_csp(csp):
    directives = {}

    parts = csp.split(";")

    for part in parts:
        part = part.strip()
        if not part:
            continue

        tokens = part.split()
        name = tokens[0]
        values = tokens[1:]

        directives[name] = values

    return directives


def check_headers(headers):
    findings = []

    # 🔥 normalizzazione
    headers = {k.lower(): v for k, v in headers.items()}

    # -------------------------
    # CSP
    # -------------------------
    csp = headers.get("content-security-policy")

    if not csp:
        findings.append({
            "title": "Missing Content Security Policy",
            "severity": "Medium",
            "description": "The site does not define a Content Security Policy.",
            "recommendation": "Add a CSP header to mitigate XSS attacks."
        })
    else:
        parsed = parse_csp(csp)

        # 🔥 wildcard per direttiva
        for directive, values in parsed.items():
            if "*" in values:
                findings.append({
                    "title": f"Weak CSP: wildcard in {directive}",
                    "severity": "High",
                    "description": f"{directive} allows any source (*).",
                    "recommendation": "Restrict sources in CSP."
                })

        # 🔥 unsafe-inline
        if "script-src" in parsed and "'unsafe-inline'" in parsed["script-src"]:
            findings.append({
                "title": "Weak CSP: unsafe-inline allowed",
                "severity": "High",
                "description": "Inline scripts are allowed.",
                "recommendation": "Remove 'unsafe-inline'."
            })

        # 🔥 unsafe-eval
        if "script-src" in parsed and "'unsafe-eval'" in parsed["script-src"]:
            findings.append({
                "title": "Weak CSP: unsafe-eval allowed",
                "severity": "High",
                "description": "Eval-like execution is allowed.",
                "recommendation": "Remove 'unsafe-eval'."
            })

        # 🔥 manca default-src
        if "default-src" not in parsed:
            findings.append({
                "title": "Weak CSP: missing default-src",
                "severity": "Medium",
                "description": "CSP does not define a default-src directive.",
                "recommendation": "Define a restrictive default-src policy."
            })

    # -------------------------
    # HSTS
    # -------------------------
    hsts = headers.get("strict-transport-security")

    if not hsts:
        findings.append({
            "title": "Missing HSTS",
            "severity": "Medium",
            "description": "The site does not enforce HTTPS via HSTS.",
            "recommendation": "Add Strict-Transport-Security header."
        })
    else:
        if "max-age" not in hsts:
            findings.append({
                "title": "Weak HSTS configuration",
                "severity": "Medium",
                "description": "HSTS header missing max-age directive.",
                "recommendation": "Set a strong max-age value (e.g., 31536000)."
            })

    # -------------------------
    # Server disclosure
    # -------------------------
    server = headers.get("server")

    if server:
        findings.append({
            "title": "Server Information Disclosure",
            "severity": "Low",
            "description": f"Server reveals version: {server}",
            "recommendation": "Hide or obfuscate server headers."
        })

    return findings