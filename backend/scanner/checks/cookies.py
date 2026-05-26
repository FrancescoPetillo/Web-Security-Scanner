def check_cookies(cookies):
    findings = []

    httponly_missing = []
    secure_missing = []

    for cookie in cookies:
        # HttpOnly
        if not cookie.get("httpOnly"):
            httponly_missing.append(cookie.get("name"))

        # Secure
        if not cookie.get("secure"):
            secure_missing.append(cookie.get("name"))

    if httponly_missing:
        findings.append({
            "title": "Cookies missing HttpOnly flag",
            "severity": "Medium",
            "description": f"{len(httponly_missing)} cookies missing HttpOnly.",
            "recommendation": "Set HttpOnly flag on cookies."
        })

    if secure_missing:
        findings.append({
            "title": "Cookies missing Secure flag",
            "severity": "Medium",
            "description": f"{len(secure_missing)} cookies not marked Secure.",
            "recommendation": "Set Secure flag."
        })

    return findings