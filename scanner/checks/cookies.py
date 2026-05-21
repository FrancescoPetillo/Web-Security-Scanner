def check_cookies(response):
    findings = []

    cookies = response.cookies  # ✅ DEFINITO QUI

    httponly_missing = []
    secure_missing = []

    for cookie in cookies:
        if not cookie._rest.get("HttpOnly"):
            httponly_missing.append(cookie.name)

        if not cookie.secure:
            secure_missing.append(cookie.name)

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