def check_cookies(response):
    findings = []

    cookies = response.cookies

    for cookie in cookies:
        # HttpOnly check
        if not cookie._rest.get("HttpOnly"):
            findings.append({
                "title": "Cookie missing HttpOnly flag",
                "severity": "Medium",
                "description": f"Cookie '{cookie.name}' is missing HttpOnly flag.",
                "recommendation": "Set HttpOnly flag to prevent access via JavaScript."
            })

        # Secure check
        if not cookie.secure:
            findings.append({
                "title": "Cookie missing Secure flag",
                "severity": "Medium",
                "description": f"Cookie '{cookie.name}' is not marked as Secure.",
                "recommendation": "Set Secure flag to ensure cookie is sent over HTTPS only."
            })

    return findings
