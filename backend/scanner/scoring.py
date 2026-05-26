BEST_PRACTICE_KEYWORDS = (
    "missing content security policy",
    "missing csp",
    "weak csp",
    "missing hsts",
    "weak hsts",
    "missing x-frame-options",
    "missing x-content-type-options",
    "missing referrer-policy",
    "server information disclosure",
    "server exposed",
    "cookies missing",
)

REAL_VULNERABILITY_KEYWORDS = (
    "possible reflected xss",
    "possible sql injection",
    "exposed sensitive",
    "site not using https",
    "dangerous http method",
)

TRUSTED_DOMAINS = (
    "google.com",
    "github.com",
    "cloudflare.com",
    "microsoft.com",
    "apple.com",
)


def _normalized_title(finding):
    return finding.get("title", "").lower()


def _is_best_practice(finding):
    finding_type = finding.get("type")
    if finding_type:
        return finding_type == "hardening"

    title = _normalized_title(finding)
    return any(keyword in title for keyword in BEST_PRACTICE_KEYWORDS)


def _is_real_vulnerability(finding):
    finding_type = finding.get("type")
    if finding_type:
        return finding_type == "vulnerability"

    title = _normalized_title(finding)
    return any(keyword in title for keyword in REAL_VULNERABILITY_KEYWORDS)


def _confidence_for(finding):
    confidence = finding.get("confidence")

    if confidence:
        return confidence.lower()

    if _is_best_practice(finding):
        return "low"

    return "medium"


def _impact_for(finding):
    impact = finding.get("impact")

    if impact:
        return impact.lower()

    if _is_real_vulnerability(finding):
        return "high"

    if _is_best_practice(finding):
        return "low"

    return "moderate"


def calculate_score(findings, reputation=None, domain=None):
    score = 100.0

    severity_weights = {
        "Critical": 24,
        "High": 14,
        "Medium": 5,
        "Low": 1.5,
        "Info": 0
    }

    confidence_multiplier = {
        "high": 1.0,
        "medium": 0.45,
        "low": 0.18
    }

    impact_multiplier = {
        "critical": 1.35,
        "high": 1.0,
        "moderate": 0.6,
        "low": 0.28,
        "info": 0
    }

    real_high_count = 0
    medium_real_count = 0

    for finding in findings:
        severity = finding.get("severity", "Low")
        confidence = _confidence_for(finding)
        impact = _impact_for(finding)

        weight = severity_weights.get(severity, 3)
        multiplier = confidence_multiplier.get(confidence, 0.45)
        penalty = weight * multiplier * impact_multiplier.get(impact, 0.6)

        if _is_best_practice(finding):
            penalty *= 0.5
        elif _is_real_vulnerability(finding):
            penalty *= 1.2

        score -= penalty

        if severity in ("Critical", "High") and _is_real_vulnerability(finding):
            real_high_count += 1
        elif severity == "Medium" and not _is_best_practice(finding):
            medium_real_count += 1

    if real_high_count >= 2:
        score -= 8

    if medium_real_count >= 4:
        score -= 4

    if reputation:
        malicious = reputation.get("malicious", 0)
        suspicious = reputation.get("suspicious", 0)

        score -= malicious * 18
        score -= suspicious * 8

        if malicious == 0 and suspicious == 0:
            score += 4

    if domain:
        normalized_domain = domain.lower()
        if any(normalized_domain == td or normalized_domain.endswith(f".{td}") for td in TRUSTED_DOMAINS):
            score += 4

    return max(0, min(round(score), 100))


def calculate_risk(score, findings):
    real_high_count = sum(
        1 for f in findings
        if f.get("severity") in ("Critical", "High") and _is_real_vulnerability(f)
    )
    medium_count = sum(
        1 for f in findings
        if f.get("severity") == "Medium" and not _is_best_practice(f)
    )

    if real_high_count >= 1 or score < 55:
        return {
            "risk_level": "High",
            "risk_explanation": "Critical vulnerabilities detected."
        }

    if score < 80 or medium_count >= 3:
        return {
            "risk_level": "Medium",
            "risk_explanation": "Several weaknesses detected."
        }

    return {
        "risk_level": "Low",
        "risk_explanation": "Strong security posture."
    }
