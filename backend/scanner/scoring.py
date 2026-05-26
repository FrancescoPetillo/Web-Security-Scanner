def calculate_score(findings, reputation=None, domain=None):
    score = 100

    severity_weights = {
        "High": 20,
        "Medium": 10,
        "Low": 3,
        "Info": 0
    }

    confidence_multiplier = {
        "high": 1.0,
        "medium": 0.7,
        "low": 0.4
    }

    high_count = 0
    medium_count = 0

    for finding in findings:
        severity = finding.get("severity", "Low")
        confidence = finding.get("confidence", "medium")

        weight = severity_weights.get(severity, 5)
        multiplier = confidence_multiplier.get(confidence, 0.7)

        penalty = weight * multiplier
        score -= penalty

        if severity == "High":
            high_count += 1
        elif severity == "Medium":
            medium_count += 1

    # 🔥 Penalità cumulative intelligenti
    if high_count >= 2:
        score -= 10

    if medium_count >= 4:
        score -= 5

    # 🔥 REPUTATION (VirusTotal)
    if reputation:
        malicious = reputation.get("malicious", 0)
        suspicious = reputation.get("suspicious", 0)

        score -= (malicious * 15)
        score -= (suspicious * 7)

    # 🔥 DOMAIN TRUST (light, non invasivo)
    if domain:
        trusted_domains = ["google.com", "github.com", "cloudflare.com"]

        if any(td in domain for td in trusted_domains):
            score += 5  # piccolo boost realistico

    # 🔥 Clamp finale pulito
    score = max(0, min(score, 100))

    return round(score)


def calculate_risk(score, findings):
    high_count = sum(1 for f in findings if f.get("severity") == "High")
    medium_count = sum(1 for f in findings if f.get("severity") == "Medium")

    if high_count >= 1:
        return {
            "risk_level": "High",
            "risk_explanation": "Critical vulnerabilities detected."
        }

    if score < 75 or medium_count >= 3:
        return {
            "risk_level": "Medium",
            "risk_explanation": "Several weaknesses detected."
        }

    return {
        "risk_level": "Low",
        "risk_explanation": "Strong security posture."
    }
