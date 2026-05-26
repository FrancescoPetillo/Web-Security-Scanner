def calculate_score(findings):
    score = 100
    high_count = 0
    medium_count = 0

    for finding in findings:

        if finding["severity"] == "High":
            score -= 25
            high_count += 1

        elif finding["severity"] == "Medium":
            score -= 8
            medium_count += 1

        elif finding["severity"] == "Low":
            score -= 2

    # Penalità extra solo se tanti HIGH
    if high_count >= 2:
        score -= 10

    # Penalità leggera se tanti MEDIUM
    if medium_count >= 4:
        score -= 5

    # Clamp intelligente (molto importante)
    if high_count == 0:
        score = max(score, 60)

    if score < 0:
        score = 0

    return score

def calculate_risk(score, findings):

    high_count = sum(1 for f in findings if f["severity"] == "High")
    medium_count = sum(1 for f in findings if f["severity"] == "Medium")

    # HIGH risk
    if high_count >= 1:
        return {
            "risk_level": "High",
            "risk_explanation": (
                "Critical vulnerabilities were detected that could significantly "
                "increase the attack surface of the application."
            )
        }

    # MEDIUM risk
    elif score < 70 or medium_count >= 3:
        return {
            "risk_level": "Medium",
            "risk_explanation": (
                "Several security weaknesses were identified that may expose "
                "the application to potential risks."
            )
        }

    # LOW risk
    else:
        return {
            "risk_level": "Low",
            "risk_explanation": (
                "The application shows a generally strong security posture "
                "with only minor issues detected."
            )
        }