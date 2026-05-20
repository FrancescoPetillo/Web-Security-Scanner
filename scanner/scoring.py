def calculate_score(findings):
    score = 100

    for finding in findings:
        if finding["severity"] == "High":
            score -= 30
        elif finding["severity"] == "Medium":
            score -= 20
        elif finding["severity"] == "Low":
            score -= 10

    if score < 0:
        score = 0

    return score
