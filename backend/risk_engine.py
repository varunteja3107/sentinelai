def calculate_risk(
    anomaly_score,
    device_risk=20,
    behavior_risk=20,
    policy_risk=10
):

    risk = (
        (0.45 * anomaly_score)
        +
        (0.20 * device_risk)
        +
        (0.20 * behavior_risk)
        +
        (0.15 * policy_risk)
    )

    risk = round(
        min(100, max(0, risk)),
        2
    )

    if risk >= 80:
        severity = "CRITICAL"
        action = "BLOCK"

    elif risk >= 60:
        severity = "HIGH"
        action = "BLOCK"

    elif risk >= 30:
        severity = "MEDIUM"
        action = "MFA"

    else:
        severity = "LOW"
        action = "ALLOW"

    return risk, severity, action
