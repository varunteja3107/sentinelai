def calculate_risk(
    anomaly_score,
    device_risk=20,
    behavior_risk=20,
    policy_risk=10,
    attack_type=None,
):
    risk = (
        (0.45 * anomaly_score)
        + (0.20 * device_risk)
        + (0.20 * behavior_risk)
        + (0.15 * policy_risk)
    )

    # Apply a risk floor for recognized high-impact attack scenarios.
    # This is a demo policy, not a production-validated security rule.
    normalized_type = str(attack_type or "").strip().lower().replace("-", "_").replace(" ", "_")

    risk_floors = {
        "ddos": 80,
        "ddos_simulation": 80,
        "port_scan": 60,
        "brute_force": 60,
    }

    if normalized_type in risk_floors:
        risk = max(risk, risk_floors[normalized_type])

    risk = round(min(100, max(0, risk)), 2)

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
