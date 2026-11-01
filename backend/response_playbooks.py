"""Explainable, recommendation-only incident response playbooks."""

from typing import Any


PLAYBOOKS: dict[str, dict[str, Any]] = {
    "DDOS": {
        "title": "Distributed denial-of-service response",
        "severity": "HIGH",
        "actions": [
            "Review traffic volume and source distribution",
            "Evaluate rate-limiting rules in simulation mode",
            "Request approval before proposing temporary source blocks",
            "Monitor service availability and record the outcome",
        ],
        "approval_required": True,
    },
    "DOS": {
        "title": "Denial-of-service response",
        "severity": "HIGH",
        "actions": [
            "Review packet rate and affected destination",
            "Evaluate rate-limiting rules in simulation mode",
            "Request approval before proposing containment",
            "Verify service recovery and record the outcome",
        ],
        "approval_required": True,
    },
    "PORT_SCAN": {
        "title": "Port-scan investigation",
        "severity": "MEDIUM",
        "actions": [
            "Review targeted ports and connection frequency",
            "Check whether the source is an authorized scanner",
            "Evaluate firewall rules without applying real network changes",
            "Escalate if scanning continues or is followed by exploitation",
        ],
        "approval_required": False,
    },
    "BRUTE_FORCE": {
        "title": "Brute-force investigation",
        "severity": "HIGH",
        "actions": [
            "Review authentication failure counts and affected accounts",
            "Verify the activity with the identity or authentication logs",
            "Require additional authentication where supported",
            "Request approval before proposing account or source containment",
        ],
        "approval_required": True,
    },
    "MALWARE": {
        "title": "Potential malware investigation",
        "severity": "CRITICAL",
        "actions": [
            "Preserve relevant security logs and detection evidence",
            "Review device identity and recent process or network activity",
            "Request authorized approval for simulated device quarantine",
            "Validate recovery before marking the incident resolved",
        ],
        "approval_required": True,
    },
    "UNKNOWN": {
        "title": "General threat investigation",
        "severity": "MEDIUM",
        "actions": [
            "Review the detection explanation and supporting telemetry",
            "Validate source, destination, protocol, and affected service",
            "Run the event through the firewall simulator",
            "Escalate to an analyst if the evidence remains inconclusive",
        ],
        "approval_required": False,
    },
}


def recommend_response(
    threat_type: str,
    severity: str = "MEDIUM",
    risk_score: float = 0,
) -> dict[str, Any]:
    """Return a response recommendation without executing actions."""
    normalized_type = threat_type.strip().upper().replace("-", "_").replace(" ", "_")
    playbook = PLAYBOOKS.get(normalized_type, PLAYBOOKS["UNKNOWN"])

    normalized_severity = severity.strip().upper()
    if normalized_severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        normalized_severity = "MEDIUM"

    score = float(risk_score)
    if not 0 <= score <= 100:
        raise ValueError("risk_score must be between 0 and 100")

    actions = list(playbook["actions"])
    approval_required = playbook["approval_required"] or score >= 60

    if score >= 80 and (
        "Request analyst review of this critical-risk event"
        not in actions
    ):
        actions.insert(
            0,
            "Request analyst review of this critical-risk event",
        )

    return {
        "threat_type": normalized_type,
        "playbook_title": playbook["title"],
        "severity": (
            "CRITICAL" if score >= 80
            else "HIGH" if score >= 60
            else normalized_severity
        ),
        "risk_score": score,
        "recommended_actions": actions,
        "approval_required": approval_required,
        "execution_mode": "RECOMMENDATION_ONLY",
        "simulation_mode": True,
        "limitation": (
            "Recommendations only. No firewall, device, account, "
            "or network action is executed by this module."
        ),
    }
