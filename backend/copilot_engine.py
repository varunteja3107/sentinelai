from typing import Optional

from ai_engine import ThreatDetectionAI
from security_context import build_security_context
from llm_provider import generate_gemini_response


# Reuse the existing trained detector.
_threat_detector = ThreatDetectionAI()


def _validate_network_event(event):
    """Validate network features before passing them to the ML models."""

    required = (
        "packets",
        "bytes_transferred",
        "port",
        "failed_attempts",
    )

    if not isinstance(event, dict):
        raise ValueError("Network event must be a dictionary")

    if any(key not in event for key in required):
        raise ValueError("Network event is missing required features")

    values = {}

    limits = {
        "packets": (0, 100_000_000),
        "bytes_transferred": (0, 10**12),
        "port": (0, 65535),
        "failed_attempts": (0, 10_000_000),
    }

    for key, (minimum, maximum) in limits.items():
        value = event[key]

        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{key} must be numeric")

        if value < minimum or value > maximum:
            raise ValueError(f"{key} is outside the allowed range")

        values[key] = value

    return values


def analyze_network_event(network_event):
    """Run the existing ML detector on explicitly supplied features."""

    features = _validate_network_event(network_event)

    result = _threat_detector.analyze_detailed(**features)

    return {
        "available": True,
        "model": "Isolation Forest + Random Forest",
        "result": result,
        "interpretation": (
            "ML classification is a supporting signal, not proof "
            "of malicious activity."
        ),
    }


def run_copilot(
    question: str,
    db,
    network_event: Optional[dict] = None,
):
    """
    Combine database security context, optional ML analysis,
    and Gemini explanation.

    This function is read-only. It never executes security actions.
    """

    if not isinstance(question, str) or not question.strip():
        raise ValueError("A question is required")

    if len(question) > 4000:
        raise ValueError("Question exceeds the allowed length")

    # Read current security records.
    security_context = build_security_context(db)

    # Only analyze ML features when explicitly supplied.
    ml_analysis = {
        "available": False,
        "reason": (
            "No network event was supplied. "
            "No ML prediction was performed."
        ),
    }

    if network_event is not None:
        ml_analysis = analyze_network_event(network_event)

    # Combine the independent evidence sources.
    copilot_context = {
        "security_database": security_context,
        "ml_analysis": ml_analysis,
        "operating_policy": {
            "mode": "read_only",
            "approval_required": True,
            "automatic_execution": False,
            "action_execution_allowed": False,
        },
    }

    answer = generate_gemini_response(
        question=question,
        security_context=copilot_context,
    )

    return {
        "answer": answer,
        "ml_analysis": ml_analysis,
        "summary": security_context["summary"],
        "mode": "read_only",
        "approval_required": True,
        "actions_executed": False,
    }
