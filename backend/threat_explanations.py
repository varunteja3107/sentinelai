"""Explainable traffic signals and exact-match threat indicators.

These rules provide transparent heuristics for analyst review.
They are not a substitute for model explanations or a validated
threat-intelligence service.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any


def explain_detection(
    packets: int,
    bytes_transferred: int,
    port: int,
    failed_attempts: int,
    threat_type: str,
    anomaly_score: float,
    confidence: float,
) -> dict[str, Any]:
    """Return transparent heuristic signals for one traffic observation."""

    values = {
        "packets": packets,
        "bytes_transferred": bytes_transferred,
        "port": port,
        "failed_attempts": failed_attempts,
    }

    for name, value in values.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{name} must be numeric")
        if value < 0 or not float(value).is_integer():
            raise ValueError(f"{name} must be a non-negative integer")

    for name, value in (
        ("anomaly_score", anomaly_score),
        ("confidence", confidence),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{name} must be numeric")
        if not 0 <= value <= 100:
            raise ValueError(f"{name} must be between 0 and 100")

    if not 0 <= port <= 65535:
        raise ValueError("port must be 0 (unknown) or between 1 and 65535")

    signals = []

    if packets >= 1000:
        signals.append({
            "code": "HIGH_PACKET_VOLUME",
            "severity": "high",
            "detail": f"Observed {packets} packets.",
        })

    if bytes_transferred >= 100_000:
        signals.append({
            "code": "HIGH_BYTE_VOLUME",
            "severity": "medium",
            "detail": f"Observed {bytes_transferred} bytes transferred.",
        })

    if failed_attempts >= 10:
        signals.append({
            "code": "REPEATED_FAILURES",
            "severity": "high",
            "detail": f"Observed {failed_attempts} failed attempts.",
        })

    if port in {21, 22, 23, 3389}:
        signals.append({
            "code": "SENSITIVE_SERVICE_PORT",
            "severity": "informational",
            "detail": f"Traffic targets service port {port}; this alone does not indicate an attack.",
        })

    if anomaly_score >= 70:
        signals.append({
            "code": "HIGH_ANOMALY_SCORE",
            "severity": "high",
            "detail": f"The existing anomaly score is {anomaly_score}/100.",
        })

    if not signals:
        signals.append({
            "code": "NO_CONFIGURED_HEURISTIC_TRIGGERED",
            "severity": "informational",
            "detail": "None of this module's configured thresholds were reached.",
        })

    return {
        "threat_type": str(threat_type),
        "anomaly_score": round(float(anomaly_score), 2),
        "classifier_confidence": round(float(confidence), 2),
        "signals": signals,
        "explanation_type": "transparent_heuristics",
        "limitations": (
            "These signals explain configured thresholds, not the internal "
            "reasoning of the machine-learning models. Thresholds are "
            "demonstration defaults and require validation before production use."
        ),
    }


def normalize_indicator(value: str) -> str:
    """Normalize an IP address, domain, or SHA-256 indicator for exact matching."""

    if not isinstance(value, str):
        raise ValueError("Indicator must be a string")

    value = value.strip()

    if not value or len(value) > 253:
        raise ValueError("Indicator must contain between 1 and 253 characters")

    if any(char.isspace() for char in value):
        raise ValueError("Indicator must not contain whitespace")

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return value.lower()

    domain = value.rstrip(".").lower()

    if len(domain) > 253 or not domain:
        raise ValueError("Invalid domain indicator")

    labels = domain.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Invalid domain or indicator format")

    return domain


def match_indicator(
    observed_value: str,
    known_indicators: list[str],
) -> dict[str, Any]:
    """Check an observed indicator against a supplied local list."""

    if not isinstance(known_indicators, list):
        raise ValueError("known_indicators must be a list")

    observed = normalize_indicator(observed_value)
    matches = []

    for item in known_indicators:
        normalized = normalize_indicator(item)
        if normalized == observed and normalized not in matches:
            matches.append(normalized)

    return {
        "observed": observed,
        "matched": bool(matches),
        "matches": matches,
        "source": "user_supplied_local_list",
        "limitations": (
            "An exact match only confirms presence in the supplied list. "
            "It does not independently verify maliciousness or list freshness."
        ),
    }
