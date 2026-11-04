"""Explainable network telemetry analysis for SentinelAI-X."""

from collections import Counter


SENSITIVE_REMOTE_PORTS = {
    23: "Telnet",
    445: "SMB",
    3389: "Remote Desktop",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM over TLS",
}

REPEATED_ENDPOINT_THRESHOLD = 10
HIGH_CONNECTION_THRESHOLD = 80


def analyze_network_observation(observation):
    """
    Analyse one stored network observation.

    This is heuristic triage, not proof of malicious activity.
    The function does not block connections or modify device state.
    """

    if isinstance(observation, dict):
        connections = observation.get("connections") or []
        restricted_processes = observation.get("restricted_processes", 0)
        warnings = observation.get("warnings") or []
    else:
        connections = observation.connections or []
        restricted_processes = observation.restricted_processes or 0
        warnings = observation.warnings or []

    if not isinstance(connections, list):
        connections = []

    try:
        restricted_processes = max(0, min(int(restricted_processes), 100000))
    except (TypeError, ValueError):
        restricted_processes = 0

    findings = []
    score = 0

    # Repeated connections to the same remote endpoint.
    endpoint_counts = Counter()

    for connection in connections:
        if not isinstance(connection, dict):
            continue

        remote_ip = connection.get("remote_ip")
        remote_port = connection.get("remote_port")
        protocol = str(connection.get("protocol") or "OTHER").upper()

        if remote_ip and remote_port is not None:
            endpoint_counts[
                (str(remote_ip), int(remote_port), protocol)
            ] += 1

    for (remote_ip, remote_port, protocol), count in endpoint_counts.items():
        if count >= REPEATED_ENDPOINT_THRESHOLD:
            findings.append({
                "type": "repeated_remote_endpoint",
                "severity": "MEDIUM",
                "description": (
                    f"{count} connections observed to "
                    f"{remote_ip}:{remote_port}/{protocol}"
                ),
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "protocol": protocol,
                "count": count,
            })
            score += 25

    # Sensitive remote service ports are indicators for review,
    # not automatic proof of an attack.
    observed_sensitive_ports = set()

    for connection in connections:
        if not isinstance(connection, dict):
            continue

        try:
            remote_port = int(connection.get("remote_port"))
        except (TypeError, ValueError):
            continue

        if remote_port in SENSITIVE_REMOTE_PORTS:
            observed_sensitive_ports.add(remote_port)

    for port in sorted(observed_sensitive_ports):
        service = SENSITIVE_REMOTE_PORTS[port]
        findings.append({
            "type": "sensitive_remote_service",
            "severity": "LOW",
            "description": (
                f"Connection observed using remote {service} port {port}; "
                "review whether this traffic is expected."
            ),
            "remote_port": port,
            "service": service,
        })
        score += 10

    # Restricted-process count is reported by the endpoint agent.
    if restricted_processes > 0:
        findings.append({
            "type": "restricted_process_indicator",
            "severity": "HIGH",
            "description": (
                f"Endpoint agent reported {restricted_processes} "
                "restricted-process indicator(s)."
            ),
            "count": restricted_processes,
        })
        score += 35

    # Large connection snapshots deserve review, but are not
    # independently classified as malicious.
    connection_count = len(connections)

    if connection_count >= HIGH_CONNECTION_THRESHOLD:
        findings.append({
            "type": "high_connection_volume",
            "severity": "LOW",
            "description": (
                f"Large connection snapshot: {connection_count} connections."
            ),
            "count": connection_count,
        })
        score += 10

    score = min(score, 100)

    if score >= 75:
        severity = "CRITICAL"
    elif score >= 50:
        severity = "HIGH"
    elif score >= 25:
        severity = "MEDIUM"
    elif score > 0:
        severity = "LOW"
    else:
        severity = "LOW"

    return {
        "risk_score": score,
        "severity": severity,
        "finding_count": len(findings),
        "findings": findings,
        "connection_count": connection_count,
        "restricted_processes": restricted_processes,
        "warnings": [
            str(item)[:200]
            for item in warnings[:10]
        ] if isinstance(warnings, list) else [],
        "assessment_type": "heuristic_network_triage",
        "disclaimer": (
            "Indicators require investigation and do not independently "
            "prove malicious activity."
        ),
    }
