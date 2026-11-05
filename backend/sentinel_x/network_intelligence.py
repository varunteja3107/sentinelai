"""Explainable network telemetry analysis for SentinelAI-X."""

from datetime import datetime, timezone

import ipaddress
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
MULTI_PORT_SCAN_THRESHOLD = 15
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

    # Multiple destination ports on one remote IP may indicate port scanning.
    # This is a heuristic indicator, not proof of malicious activity.
    ports_by_remote_ip = {}

    for connection in connections:
        if not isinstance(connection, dict):
            continue

        try:
            remote_ip = str(ipaddress.ip_address(
                str(connection.get("remote_ip"))
            ))
            remote_port = int(connection.get("remote_port"))
        except (ValueError, TypeError):
            continue

        if not 1 <= remote_port <= 65535:
            continue

        ports_by_remote_ip.setdefault(remote_ip, set()).add(remote_port)

    for remote_ip, ports in ports_by_remote_ip.items():
        if len(ports) >= MULTI_PORT_SCAN_THRESHOLD:
            findings.append({
                "type": "multi_port_scan_indicator",
                "severity": "MEDIUM",
                "risk_score": 25,
                "description": (
                    f"{len(ports)} distinct destination ports observed "
                    f"for remote IP {remote_ip}; review for possible "
                    "port-scanning activity."
                ),
                "remote_ip": remote_ip,
                "distinct_ports": len(ports),
                "ports": sorted(ports),
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



def analyze_network_history(observations, minimum_observations=4):
    """
    Correlate remote endpoints across independent telemetry snapshots.

    Recurrence is contextual evidence, not proof of malicious activity.
    Loopback addresses are excluded because they represent local traffic.
    """
    if not isinstance(observations, (list, tuple)):
        observations = []

    try:
        minimum_observations = max(2, min(int(minimum_observations), 20))
    except (TypeError, ValueError):
        minimum_observations = 4

    observations = list(observations[:20])

    def get_connections(observation):
        if isinstance(observation, dict):
            connections = observation.get("connections") or []
        else:
            connections = getattr(observation, "connections", None) or []
        return connections if isinstance(connections, list) else []

    endpoint_snapshots = {}
    latest_endpoints = set()

    for index, observation in enumerate(observations):
        endpoints = set()

        for connection in get_connections(observation):
            if not isinstance(connection, dict):
                continue

            remote_ip = connection.get("remote_ip")
            try:
                ip = ipaddress.ip_address(str(remote_ip))
                remote_port = int(connection.get("remote_port"))
            except (ValueError, TypeError):
                continue

            if ip.is_loopback or not 0 <= remote_port <= 65535:
                continue

            protocol = str(connection.get("protocol") or "OTHER").upper()
            endpoints.add((str(ip), remote_port, protocol))

        for endpoint in endpoints:
            endpoint_snapshots[endpoint] = (
                endpoint_snapshots.get(endpoint, 0) + 1
            )

        if index == len(observations) - 1:
            latest_endpoints = endpoints

    findings = []

    for endpoint, count in endpoint_snapshots.items():
        if count < minimum_observations or endpoint not in latest_endpoints:
            continue

        remote_ip, remote_port, protocol = endpoint

        findings.append({
            "type": "historical_endpoint_recurrence",
            "severity": "LOW",
            "risk_score": 5,
            "description": (
                f"Remote endpoint {remote_ip}:{remote_port}/{protocol} "
                f"appeared in {count} independent telemetry observations "
                "and is present in the latest observation. Recurrence "
                "alone is not evidence of malicious activity."
            ),
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "protocol": protocol,
            "observation_count": count,
            "minimum_observations": minimum_observations,
        })


    # Compare the latest snapshot against a recent, timestamped baseline.
    # Snapshot counts are contextual indicators, not connection-event rates.
    if len(observations) >= 5:
        timestamped_counts = []

        for observation in observations:
            if isinstance(observation, dict):
                captured_at = observation.get("captured_at")
            else:
                captured_at = getattr(observation, "captured_at", None)

            if isinstance(captured_at, str):
                try:
                    captured_at = datetime.fromisoformat(
                        captured_at.replace("Z", "+00:00")
                    )
                except ValueError:
                    captured_at = None

            if not isinstance(captured_at, datetime):
                timestamped_counts = []
                break

            if captured_at.tzinfo is not None:
                captured_at = captured_at.astimezone(
                    timezone.utc
                ).replace(tzinfo=None)

            timestamped_counts.append(
                (captured_at, len(get_connections(observation)))
            )

        if len(timestamped_counts) == len(observations):
            timestamps = [item[0] for item in timestamped_counts]
            window_seconds = (
                timestamps[-1] - timestamps[0]
            ).total_seconds()

            if (
                timestamps == sorted(timestamps)
                and 0 <= window_seconds <= 600
            ):
                baseline_counts = sorted(
                    count for _, count in timestamped_counts[:-1]
                )
                middle = len(baseline_counts) // 2

                if len(baseline_counts) % 2:
                    baseline_median = baseline_counts[middle]
                else:
                    baseline_median = (
                        baseline_counts[middle - 1]
                        + baseline_counts[middle]
                    ) / 2

                latest_count = timestamped_counts[-1][1]
                increase = latest_count - baseline_median

                if (
                    latest_count >= 50
                    and latest_count >= baseline_median * 2
                    and increase >= 30
                ):
                    findings.append({
                        "type": "connection_volume_spike",
                        "severity": "MEDIUM",
                        "risk_score": 15,
                        "description": (
                            f"Latest snapshot contains {latest_count} "
                            f"connections, compared with a recent baseline "
                            f"median of {baseline_median:g}. Review this "
                            "unusual increase in observed connection volume."
                        ),
                        "latest_connection_count": latest_count,
                        "baseline_median": baseline_median,
                        "increase": increase,
                        "window_seconds": window_seconds,
                    })

    return {
        "risk_score": 0,
        "severity": "LOW",
        "finding_count": len(findings),
        "findings": findings,
        "observations_analyzed": len(observations),
        "assessment_type": "historical_network_correlation",
        "disclaimer": (
            "Recurring endpoints are contextual telemetry and do not "
            "independently prove malicious activity."
        ),
    }
