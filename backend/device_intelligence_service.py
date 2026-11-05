"""Database-backed device intelligence and alert persistence."""

import hashlib
import logging

from sqlalchemy.orm import Session

from device_intelligence import DeviceIntelligenceEngine
from models import (
    DeviceTelemetry,
    DeviceAssessment,
    DeviceAlert,
    SentinelXNetworkObservation,
)
from sentinel_x.network_intelligence import (
    analyze_network_observation,
    analyze_network_history,
)


logger = logging.getLogger("sentinelai.device_intelligence")

BASELINE_SIZE = 30


def _telemetry_payload(row):
    return {
        "cpu_percent": row.cpu_percent,
        "memory_percent": row.memory_percent,
        "disk_percent": row.disk_percent,
        "network_sent_mb": row.network_sent_mb,
        "network_recv_mb": row.network_recv_mb,
    }


def _alert_key(device_id, anomaly_type, episode_id):
    raw = f"{device_id}:{anomaly_type}:{episode_id}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def assess_and_persist(db: Session, current: DeviceTelemetry):
    """
    Reconstruct a device baseline from stored history, assess the current
    report, and persist the assessment and deduplicated alerts.

    The caller must commit the telemetry row before calling this function.
    """

    if current.id is None:
        raise ValueError("Current telemetry must be committed first.")

    history = (
        db.query(DeviceTelemetry)
        .filter(
            DeviceTelemetry.device_id == current.device_id,
            DeviceTelemetry.id != current.id,
        )
        .order_by(DeviceTelemetry.captured_at.desc(), DeviceTelemetry.id.desc())
        .limit(BASELINE_SIZE)
        .all()
    )

    history.reverse()

    # Restore consecutive anomalous reports from saved assessments.
    previous_assessments = (
        db.query(DeviceAssessment)
        .filter(DeviceAssessment.device_id == current.device_id)
        .order_by(DeviceAssessment.assessed_at.desc(), DeviceAssessment.id.desc())
        .limit(2)
        .all()
    )

    previous_streak = 0
    for previous in previous_assessments:
        if previous.anomaly_count > 0:
            previous_streak += 1
        else:
            break

    engine = DeviceIntelligenceEngine(baseline_size=BASELINE_SIZE)
    engine.seed_baseline(
        current.device_id,
        [_telemetry_payload(sample) for sample in history],
        anomaly_streak=previous_streak,
    )

    result = engine.analyze(
        current.device_id,
        _telemetry_payload(current),
    )

    assessment = DeviceAssessment(
        device_id=current.device_id,
        risk_score=result["risk_score"],
        severity=result["severity"],
        confidence=result["confidence"],
        baseline_samples=result["baseline_samples"],
        anomaly_count=result["anomaly_count"],
        evidence=result["evidence"],
        network_delta_mb=result["network_delta_mb"],
        recommended_action=result["recommended_action"],
        assessed_at=current.captured_at,
    )

    db.add(assessment)

    active_types = {
        str(item.get("metric", "unknown"))[:80]
        for item in result["evidence"]
    }

    existing_alerts = (
        db.query(DeviceAlert)
        .filter(
            DeviceAlert.device_id == current.device_id,
            DeviceAlert.anomaly_type.notlike("network_%"),
            DeviceAlert.status.in_(("OPEN", "ACKNOWLEDGED")),
        )
        .all()
    )

    # Resolve alerts whose anomalies are no longer present.
    for alert in existing_alerts:
        if alert.anomaly_type not in active_types:
            alert.status = "RESOLVED"
            alert.resolved_at = current.captured_at

    evidence_by_type = {}
    for item in result["evidence"]:
        anomaly_type = str(item.get("metric", "unknown"))[:80]
        evidence_by_type.setdefault(anomaly_type, []).append(item)

    # Create new alerts or refresh existing open alerts.
    for anomaly_type, evidence in evidence_by_type.items():
        alert = (
            db.query(DeviceAlert)
            .filter(
                DeviceAlert.device_id == current.device_id,
                DeviceAlert.anomaly_type == anomaly_type,
                DeviceAlert.status.in_(("OPEN", "ACKNOWLEDGED")),
            )
            .order_by(DeviceAlert.id.desc())
            .first()
        )

        description = "; ".join(
            str(item.get("reason", "Anomaly detected"))
            for item in evidence
        )[:1000]

        title = f"Device anomaly: {anomaly_type}"[:200]

        if alert is None:
            alert = DeviceAlert(
                alert_key=_alert_key(
                    current.device_id,
                    anomaly_type,
                    current.id,
                ),
                device_id=current.device_id,
                anomaly_type=anomaly_type,
                severity=result["severity"],
                risk_score=result["risk_score"],
                title=title,
                description=description,
                evidence=evidence,
                status="OPEN",
                first_detected_at=current.captured_at,
                last_detected_at=current.captured_at,
            )
            db.add(alert)
        else:
            alert.severity = result["severity"]
            alert.risk_score = result["risk_score"]
            alert.title = title
            alert.description = description
            alert.evidence = evidence
            alert.last_detected_at = current.captured_at

    db.commit()

    return result




def _network_indicator_present(alert, observation):
    """Check whether this alert's specific indicator exists in a snapshot."""
    evidence = alert.evidence if isinstance(alert.evidence, list) else []
    anomaly_type = alert.anomaly_type.removeprefix("network_")

    connections = observation.connections or []

    if anomaly_type in (
        "historical_endpoint_recurrence",
        "repeated_remote_endpoint",
    ):
        for item in evidence:
            if not isinstance(item, dict):
                continue

            for connection in connections:
                if not isinstance(connection, dict):
                    continue

                try:
                    port = int(connection.get("remote_port"))
                except (TypeError, ValueError):
                    continue

                if (
                    str(connection.get("remote_ip")) == str(item.get("remote_ip"))
                    and port == item.get("remote_port")
                    and str(connection.get("protocol") or "OTHER").upper()
                    == str(item.get("protocol") or "OTHER").upper()
                ):
                    return True
        return False

    if anomaly_type == "sensitive_remote_service":
        ports = set()
        for connection in connections:
            if isinstance(connection, dict):
                try:
                    ports.add(int(connection.get("remote_port")))
                except (TypeError, ValueError):
                    pass

        return any(
            isinstance(item, dict) and item.get("remote_port") in ports
            for item in evidence
        )

    current_findings = analyze_network_observation(observation)["findings"]

    for old in evidence:
        if not isinstance(old, dict):
            continue

        for current in current_findings:
            if current.get("type") != anomaly_type:
                continue

            identity_fields = (
                "remote_ip", "remote_port", "protocol", "service"
            )
            if all(
                old.get(key) == current.get(key)
                for key in identity_fields
                if key in old
            ):
                return True

    return False


def assess_network_and_persist(db: Session, observation: SentinelXNetworkObservation):
    """Analyse current and historical network snapshots and persist alerts."""

    history = (
        db.query(SentinelXNetworkObservation)
        .filter(
            SentinelXNetworkObservation.device_id == observation.device_id
        )
        .order_by(
            SentinelXNetworkObservation.captured_at.desc(),
            SentinelXNetworkObservation.id.desc(),
        )
        .limit(20)
        .all()
    )
    history.reverse()

    current_result = analyze_network_observation(observation)
    historical_result = analyze_network_history(history)

    findings = (
        list(current_result["findings"])
        + list(historical_result["findings"])
    )

    # Historical recurrence is contextual evidence and does not
    # increase the current network threat score.
    risk_score = current_result["risk_score"]
    severity = current_result["severity"]

    result = {
        **current_result,
        "risk_score": risk_score,
        "severity": severity,
        "findings": findings,
        "finding_count": len(findings),
        "historical_correlation": historical_result,
    }

    captured_at = observation.captured_at

    grouped_findings = {}
    for finding in findings:
        anomaly_type = (
            f"network_{str(finding.get('type', 'unknown'))[:70]}"
        )
        grouped_findings.setdefault(anomaly_type, []).append(finding)

    active_types = set(grouped_findings)

    existing_alerts = (
        db.query(DeviceAlert)
        .filter(
            DeviceAlert.device_id == observation.device_id,
            DeviceAlert.anomaly_type.like("network_%"),
            DeviceAlert.status.in_(("OPEN", "ACKNOWLEDGED")),
        )
        .all()
    )

    # Resolve only after three consecutive snapshots lack this indicator.
    recent_observations = history[-3:]

    for alert in existing_alerts:
        if alert.anomaly_type in active_types:
            continue

        if len(recent_observations) < 3:
            continue

        absent_three_times = all(
            not _network_indicator_present(alert, snapshot)
            for snapshot in recent_observations
        )

        if absent_three_times:
            alert.status = "RESOLVED"
            alert.resolved_at = captured_at

    for anomaly_type, evidence in grouped_findings.items():
        description = "; ".join(
            str(item.get("description", "Network indicator detected"))
            for item in evidence
        )[:1000]

        title = (
            f"Network indicator: "
            f"{anomaly_type.removeprefix('network_')}"
        )[:200]

        # Score each alert using its own evidence, not the device-wide
        # aggregate. Multiple endpoints of the same type do not stack.
        finding_scores = {
            "repeated_remote_endpoint": 25,
            "sensitive_remote_service": 10,
            "restricted_process_indicator": 35,
            "high_connection_volume": 10,
            "historical_endpoint_recurrence": 5,
        }
        severity_rank = {
            "LOW": 0,
            "MEDIUM": 1,
            "HIGH": 2,
            "CRITICAL": 3,
        }

        alert_risk_score = max(
            (
                int(item.get(
                    "risk_score",
                    finding_scores.get(
                        str(item.get("type", "")), 0
                    ),
                ))
                for item in evidence
            ),
            default=0,
        )
        alert_severity = max(
            (
                str(item.get("severity", "LOW")).upper()
                for item in evidence
            ),
            key=lambda value: severity_rank.get(value, 0),
            default="LOW",
        )

        alert = (
            db.query(DeviceAlert)
            .filter(
                DeviceAlert.device_id == observation.device_id,
                DeviceAlert.anomaly_type == anomaly_type,
                DeviceAlert.status.in_(("OPEN", "ACKNOWLEDGED")),
            )
            .order_by(DeviceAlert.id.desc())
            .first()
        )

        if alert is None:
            alert = DeviceAlert(
                alert_key=_alert_key(
                    observation.device_id,
                    anomaly_type,
                    observation.id,
                ),
                device_id=observation.device_id,
                anomaly_type=anomaly_type,
                severity=alert_severity,
                risk_score=alert_risk_score,
                title=title,
                description=description,
                evidence=evidence,
                status="OPEN",
                first_detected_at=captured_at,
                last_detected_at=captured_at,
            )
            db.add(alert)
        else:
            alert.severity = alert_severity
            alert.risk_score = alert_risk_score
            alert.title = title
            alert.description = description
            alert.evidence = evidence
            alert.last_detected_at = captured_at

    db.commit()
    return result
