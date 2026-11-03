"""Database-backed device intelligence and alert persistence."""

import hashlib
import logging

from sqlalchemy.orm import Session

from device_intelligence import DeviceIntelligenceEngine
from models import DeviceTelemetry, DeviceAssessment, DeviceAlert


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
