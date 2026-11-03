import ipaddress

from sqlalchemy.orm import Session

from models import (
    Threat,
    Incident,
    FirewallRule,
    UserSession,
    AuditLog,
    ResponseAction,
    BlockSpikeAlert,
)


def mask_ip(value):
    """Mask the final IPv4 octet before external AI processing."""
    if not value:
        return "UNKNOWN"

    try:
        address = ipaddress.ip_address(str(value))
        if address.version == 4:
            parts = str(address).split(".")
            return ".".join(parts[:3] + ["xxx"])

        # Do not transmit full IPv6 addresses.
        return "IPv6_ADDRESS_REDACTED"

    except ValueError:
        return "INVALID_OR_UNKNOWN"


def build_security_context(db: Session):
    """
    Build a bounded, read-only security snapshot for Gemini.

    No database writes or security actions are performed.
    """

    threats = (
        db.query(Threat)
        .order_by(Threat.created_at.desc())
        .limit(20)
        .all()
    )

    incidents = (
        db.query(Incident)
        .order_by(Incident.created_at.desc())
        .limit(15)
        .all()
    )

    firewall_rules = (
        db.query(FirewallRule)
        .order_by(FirewallRule.priority.asc())
        .limit(20)
        .all()
    )

    sessions = (
        db.query(UserSession)
        .order_by(UserSession.updated_at.desc())
        .limit(15)
        .all()
    )

    audit_logs = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .limit(15)
        .all()
    )

    pending_actions = (
        db.query(ResponseAction)
        .filter(ResponseAction.status == "PENDING")
        .order_by(ResponseAction.created_at.desc())
        .limit(10)
        .all()
    )

    block_alerts = (
        db.query(BlockSpikeAlert)
        .order_by(BlockSpikeAlert.detected_at.desc())
        .limit(10)
        .all()
    )

    def safe_text(value, limit=200):
        if value is None:
            return ""
        return str(value)[:limit]

    return {
        "source": "SentinelAI local database",
        "mode": "read_only",
        "approval_required": True,

        "summary": {
            "threat_records": len(threats),
            "incident_records": len(incidents),
            "firewall_rules": len(firewall_rules),
            "zero_trust_sessions": len(sessions),
            "audit_events": len(audit_logs),
            "pending_response_actions": len(pending_actions),
            "block_spike_alerts": len(block_alerts),
        },

        "threats": [
            {
                "id": item.id,
                "type": safe_text(item.threat_type, 80),
                "source_ip": mask_ip(item.source_ip),
                "destination_ip": mask_ip(item.destination_ip),
                "port": item.port,
                "protocol": safe_text(item.protocol, 20),
                "packets": item.packets,
                "bytes_transferred": item.bytes_transferred,
                "anomaly_score": item.anomaly_score,
                "risk_score": item.risk_score,
                "severity": safe_text(item.severity, 30),
                "recorded_action": safe_text(item.action, 30),
                "status": safe_text(item.status, 30),
                "created_at": safe_text(item.created_at, 40),
            }
            for item in threats
        ],

        "incidents": [
            {
                "id": item.id,
                "title": safe_text(item.title, 120),
                "severity": safe_text(item.severity, 30),
                "risk_score": item.risk_score,
                "status": safe_text(item.status, 30),
                "threat_id": item.threat_id,
                "created_at": safe_text(item.created_at, 40),
            }
            for item in incidents
        ],

        "firewall_rules": [
            {
                "id": item.id,
                "name": safe_text(item.name, 100),
                "port": safe_text(item.port, 32),
                "protocol": safe_text(item.protocol, 20),
                "action": safe_text(item.action, 20),
                "status": safe_text(item.status, 20),
                "priority": item.priority,
                "description": safe_text(item.description, 200),
            }
            for item in firewall_rules
        ],

        "zero_trust_sessions": [
            {
                "risk_score": item.risk_score,
                "decision": safe_text(item.decision, 20),
                "identity_verified": bool(item.identity_verified),
                "device_trusted": bool(item.device_trusted),
                "network_trusted": bool(item.network_trusted),
                "device_compliant": bool(item.device_compliant),
                "device_posture_score": item.device_posture_score,
                "failed_login_attempts": item.failed_login_attempts,
                "unusual_activity": bool(item.unusual_activity),
                "resource_sensitivity": safe_text(
                    item.resource_sensitivity, 20
                ),
                "status": safe_text(item.status, 20),
            }
            for item in sessions
        ],

        "audit_events": [
            {
                "event_type": safe_text(item.event_type, 80),
                "severity": safe_text(item.severity, 20),
                "action": safe_text(item.action, 50),
                "source_ip": mask_ip(item.source_ip),
                "message": safe_text(item.message, 200),
                "created_at": safe_text(item.created_at, 40),
            }
            for item in audit_logs
        ],

        "pending_response_actions": [
            {
                "id": item.id,
                "threat_type": safe_text(item.threat_type, 80),
                "risk_score": item.risk_score,
                "recommended_action": safe_text(
                    item.recommended_action, 200
                ),
                "status": safe_text(item.status, 20),
                "simulation_mode": bool(item.simulation_mode),
                "rollback_status": safe_text(item.rollback_status, 30),
            }
            for item in pending_actions
        ],

        "block_spike_alerts": [
            {
                "severity": safe_text(item.severity, 20),
                "latest_block_count": item.latest_block_count,
                "baseline_average": item.baseline_average,
                "detection_threshold": item.detection_threshold,
                "status": safe_text(item.status, 20),
            }
            for item in block_alerts
        ],
    }
