import os
import ipaddress
import time
from collections import defaultdict, deque
from threading import RLock
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, Header
from pydantic import BaseModel, Field
from typing import Optional
from fastapi.middleware.cors import CORSMiddleware
from io import BytesIO

from sqlalchemy import inspect
from sqlalchemy.orm import Session

from database import Base, engine, get_db
from models import Threat, Device, Incident
from schemas import ThreatCreate, ThreatResponse, ZeroTrustRequest, ZeroTrustResponse

from ai_engine import ThreatDetectionAI
from risk_engine import calculate_risk


Base.metadata.create_all(bind=engine)

# Add the notes column when upgrading an older existing database.
# SQLAlchemy inspection works with SQLite and PostgreSQL.
incident_columns = {
    column["name"] for column in inspect(engine).get_columns("incidents")
}
if "notes" not in incident_columns:
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "ALTER TABLE incidents ADD COLUMN notes VARCHAR DEFAULT ''"
        )

app = FastAPI(
    title="SentinelAI API",
    version="1.0.0",
)

frontend_origins = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "FRONTEND_URL",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=frontend_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


ai = ThreatDetectionAI()


@app.get("/")
def root():

    return {
        "application": "SentinelAI",
        "status": "online",
        "version": "1.0.0"
    }


@app.get("/api/health")
def health():

    return {
        "status": "healthy",
        "ai_engine": "online",
        "database": "connected"
    }


@app.get("/api/dashboard")
def dashboard(
    db: Session = Depends(get_db)
):

    active_threats = db.query(Threat).filter(
        Threat.status == "OPEN"
    ).count()

    blocked_attacks = db.query(Threat).filter(
        Threat.action == "BLOCK"
    ).count()

    devices = db.query(Device).count()

    alerts = db.query(Incident).filter(
        Incident.status == "OPEN"
    ).count()

    return {

        "active_threats": active_threats,

        "blocked_attacks": blocked_attacks,

        "connected_devices": devices,

        "security_alerts": alerts,

        "security_score": max(
            0,
            100 - (active_threats * 2)
        )
    }


@app.get("/api/threats")
def get_threats(
    db: Session = Depends(get_db)
):

    return db.query(
        Threat
    ).order_by(
        Threat.created_at.desc()
    ).all()


@app.post(
    "/api/threats/analyze",
    response_model=ThreatResponse
)
def analyze_threat(
    event: ThreatCreate,
    db: Session = Depends(get_db)
):

    failed_attempts = max(
        0,
        event.packets // 50
    )

    anomaly_score = ai.analyze(

        packets=event.packets,

        bytes_transferred=event.bytes_transferred,

        port=event.port,

        failed_attempts=failed_attempts
    )

    device_risk = 80 if event.port in [
        22,
        23,
        3389
    ] else 20

    behavior_risk = min(
        100,
        failed_attempts * 5
    )

    policy_risk = 80 if event.port in [
        23,
        3389
    ] else 20

    risk_score, severity, action = calculate_risk(
        anomaly_score,
        device_risk,
        behavior_risk,
        policy_risk,
        attack_type=event.threat_type,
    )

    threat = Threat(

        threat_type=event.threat_type,

        source_ip=event.source_ip,

        destination_ip=event.destination_ip,

        protocol=event.protocol,

        port=event.port,

        packets=event.packets,

        bytes_transferred=event.bytes_transferred,

        anomaly_score=anomaly_score,

        risk_score=risk_score,

        severity=severity,

        action=action,

        status="OPEN"
    )

    db.add(threat)

    db.commit()

    db.refresh(threat)


    if action == "BLOCK":

        incident = Incident(

            title=f"{severity} Threat: {event.threat_type}",

            severity=severity,

            risk_score=risk_score,

            status="OPEN",

            threat_id=threat.id
        )

        db.add(incident)

        db.commit()


    create_audit_log(
        db=db,
        event_type="THREAT_BLOCKED" if action == "BLOCK" else "THREAT_DETECTED",
        message=(
            f"SentinelAI detected {event.threat_type} "
            f"from {event.source_ip} to "
            f"{event.destination_ip}:{event.port}. "
            f"Risk: {risk_score}. Action: {action}"
        ),
        severity=severity,
        source_ip=event.source_ip,
        action=action
    )


    return threat


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = Field(default=None, max_length=5000)


def incident_response(incident, db):
    threat = None
    if incident.threat_id is not None:
        threat = db.query(Threat).filter(
            Threat.id == incident.threat_id
        ).first()

    return {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "status": incident.status,
        "notes": incident.notes or "",
        "threat_id": incident.threat_id,
        "created_at": incident.created_at,
        "threat_type": threat.threat_type if threat else None,
        "source_ip": threat.source_ip if threat else None,
        "destination_ip": threat.destination_ip if threat else None,
        "description": (
            f"{threat.threat_type} traffic to port {threat.port} over {threat.protocol}"
            if threat else None
        ),
    }


@app.get("/api/incidents")
def get_incidents(db: Session = Depends(get_db)):
    incidents = db.query(Incident).order_by(
        Incident.created_at.desc()
    ).all()
    return [incident_response(item, db) for item in incidents]


@app.patch("/api/incidents/{incident_id}")
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    db: Session = Depends(get_db)
):
    incident = db.query(Incident).filter(
        Incident.id == incident_id
    ).first()

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    changes = payload.dict(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="No update fields supplied")

    if "status" in changes:
        if changes["status"] is None:
            raise HTTPException(status_code=400, detail="Status cannot be null")
        status = changes["status"].strip().upper()
        allowed = {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}
        if status not in allowed:
            raise HTTPException(status_code=400, detail="Unsupported incident status")
        incident.status = status

    if "notes" in changes:
        if changes["notes"] is None:
            raise HTTPException(status_code=400, detail="Notes cannot be null")
        incident.notes = changes["notes"].strip()

    db.commit()
    db.refresh(incident)

    threat = None
    if incident.threat_id is not None:
        threat = db.query(Threat).filter(
            Threat.id == incident.threat_id
        ).first()

    create_audit_log(
        db=db,
        event_type="INCIDENT_UPDATED",
        message=(
            f"Incident #{incident.id} updated; status={incident.status}; "
            f"notes_updated={'yes' if 'notes' in changes else 'no'}"
        ),
        severity=incident.severity or "INFO",
        source_ip=threat.source_ip if threat else "",
        action="UPDATE"
    )

    return incident_response(incident, db)


@app.get("/api/devices")
def get_devices(
    db: Session = Depends(get_db)
):

    return db.query(Device).all()


@app.post("/api/devices/seed")
def seed_devices(
    db: Session = Depends(get_db)
):

    if db.query(Device).count() > 0:

        return {
            "message": "Devices already exist"
        }


    devices = [

        Device(
            name="Gateway-01",
            ip_address="192.168.1.1",
            device_type="Gateway",
            trust_score=98,
            status="ONLINE"
        ),

        Device(
            name="Server-01",
            ip_address="192.168.1.10",
            device_type="Server",
            trust_score=94,
            status="ONLINE"
        ),

        Device(
            name="Workstation-01",
            ip_address="192.168.1.25",
            device_type="Workstation",
            trust_score=87,
            status="ONLINE"
        ),

        Device(
            name="Laptop-01",
            ip_address="192.168.1.45",
            device_type="Laptop",
            trust_score=91,
            status="ONLINE"
        )
    ]

    db.add_all(devices)

    db.commit()

    return {
        "message": "Devices created",
        "count": len(devices)
    }


@app.post("/api/demo/attack", response_model=ThreatResponse)
def simulate_attack(
    scenario: str = "port_scan",
    db: Session = Depends(get_db)
):
    """Generate a simulated traffic event and analyze it using the existing AI engine."""

    scenarios = {
        "port_scan": {
            "threat_type": "Port Scan",
            "source_ip": "192.168.1.250",
            "destination_ip": "192.168.1.10",
            "protocol": "TCP",
            "port": 3389,
            "packets": 950,
            "bytes_transferred": 85000,
        },
        "ddos": {
            "threat_type": "DDoS Simulation",
            "source_ip": "192.168.1.251",
            "destination_ip": "192.168.1.10",
            "protocol": "TCP",
            "port": 443,
            "packets": 6000,
            "bytes_transferred": 1000000,
        },
        "brute_force": {
            "threat_type": "Brute Force",
            "source_ip": "192.168.1.252",
            "destination_ip": "192.168.1.10",
            "protocol": "TCP",
            "port": 22,
            "packets": 400,
            "bytes_transferred": 60000,
        },
        "benign": {
            "threat_type": "Benign HTTPS Traffic",
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.10",
            "protocol": "TCP",
            "port": 443,
            "packets": 30,
            "bytes_transferred": 8000,
        },
    }

    selected = scenario.strip().lower().replace("-", "_").replace(" ", "_")
    if selected not in scenarios:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Unknown simulation scenario",
                "available_scenarios": list(scenarios.keys()),
            },
        )

    event = ThreatCreate(**scenarios[selected])
    threat = analyze_threat(event, db)
    return ThreatResponse.model_validate(threat)


@app.post(
    "/api/zero-trust/check",
    response_model=ZeroTrustResponse
)
def zero_trust_check(
    request: ZeroTrustRequest,
    db: Session = Depends(get_db)
):

    risk = request.risk_score

    if not request.identity_verified:
        return ZeroTrustResponse(
            decision="BLOCK",
            risk_score=100,
            identity="UNVERIFIED",
            device="UNKNOWN",
            context="DENIED",
            reason="Identity verification failed."
        )

    if not request.device_trusted:
        risk = min(100, risk + 25)

    if request.location.lower() in [
        "unknown",
        "untrusted",
        "foreign"
    ]:
        risk = min(100, risk + 15)

    if risk >= 80:

        decision = "BLOCK"

        reason = (
            "Critical risk detected. "
            "Access blocked and security incident recommended."
        )

    elif risk >= 60:

        decision = "BLOCK"

        reason = (
            "High risk detected. "
            "Zero Trust policy requires access denial."
        )

    elif risk >= 30:

        decision = "MFA"

        reason = (
            "Medium risk detected. "
            "Additional authentication is required."
        )

    else:

        decision = "ALLOW"

        reason = (
            "Low risk. Identity and device posture "
            "meet Zero Trust requirements."
        )

    create_audit_log(
        db=db,
        event_type="ZERO_TRUST",
        message=(
            f"User {request.user} requested "
            f"{request.resource}. "
            f"Decision: {decision}. "
            f"Risk: {round(risk, 2)}"
        ),
        severity=(
            "HIGH"
            if decision == "BLOCK"
            else "WARNING"
            if decision == "MFA"
            else "INFO"
        ),
        action=decision
    )

    return ZeroTrustResponse(

        decision=decision,

        risk_score=round(risk, 2),

        identity=(
            "VERIFIED"
            if request.identity_verified
            else "UNVERIFIED"
        ),

        device=(
            "TRUSTED"
            if request.device_trusted
            else "UNTRUSTED"
        ),

        context=request.location,

        reason=reason
    )


# =========================================================
# FIREWALL RULES
# =========================================================

firewall_rules = [
    {
        "id": 1,
        "name": "Block Port Scan",
        "source": "Any",
        "destination": "Internal Network",
        "port": "3389",
        "protocol": "TCP",
        "action": "BLOCK",
        "status": "ACTIVE",
        "priority": 100,
    },
    {
        "id": 2,
        "name": "Allow HTTPS",
        "source": "Any",
        "destination": "Web Server",
        "port": "443",
        "protocol": "TCP",
        "action": "ALLOW",
        "status": "ACTIVE",
        "priority": 50,
    },
    {
        "id": 3,
        "name": "Block Telnet",
        "source": "Any",
        "destination": "Internal Network",
        "port": "23",
        "protocol": "TCP",
        "action": "BLOCK",
        "status": "ACTIVE",
        "priority": 100,
    },
    {
        "id": 4,
        "name": "Allow DNS",
        "source": "Internal Network",
        "destination": "DNS Server",
        "port": "53",
        "protocol": "UDP",
        "action": "ALLOW",
        "status": "ACTIVE",
        "priority": 50,
    },
]


@app.get("/api/firewall/rules")
def get_firewall_rules():
    return sorted(
        firewall_rules,
        key=lambda rule: (-rule.get("priority", 0), rule["id"]),
    )


@app.post("/api/firewall/rules/{rule_id}/toggle")
def toggle_firewall_rule(rule_id: int):
    for rule in firewall_rules:
        if rule["id"] == rule_id:
            rule["status"] = (
                "DISABLED" if rule["status"] == "ACTIVE" else "ACTIVE"
            )
            return rule

    raise HTTPException(status_code=404, detail="Firewall rule not found")


def source_matches(rule_source: str, source_ip: str | None) -> bool:
    """Match Any, an IP address, or a CIDR network.

    Existing descriptive scopes such as 'Internal Network' are retained
    for compatibility. Configure them as real CIDRs before relying on them
    for production source-network restrictions.
    """
    if rule_source.strip().lower() == "any":
        return True

    try:
        network = ipaddress.ip_network(rule_source, strict=False)
    except ValueError:
        # Legacy descriptive labels are not actual IP access controls.
        return True

    if not source_ip:
        return False

    return ipaddress.ip_address(source_ip) in network



# TEMPORARY IP BLOCKING AND RATE LIMITING
# Simulation only. This does not modify the operating system firewall.


_protection_lock = RLock()
_temporary_blocks = {}
_rate_events = defaultdict(deque)

PROTECTION_CONFIG = {
    "rate_limit_requests": 20,
    "rate_limit_window_seconds": 60,
    "temporary_block_seconds": 300,
}


def _valid_source_ip(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=422,
            detail="source_ip must be a valid IPv4 or IPv6 address",
        )


def _expire_old_blocks(now=None):
    now = time.time() if now is None else now
    expired = [
        ip for ip, item in _temporary_blocks.items()
        if item["expires_at_epoch"] <= now
    ]
    for ip in expired:
        del _temporary_blocks[ip]
    return expired


def _block_response(source_ip, item):
    return {
        "source_ip": source_ip,
        "reason": item["reason"],
        "created_at": item["created_at"],
        "expires_at": item["expires_at"],
        "remaining_seconds": max(
            0, int(item["expires_at_epoch"] - time.time())
        ),
        "simulation_mode": True,
    }


@app.get("/api/firewall/protection/config")
def get_firewall_protection_config():
    return {
        **PROTECTION_CONFIG,
        "temporary_blocking_enabled": True,
        "rate_limiting_enabled": True,
        "simulation_mode": True,
    }


@app.get("/api/firewall/blocks")
def get_temporary_blocks():
    with _protection_lock:
        _expire_old_blocks()
        return {
            "blocks": [
                _block_response(ip, item)
                for ip, item in sorted(_temporary_blocks.items())
            ],
            "count": len(_temporary_blocks),
            "simulation_mode": True,
        }


@app.post("/api/firewall/blocks")
def create_temporary_block(
    source_ip: str,
    duration_seconds: int = 300,
    reason: str = "Manual temporary block",
    db: Session = Depends(get_db),
):
    source_ip = _valid_source_ip(source_ip)
    if not 1 <= duration_seconds <= 86400:
        raise HTTPException(
            status_code=422,
            detail="duration_seconds must be between 1 and 86400",
        )

    now = time.time()
    expires = now + duration_seconds
    item = {
        "reason": reason[:200],
        "created_at": datetime.fromtimestamp(
            now, timezone.utc
        ).isoformat(),
        "expires_at": datetime.fromtimestamp(
            expires, timezone.utc
        ).isoformat(),
        "expires_at_epoch": expires,
    }

    with _protection_lock:
        _temporary_blocks[source_ip] = item
        _rate_events.pop(source_ip, None)

    create_audit_log(
        db,
        event_type="TEMPORARY_IP_BLOCK",
        message=f"Temporary block created for {source_ip}; "
                f"duration={duration_seconds}s; reason={item['reason']}",
        severity="WARNING",
        source_ip=source_ip,
        action="BLOCK",
    )

    return {
        "status": "blocked",
        **_block_response(source_ip, item),
    }


@app.post("/api/firewall/blocks/release")
def release_temporary_block(
    source_ip: str,
    db: Session = Depends(get_db),
):
    source_ip = _valid_source_ip(source_ip)
    with _protection_lock:
        existed = _temporary_blocks.pop(source_ip, None) is not None

    if not existed:
        raise HTTPException(
            status_code=404,
            detail="No active temporary block found for this IP",
        )

    create_audit_log(
        db,
        event_type="TEMPORARY_IP_UNBLOCK",
        message=f"Temporary block manually released for {source_ip}",
        severity="INFO",
        source_ip=source_ip,
        action="RELEASE",
    )
    return {
        "status": "released",
        "source_ip": source_ip,
        "simulation_mode": True,
    }


@app.post("/api/firewall/evaluate")
def evaluate_firewall(
    port: int,
    protocol: str = "TCP",
    source_ip: str | None = None,
    db: Session = Depends(get_db),
):
    if not 1 <= port <= 65535:
        raise HTTPException(
            status_code=422,
            detail="Port must be between 1 and 65535",
        )

    protocol = protocol.strip().upper()
    if protocol not in {"TCP", "UDP"}:
        raise HTTPException(
            status_code=422,
            detail="Protocol must be TCP or UDP",
        )

    if source_ip:
        source_ip = _valid_source_ip(source_ip)

    now = time.time()
    forced_block_reason = None
    block_details = None

    if source_ip:
        with _protection_lock:
            _expire_old_blocks(now)

            existing_block = _temporary_blocks.get(source_ip)
            if existing_block:
                forced_block_reason = "Temporary IP Block"
                block_details = existing_block
            else:
                events = _rate_events[source_ip]
                cutoff = now - PROTECTION_CONFIG["rate_limit_window_seconds"]

                while events and events[0] <= cutoff:
                    events.popleft()

                events.append(now)

                if len(events) > PROTECTION_CONFIG["rate_limit_requests"]:
                    duration = PROTECTION_CONFIG["temporary_block_seconds"]
                    expires = now + duration
                    block_details = {
                        "reason": (
                            f"Rate limit exceeded: more than "
                            f"{PROTECTION_CONFIG['rate_limit_requests']} "
                            f"evaluations in "
                            f"{PROTECTION_CONFIG['rate_limit_window_seconds']}s"
                        ),
                        "created_at": datetime.fromtimestamp(
                            now, timezone.utc
                        ).isoformat(),
                        "expires_at": datetime.fromtimestamp(
                            expires, timezone.utc
                        ).isoformat(),
                        "expires_at_epoch": expires,
                    }
                    _temporary_blocks[source_ip] = block_details
                    _rate_events.pop(source_ip, None)
                    forced_block_reason = "Rate Limit Temporary Block"

    if forced_block_reason:
        action = "BLOCK"
        rule_name = forced_block_reason
        matched = True
        priority = 1000
    else:
        matching_rules = sorted(
            (
                rule for rule in firewall_rules
                if rule["status"] == "ACTIVE"
                and rule["port"] == str(port)
                and rule["protocol"] == protocol
                and source_matches(rule.get("source", "Any"), source_ip)
            ),
            key=lambda rule: (-rule.get("priority", 0), rule["id"]),
        )

        matched = bool(matching_rules)
        rule = matching_rules[0] if matched else None
        action = rule["action"] if rule else "BLOCK"
        rule_name = rule["name"] if rule else "Default Deny Policy"
        priority = rule.get("priority", 0) if rule else 0

    create_audit_log(
        db,
        event_type="FIREWALL_DECISION",
        message=(
            f"Rule={rule_name}; port={port}; protocol={protocol}; "
            f"matched={matched}; action={action}; priority={priority}"
            + (f"; reason={block_details['reason']}" if block_details else "")
        ),
        severity="WARNING" if action == "BLOCK" else "INFO",
        source_ip=source_ip or "",
        action=action,
    )

    return {
        "matched": matched,
        "rule": rule_name,
        "action": action,
        "port": port,
        "protocol": protocol,
        "source_ip": source_ip,
        "priority": priority,
        "temporary_block": bool(forced_block_reason),
        "block_reason": block_details["reason"] if forced_block_reason else None,
        "simulation_mode": True,
    }


# SECURITY AUDIT LOGS
# =========================================================

from models import AuditLog


def create_audit_log(
    db,
    event_type,
    message,
    severity="INFO",
    source_ip="",
    action=""
):

    log = AuditLog(
        event_type=event_type,
        message=message,
        severity=severity,
        source_ip=source_ip,
        action=action
    )

    db.add(log)
    db.commit()

    return log


@app.get("/api/logs")
def get_logs(
    db: Session = Depends(get_db)
):

    return db.query(
        AuditLog
    ).order_by(
        AuditLog.created_at.desc()
    ).limit(100).all()


# =========================================================
# NETWORK MONITOR
# =========================================================

@app.get("/api/network/summary")
def network_summary(
    db: Session = Depends(get_db)
):

    devices = db.query(Device).all()

    online = sum(
        1 for device in devices
        if device.status == "ONLINE"
    )

    offline = sum(
        1 for device in devices
        if device.status != "ONLINE"
    )

    blocked = db.query(Threat).filter(
        Threat.action == "BLOCK"
    ).count()

    threats = db.query(Threat).count()

    return {
        "devices": len(devices),
        "online": online,
        "offline": offline,
        "total_threats": threats,
        "blocked_connections": blocked
    }

@app.get("/api/analytics")
def analytics(db: Session = Depends(get_db)):

    threats = db.query(Threat).all()

    total = len(threats)

    critical = sum(1 for t in threats if t.severity == "CRITICAL")
    high = sum(1 for t in threats if t.severity == "HIGH")
    medium = sum(1 for t in threats if t.severity == "MEDIUM")
    low = sum(1 for t in threats if t.severity == "LOW")

    blocked = sum(1 for t in threats if t.action == "BLOCK")
    mfa = sum(1 for t in threats if t.action == "MFA")
    allowed = sum(1 for t in threats if t.action == "ALLOW")

    average_risk = (
        round(sum(t.risk_score for t in threats) / total, 2)
        if total > 0
        else 0
    )

    average_anomaly = (
        round(sum(t.anomaly_score for t in threats) / total, 2)
        if total > 0
        else 0
    )

    threat_types = {}

    for threat in threats:
        threat_types[threat.threat_type] = (
            threat_types.get(threat.threat_type, 0) + 1
        )

    return {
        "total_threats": total,
        "average_risk": average_risk,
        "average_anomaly": average_anomaly,
        "severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low
        },
        "actions": {
            "blocked": blocked,
            "mfa": mfa,
            "allowed": allowed
        },
        "threat_types": [
            {
                "name": name,
                "count": count
            }
            for name, count in threat_types.items()
        ]
    }


@app.post("/api/assistant")
def security_assistant(question: str, db: Session = Depends(get_db)):

    q = question.lower()

    latest = (
        db.query(Threat)
        .order_by(Threat.created_at.desc())
        .first()
    )

    if latest is None:
        if "risk" in q or "score" in q:
            return {
                "answer": (
                    "The current overall SentinelAI security score is "
                    "100/100 (SECURE). No threats have been recorded, "
                    "so there is no individual threat risk score yet."
                ),
                "threat": None
            }

        if "firewall" in q:
            return {
                "answer": (
                    "The firewall is ACTIVE in AI ADAPTIVE mode. "
                    "Dynamic response and Zero Trust are enabled. "
                    "Simulation mode is active, so actions are simulated "
                    "rather than enforced on real network traffic."
                ),
                "threat": None
            }

        if "zero trust" in q or "zero-trust" in q:
            return {
                "answer": (
                    "Zero Trust is enabled, including continuous "
                    "verification, least privilege, identity verification, "
                    "device trust, and risk-based access."
                ),
                "threat": None
            }

        return {
            "answer": (
                "No security events are available yet. The current "
                "overall security score is 100/100 (SECURE). You can ask "
                "about the risk score, firewall status, or Zero Trust."
            ),
            "threat": None
        }

    if "why" in q and ("blocked" in q or "block" in q):

        answer = (
            f"The latest connection was blocked because SentinelAI "
            f"identified a {latest.threat_type} with a risk score of "
            f"{latest.risk_score}. The AI anomaly score was "
            f"{latest.anomaly_score}, which indicates suspicious traffic. "
            f"The connection targeted port {latest.port} from "
            f"{latest.source_ip}. Based on the risk engine, the threat "
            f"was classified as {latest.severity} and the recommended "
            f"firewall action was {latest.action}."
        )

    elif "risk" in q or "score" in q:

        answer = (
            f"The latest threat has a risk score of {latest.risk_score}/100. "
            f"The AI anomaly score is {latest.anomaly_score}/100. "
            f"The final classification is {latest.severity}. "
            f"SentinelAI therefore selected the {latest.action} action."
        )

    elif "threat" in q or "attack" in q:

        answer = (
            f"The latest detected threat is a {latest.threat_type}. "
            f"Traffic originated from {latest.source_ip} and targeted "
            f"{latest.destination_ip} on port {latest.port} using "
            f"{latest.protocol}. {latest.packets} packets and "
            f"{latest.bytes_transferred} bytes were observed."
        )

    elif "recommend" in q or "recommendation" in q:

        answer = (
            f"Recommended response: keep the source {latest.source_ip} "
            f"blocked, investigate the repeated Port Scan activity, "
            f"review the affected device, and monitor for additional "
            f"attempts. The current risk level is {latest.risk_score}/100."
        )

    else:

        answer = (
            f"Latest SentinelAI event: {latest.threat_type}, "
            f"risk {latest.risk_score}/100, anomaly score "
            f"{latest.anomaly_score}/100, severity {latest.severity}, "
            f"action {latest.action}. "
            f"Ask me why it was blocked, what the risk score means, "
            f"what threat was detected, or what response is recommended."
        )

    return {
        "answer": answer,
        "threat": {
            "id": latest.id,
            "type": latest.threat_type,
            "source_ip": latest.source_ip,
            "destination_ip": latest.destination_ip,
            "port": latest.port,
            "protocol": latest.protocol,
            "anomaly_score": latest.anomaly_score,
            "risk_score": latest.risk_score,
            "severity": latest.severity,
            "action": latest.action
        }
    }



# ============================================================
# SECURITY ANALYTICS
# ============================================================

@app.get("/api/analytics/summary")
def analytics_summary(db: Session = Depends(get_db)):

    threats = db.query(Threat).all()
    total = len(threats)

    blocked = sum(1 for t in threats if t.action == "BLOCK")
    allowed = sum(1 for t in threats if t.action == "ALLOW")
    mfa = sum(1 for t in threats if t.action == "MFA")

    critical = sum(1 for t in threats if t.severity == "CRITICAL")
    high = sum(1 for t in threats if t.severity == "HIGH")
    medium = sum(1 for t in threats if t.severity == "MEDIUM")
    low = sum(1 for t in threats if t.severity == "LOW")

    average_risk = round(
        sum(t.risk_score or 0 for t in threats) / total,
        2
    ) if total else 0

    average_anomaly = round(
        sum(t.anomaly_score or 0 for t in threats) / total,
        2
    ) if total else 0

    threat_types = {}

    for threat in threats:
        threat_types[threat.threat_type] = (
            threat_types.get(threat.threat_type, 0) + 1
        )

    return {
        "total_threats": total,
        "blocked": blocked,
        "allowed": allowed,
        "mfa": mfa,
        "average_risk": average_risk,
        "average_anomaly": average_anomaly,
        "severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low
        },
        "threat_types": threat_types
    }


@app.get("/api/security-score")
def security_score(db: Session = Depends(get_db)):

    threats = db.query(Threat).all()

    if not threats:
        return {
            "score": 100,
            "status": "SECURE"
        }

    average_risk = sum(
        t.risk_score or 0 for t in threats
    ) / len(threats)

    blocked_ratio = sum(
        1 for t in threats if t.action == "BLOCK"
    ) / len(threats)

    score = (
        100
        - (average_risk * 0.6)
        + (blocked_ratio * 20)
    )

    score = round(min(100, max(0, score)), 2)

    if score >= 80:
        status = "SECURE"
    elif score >= 60:
        status = "MODERATE"
    else:
        status = "AT RISK"

    return {
        "score": score,
        "status": status
    }


@app.get("/api/threats/recent")
def recent_threats(
    limit: int = 20,
    db: Session = Depends(get_db)
):

    threats = (
        db.query(Threat)
        .order_by(Threat.created_at.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": t.id,
            "threat_type": t.threat_type,
            "source_ip": t.source_ip,
            "destination_ip": t.destination_ip,
            "port": t.port,
            "protocol": t.protocol,
            "packets": t.packets,
            "bytes_transferred": t.bytes_transferred,
            "anomaly_score": t.anomaly_score,
            "risk_score": t.risk_score,
            "severity": t.severity,
            "action": t.action,
            "status": t.status,
            "created_at": t.created_at
        }
        for t in threats
    ]


@app.get("/api/firewall/status")
def firewall_status(db: Session = Depends(get_db)):

    threats = db.query(Threat).all()

    blocked = [
        t.source_ip
        for t in threats
        if t.action == "BLOCK"
    ]

    return {
        "firewall": "ACTIVE",
        "mode": "AI ADAPTIVE",
        "blocked_connections": len(blocked),
        "blocked_ips": list(set(blocked)),
        "dynamic_response": True,
        "zero_trust": True,
        "simulation_mode": True
    }


@app.get("/api/zero-trust/status")
def zero_trust_status():

    return {
        "enabled": True,
        "continuous_verification": True,
        "least_privilege": True,
        "risk_based_access": True,
        "device_trust": True,
        "identity_verification": True,
        "adaptive_authentication": True,
        "possible_decisions": [
            "ALLOW",
            "MFA",
            "LIMIT",
            "BLOCK"
        ]
    }


# DATASET_LAB_UPLOAD_ROUTE
@app.post("/api/datasets/preview")
async def preview_dataset(file: UploadFile = File(...)):
    """Accept CSV files up to 10 GiB and inspect them in chunks."""
    import os
    import tempfile
    from collections import Counter

    import pandas as pd

    MAX_UPLOAD_BYTES = 10 * 1024 * 1024 * 1024
    COPY_CHUNK_BYTES = 8 * 1024 * 1024
    PARSE_CHUNK_ROWS = 10_000

    filename = file.filename or "dataset.csv"

    if not filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a CSV file.")

    temp_path = None
    total_bytes = 0

    try:
        # Copy the upload to disk in bounded chunks instead of reading
        # the complete file into Python memory.
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".csv", prefix="sentinelai_", delete=False
        ) as temp:
            temp_path = temp.name

            while True:
                part = await file.read(COPY_CHUNK_BYTES)
                if not part:
                    break

                total_bytes += len(part)
                if total_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="Maximum upload size is 10 GiB (10 GB).",
                    )

                temp.write(part)

        print(f"[DatasetLab] Upload received: {filename}, {total_bytes:,} bytes. Starting scan.", flush=True)
        if total_bytes == 0:
            raise HTTPException(status_code=400, detail="The file is empty.")

        row_count = 0
        chunks_processed = 0
        columns = None
        numeric_columns = []
        label_column = None
        preview = []
        label_counts = Counter()

        recognized_labels = {
            "label", "class", "attack", "attack_type", "attack type",
            "category", "target",
        }

        try:
            for frame in pd.read_csv(
                temp_path,
                chunksize=PARSE_CHUNK_ROWS,
                on_bad_lines="error",
            ):
                frame.columns = [str(c).strip() for c in frame.columns]

                if columns is None:
                    columns = list(frame.columns)
                    numeric_columns = [
                        str(c)
                        for c in frame.select_dtypes(include="number").columns
                    ]
                    label_column = next(
                        (c for c in columns if c.lower() in recognized_labels),
                        None,
                    )

                row_count += len(frame)
                chunks_processed += 1
                if chunks_processed % 5 == 0:
                    print(f"[DatasetLab] Scanned {row_count:,} rows.", flush=True)

                # Retain only the first 10 rows for the displayed preview.
                if len(preview) < 10:
                    sample = frame.head(10 - len(preview)).astype(object)
                    sample = sample.where(pd.notna(sample), None)
                    preview.extend(sample.to_dict(orient="records"))

                if label_column:
                    counts = (
                        frame[label_column]
                        .fillna("Unknown")
                        .astype(str)
                        .value_counts()
                        .to_dict()
                    )
                    label_counts.update(counts)

        except (
            pd.errors.EmptyDataError,
            pd.errors.ParserError,
            UnicodeDecodeError,
        ) as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Could not read the CSV: {exc}",
            ) from exc

        if columns is None:
            raise HTTPException(
                status_code=400,
                detail="No tabular data rows found in the CSV.",
            )

        print(f"[DatasetLab] Analysis complete: {row_count:,} rows.", flush=True)
        return {
            "filename": filename,
            "rows": row_count,
            "columns_count": len(columns),
            "columns": columns,
            "numeric_columns": numeric_columns,
            "preview": preview,
            "label_column": label_column,
            "label_distribution": dict(label_counts.most_common(30)),
            "message": (
                "CSV preview complete. Labels come from the dataset and "
                "are not verified live threat detections."
            ),
        }

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        await file.close()


# =========================================================
# OPT-IN DEVICE MONITORING (health telemetry + location)
# Configure DEVICE_MONITOR_TOKEN in Render before use.
# Reports are held in memory and reset when the service restarts.
# =========================================================
import os as _device_monitor_os
import hmac as _device_monitor_hmac
from datetime import datetime as _device_monitor_datetime, timezone as _device_monitor_timezone

_device_monitor_reports: dict[str, dict] = {}


def _device_monitor_authorize(authorization: str | None) -> None:
    expected = _device_monitor_os.getenv("DEVICE_MONITOR_TOKEN", "").strip()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Device monitoring is not configured. Set DEVICE_MONITOR_TOKEN on the backend.",
        )
    supplied = authorization or ""
    wanted = f"Bearer {expected}"
    if not _device_monitor_hmac.compare_digest(supplied, wanted):
        raise HTTPException(status_code=401, detail="Invalid device-monitor token.")


@app.post("/api/device-monitor/report")
def device_monitor_report(
    payload: dict,
    authorization: str | None = Header(default=None),
):
    _device_monitor_authorize(authorization)
    device_id = str(payload.get("device_id", "")).strip()[:120]
    device_name = str(payload.get("device_name", "")).strip()[:160]
    if not device_id or not device_name:
        raise HTTPException(status_code=400, detail="device_id and device_name are required.")

    now = _device_monitor_datetime.now(_device_monitor_timezone.utc).isoformat()
    report = dict(_device_monitor_reports.get(device_id, {}))
    # Keep the location object supplied separately by the consented browser watch.
    report.update(payload)
    report["device_id"] = device_id
    report["device_name"] = device_name
    report["last_seen"] = now
    _device_monitor_reports[device_id] = report
    return {"ok": True, "device_id": device_id, "last_seen": now}


@app.post("/api/device-monitor/location")
def device_monitor_location(
    payload: dict,
    authorization: str | None = Header(default=None),
):
    _device_monitor_authorize(authorization)
    device_id = str(payload.get("device_id", "")).strip()[:120]
    report = _device_monitor_reports.get(device_id)
    if not device_id or report is None:
        raise HTTPException(status_code=404, detail="Start the laptop monitor agent first, then try location sharing again.")

    try:
        latitude = float(payload.get("latitude"))
        longitude = float(payload.get("longitude"))
        accuracy = float(payload.get("accuracy_m", 0))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Valid latitude, longitude, and accuracy are required.")
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
        raise HTTPException(status_code=400, detail="Location coordinates are out of range.")

    now = _device_monitor_datetime.now(_device_monitor_timezone.utc).isoformat()
    report["location"] = {
        "latitude": latitude,
        "longitude": longitude,
        "accuracy_m": max(0, accuracy),
        "updated_at": now,
    }
    return {"ok": True, "location_updated_at": now}


@app.get("/api/device-monitor/latest")
def device_monitor_latest(authorization: str | None = Header(default=None)):
    _device_monitor_authorize(authorization)
    if not _device_monitor_reports:
        return {"device": None, "message": "No laptop agent has reported yet."}
    latest = max(
        _device_monitor_reports.values(),
        key=lambda item: item.get("last_seen", ""),
    )
    return {"device": latest}


# Local system telemetry. Run this backend on the Mac being monitored.
@app.get("/api/live/system")
def live_system_telemetry():
    import psutil
    import platform
    from datetime import datetime, timezone

    try:
        cpu_percent = psutil.cpu_percent(interval=0.2)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        network = psutil.net_io_counters()
        connections = []

        try:
            for conn in psutil.net_connections(kind="inet")[:100]:
                local = conn.laddr
                remote = conn.raddr
                connections.append({
                    "status": conn.status,
                    "local_ip": local.ip if local else None,
                    "local_port": local.port if local else None,
                    "remote_ip": remote.ip if remote else None,
                    "remote_port": remote.port if remote else None,
                    "pid": conn.pid,
                })
            connection_access = "available"
        except (psutil.AccessDenied, OSError):
            connection_access = "permission_limited"

        interfaces = {}
        for name, addresses in psutil.net_if_addrs().items():
            interfaces[name] = [
                {
                    "address": item.address,
                    "family": str(item.family),
                }
                for item in addresses
                if item.family in (2, 10, 30)
            ]

        return {
            "source": "local_machine",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "hostname": platform.node(),
            "platform": platform.platform(),
            "cpu_percent": cpu_percent,
            "memory": {
                "total_bytes": memory.total,
                "used_bytes": memory.used,
                "available_bytes": memory.available,
                "percent": memory.percent,
            },
            "disk": {
                "total_bytes": disk.total,
                "used_bytes": disk.used,
                "free_bytes": disk.free,
                "percent": disk.percent,
            },
            "process_count": len(psutil.pids()),
            "network_io": {
                "bytes_sent": network.bytes_sent,
                "bytes_received": network.bytes_recv,
                "packets_sent": network.packets_sent,
                "packets_received": network.packets_recv,
            },
            "network_interfaces": interfaces,
            "connections": connections,
            "connection_access": connection_access,
            "note": (
                "Live operating-system telemetry, not proof of an attack. "
                "Connection visibility may be limited by macOS permissions."
            ),
        }
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to collect system telemetry: {type(exc).__name__}",
        )
