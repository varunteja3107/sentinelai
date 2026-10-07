from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy.orm import Session

from database import Base, engine, get_db
from models import Threat, Device, Incident
from schemas import ThreatCreate, ThreatResponse, ZeroTrustRequest, ZeroTrustResponse

from ai_engine import ThreatDetectionAI
from risk_engine import calculate_risk


Base.metadata.create_all(bind=engine)


app = FastAPI(



    title="SentinelAI API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

        policy_risk
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


@app.get("/api/incidents")
def get_incidents(
    db: Session = Depends(get_db)
):

    return db.query(
        Incident
    ).order_by(
        Incident.created_at.desc()
    ).all()


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
    db: Session = Depends(get_db)
):

    event = ThreatCreate(

        threat_type="Port Scan",

        source_ip="192.168.1.250",

        destination_ip="192.168.1.10",

        protocol="TCP",

        port=3389,

        packets=950,

        bytes_transferred=85000
    )

    threat = analyze_threat(
        event,
        db
    )

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
        "status": "ACTIVE"
    },
    {
        "id": 2,
        "name": "Allow HTTPS",
        "source": "Any",
        "destination": "Web Server",
        "port": "443",
        "protocol": "TCP",
        "action": "ALLOW",
        "status": "ACTIVE"
    },
    {
        "id": 3,
        "name": "Block Telnet",
        "source": "Any",
        "destination": "Internal Network",
        "port": "23",
        "protocol": "TCP",
        "action": "BLOCK",
        "status": "ACTIVE"
    },
    {
        "id": 4,
        "name": "Allow DNS",
        "source": "Internal Network",
        "destination": "DNS Server",
        "port": "53",
        "protocol": "UDP",
        "action": "ALLOW",
        "status": "ACTIVE"
    }
]


@app.get("/api/firewall/rules")
def get_firewall_rules():

    return firewall_rules


@app.post("/api/firewall/rules/{rule_id}/toggle")
def toggle_firewall_rule(rule_id: int):

    for rule in firewall_rules:

        if rule["id"] == rule_id:

            if rule["status"] == "ACTIVE":
                rule["status"] = "DISABLED"

            else:
                rule["status"] = "ACTIVE"

            return rule

    return {
        "error": "Firewall rule not found"
    }


@app.post("/api/firewall/evaluate")
def evaluate_firewall(
    port: int,
    protocol: str = "TCP"
):

    for rule in firewall_rules:

        if (
            rule["status"] == "ACTIVE"
            and rule["port"] == str(port)
            and rule["protocol"] == protocol
        ):

            return {
                "matched": True,
                "rule": rule["name"],
                "action": rule["action"],
                "port": port,
                "protocol": protocol
            }

    return {
        "matched": False,
        "rule": "Default Policy",
        "action": "ALLOW",
        "port": port,
        "protocol": protocol
    }


# =========================================================
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

    latest = (
        db.query(Threat)
        .order_by(Threat.created_at.desc())
        .first()
    )

    if latest is None:
        return {
            "answer": "No security events are available yet.",
            "threat": None
        }

    q = question.lower()

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
