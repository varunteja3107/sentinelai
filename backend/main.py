import ipaddress
import re
import time
import logging
from network_topology import router as network_topology_router


from dotenv import load_dotenv
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Security
from schemas import LoginRequest, LoginResponse, AdminCreateRequest
import os
import hashlib
import secrets
from auth import verify_password, hash_password, create_access_token, verify_access_token
from schemas import ResponseActionReview
from schemas import (
    ThreatCreate,
    ThreatResponse,
    ZeroTrustRequest,
    ZeroTrustResponse,
    ResponsePlaybookRequest,
    ResponseActionCreate,
    ResponseActionReview,
    ResponseActionRollback,
    LoginRequest,
    LoginResponse,
)
from collections import defaultdict, deque
from threading import RLock
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, Header
from pydantic import BaseModel, Field
from typing import Optional
from fastapi.middleware.cors import CORSMiddleware
from io import BytesIO

from sqlalchemy import inspect
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from database import Base, engine, get_db, SessionLocal
from models import Threat, Device, Incident, ResponseAction, RevokedToken, UserSession, SessionEvent, FirewallRule, AuditLog, BlockSpikeAlert, DeviceAgent, DeviceTelemetry, AdminUser, DeviceAssessment, DeviceAlert, DeviceCredential, SentinelXDriftEvent, SentinelXDetectorState
from device_intelligence_service import assess_and_persist
from schemas import ThreatCreate, ThreatResponse, ZeroTrustRequest, ZeroTrustResponse, ResponsePlaybookRequest, ResponseActionCreate, ResponseActionReview, ResponseActionRollback

from ai_engine import ThreatDetectionAI
from copilot_engine import run_copilot
from risk_engine import calculate_risk
from threat_explanations import explain_detection
load_dotenv()
logger = logging.getLogger("sentinelai.api")

security = HTTPBearer(auto_error=False)


def get_current_admin(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = verify_access_token(credentials.credentials)
    except (ValueError, RuntimeError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_hash = hashlib.sha256(
        credentials.credentials.encode("utf-8")
    ).hexdigest()

    db = SessionLocal()
    try:
        revoked = (
            db.query(RevokedToken)
            .filter(RevokedToken.token_hash == token_hash)
            .first()
        )
    except SQLAlchemyError:
        raise HTTPException(
            status_code=503,
            detail="Authentication service temporarily unavailable",
        )
    finally:
        db.close()

    if revoked is not None:
        raise HTTPException(
            status_code=401,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Administrator access required",
        )

    # The environment-configured primary admin remains valid.
    primary_username = os.getenv("SENTINELAI_ADMIN_USERNAME", "").strip()
    token_username = payload.get("sub", "")

    if not (
        primary_username
        and hmac.compare_digest(token_username, primary_username)
    ):
        db = SessionLocal()
        try:
            account = (
                db.query(AdminUser)
                .filter(AdminUser.username == token_username)
                .first()
            )
            if account is None or not account.is_active:
                raise HTTPException(
                    status_code=401,
                    detail="Administrator account is inactive or unavailable",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        except SQLAlchemyError:
            raise HTTPException(
                status_code=503,
                detail="Authentication service temporarily unavailable",
            )
        finally:
            db.close()

    return payload

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
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5181,http://127.0.0.1:5181",
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

import hmac



# =========================================================
# SENTINELAI-X: ADMIN-MANAGED DEVICE CREDENTIALS
# =========================================================

@app.post("/api/x/devices/register", status_code=201)
def register_sentinel_x_device(
    payload: dict,
    current_admin: dict = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    device_id = str(payload.get("device_id", "")).strip()
    device_name = str(payload.get("device_name", "")).strip()

    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,120}", device_id):
        raise HTTPException(status_code=422, detail="Invalid device_id.")

    if not device_name or len(device_name) > 160:
        raise HTTPException(status_code=422, detail="device_name is required (maximum 160 characters).")

    platform_name = str(payload.get("platform") or "Unknown").strip()[:80]
    os_version = str(payload.get("os_version") or "").strip()[:120]

    try:
        credential = (
            db.query(DeviceCredential)
            .filter(DeviceCredential.device_id == device_id)
            .first()
        )

        if credential is not None and credential.is_active:
            raise HTTPException(
                status_code=409,
                detail="An active credential already exists for this device.",
            )

        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = datetime.utcnow()

        if credential is None:
            credential = DeviceCredential(
                device_id=device_id,
                token_hash=token_hash,
                is_active=True,
                created_at=now,
                last_used_at=None,
                revoked_at=None,
            )
            db.add(credential)
        else:
            credential.token_hash = token_hash
            credential.is_active = True
            credential.created_at = now
            credential.last_used_at = None
            credential.revoked_at = None

        agent = (
            db.query(DeviceAgent)
            .filter(DeviceAgent.device_id == device_id)
            .first()
        )

        if agent is None:
            agent = DeviceAgent(
                device_id=device_id,
                device_name=device_name,
                first_seen=now,
            )
            db.add(agent)

        agent.device_name = device_name
        agent.platform = platform_name
        agent.os_version = os_version

        db.commit()

        return {
            "ok": True,
            "device_id": device_id,
            "device_name": device_name,
            "token": token,
            "message": "Save this token securely. It will not be shown again.",
        }

    except HTTPException:
        db.rollback()
        raise
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Device registration conflict.")
    except Exception:
        db.rollback()
        logger.exception("SentinelAI-X device registration failed")
        raise HTTPException(status_code=500, detail="Device registration failed.")


@app.get("/api/x/devices/credentials")
def list_sentinel_x_device_credentials(
    current_admin: dict = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    records = (
        db.query(DeviceCredential)
        .order_by(DeviceCredential.created_at.desc())
        .all()
    )

    return {
        "devices": [
            {
                "device_id": item.device_id,
                "active": item.is_active,
                "created_at": item.created_at.isoformat() if item.created_at else None,
                "last_used_at": item.last_used_at.isoformat() if item.last_used_at else None,
                "revoked_at": item.revoked_at.isoformat() if item.revoked_at else None,
            }
            for item in records
        ],
        "count": len(records),
    }


@app.post("/api/x/devices/{device_id}/revoke")
def revoke_sentinel_x_device_credential(
    device_id: str,
    current_admin: dict = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    credential = (
        db.query(DeviceCredential)
        .filter(DeviceCredential.device_id == device_id)
        .first()
    )

    if credential is None:
        raise HTTPException(status_code=404, detail="Device credential not found.")

    if credential.is_active:
        credential.is_active = False
        credential.revoked_at = datetime.utcnow()
        db.commit()

    return {
        "ok": True,
        "device_id": device_id,
        "active": False,
        "message": "Device credential revoked.",
    }


@app.post("/api/auth/login", response_model=LoginResponse)
def admin_login(payload: LoginRequest):
    admin_username = os.getenv("SENTINELAI_ADMIN_USERNAME", "").strip()
    admin_password_hash = os.getenv(
        "SENTINELAI_ADMIN_PASSWORD_HASH", ""
    ).strip()

    authenticated_username = None

    # Preserve the existing environment-configured primary admin.
    if admin_username and hmac.compare_digest(
        payload.username, admin_username
    ):
        if admin_password_hash and verify_password(
            payload.password, admin_password_hash
        ):
            authenticated_username = admin_username
        else:
            raise HTTPException(
                status_code=401,
                detail="Invalid username or password",
            )
    else:
        # Check additional database-backed administrator accounts.
        db = SessionLocal()
        try:
            account = (
                db.query(AdminUser)
                .filter(AdminUser.username == payload.username)
                .first()
            )

            if (
                account is None
                or not account.is_active
                or not verify_password(
                    payload.password, account.password_hash
                )
            ):
                raise HTTPException(
                    status_code=401,
                    detail="Invalid username or password",
                )

            authenticated_username = account.username

        except SQLAlchemyError:
            raise HTTPException(
                status_code=503,
                detail="Authentication service temporarily unavailable",
            )
        finally:
            db.close()

    try:
        token = create_access_token(authenticated_username)
    except RuntimeError:
        raise HTTPException(
            status_code=503,
            detail="Token secret is not configured",
        )

    return LoginResponse(
        access_token=token,
        expires_in=1800,
        username=authenticated_username,
        role="admin",
    )


@app.post("/api/auth/admins", status_code=201)
def create_admin_account(
    payload: AdminCreateRequest,
    current_admin: dict = Depends(get_current_admin),
):
    username = payload.username.strip()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,128}", username):
        raise HTTPException(
            status_code=422,
            detail="Username may contain only letters, numbers, dots, underscores and hyphens",
        )

    try:
        password_hash = hash_password(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    db = SessionLocal()
    try:
        existing = (
            db.query(AdminUser)
            .filter(AdminUser.username == username)
            .first()
        )

        if existing is not None:
            raise HTTPException(
                status_code=409,
                detail="An administrator with this username already exists",
            )

        account = AdminUser(
            username=username,
            password_hash=password_hash,
            role="admin",
            is_active=True,
            created_by=current_admin.get("sub", "admin"),
        )

        db.add(account)
        db.commit()
        db.refresh(account)

        return {
            "id": account.id,
            "username": account.username,
            "role": account.role,
            "is_active": account.is_active,
            "created_by": account.created_by,
            "created_at": account.created_at,
        }

    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="An administrator with this username already exists",
        )
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail="Could not create administrator account",
        )
    finally:
        db.close()


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

    # Obtain the full model output while preserving the existing risk policy.
    model_result = ai.analyze_detailed(
        packets=event.packets,
        bytes_transferred=event.bytes_transferred,
        port=event.port,
        failed_attempts=failed_attempts,
    )
    anomaly_score = model_result["anomaly_score"]

    # Port 0 is treated as unknown, matching the existing request schema default.
    explanation = explain_detection(
        packets=event.packets,
        bytes_transferred=event.bytes_transferred,
        port=event.port,
        failed_attempts=failed_attempts,
        threat_type=model_result["threat_type"],
        anomaly_score=anomaly_score,
        confidence=model_result["confidence"],
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


    # Expose explanation in this response without adding a database column.
    threat.explanation = explanation
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


@app.post("/api/response/playbook")
def get_response_playbook(payload: ResponsePlaybookRequest):
    from response_playbooks import recommend_response

    try:
        return recommend_response(
            threat_type=payload.threat_type,
            severity=payload.severity,
            risk_score=payload.risk_score,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


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
    original_risk = float(request.risk_score)

    device_adjustment = 0
    location_adjustment = 0
    network_adjustment = 0
    compliance_adjustment = 0
    posture_adjustment = round((100 - request.device_posture_score) * 0.25)
    failed_login_adjustment = min(request.failed_login_attempts * 3, 15)
    behavior_adjustment = 20 if request.unusual_activity else 0
    session_adjustment = (
        10 if request.session_age_minutes >= 1440
        else 5 if request.session_age_minutes >= 480
        else 0
    )
    resource_adjustment = {
        "LOW": 0,
        "NORMAL": 0,
        "HIGH": 5,
        "CRITICAL": 10,
    }[request.resource_sensitivity]

    if not request.device_trusted:
        device_adjustment = 25

    if request.location.strip().lower() in {
        "unknown",
        "untrusted",
        "foreign",
    }:
        location_adjustment = 15

    if not request.network_trusted:
        network_adjustment = 15

    if not request.device_compliant:
        compliance_adjustment = 15

    total_adjustment = (
        device_adjustment
        + location_adjustment
        + network_adjustment
        + compliance_adjustment
        + posture_adjustment
        + failed_login_adjustment
        + behavior_adjustment
        + session_adjustment
        + resource_adjustment
    )

    if not request.identity_verified:
        final_risk = 100
        decision = "BLOCK"
        reason = "Identity verification failed. Access denied."
        threshold = "Unverified identity: immediate block"
        identity = "UNVERIFIED"
        device = "UNKNOWN"
        context = "DENIED"
    else:
        final_risk = min(
            100,
            original_risk + total_adjustment
        )

        identity = "VERIFIED"
        device = "TRUSTED" if request.device_trusted else "UNTRUSTED"
        context = request.location

        if final_risk >= 80:
            decision = "BLOCK"
            threshold = "Critical risk: 80-100"
            reason = (
                "Critical risk detected. Access denied; "
                "a security incident is recommended."
            )
        elif final_risk >= 60:
            decision = "BLOCK"
            threshold = "High risk: 60-79.99"
            reason = (
                "High risk detected. Zero Trust policy requires "
                "access denial."
            )
        elif location_adjustment > 0 and final_risk < 60:
            decision = "MFA"
            threshold = "Flagged location: MFA required"
            reason = (
                "The location is flagged as untrusted. "
                "Additional authentication is required."
            )
        elif final_risk >= 30:
            decision = "MFA"
            threshold = "Medium risk: 30-59.99"
            reason = (
                "Medium risk detected. Additional authentication "
                "is required."
            )
        else:
            decision = "ALLOW"
            threshold = "Low risk: 0-29.99"
            reason = (
                "Low risk. Identity and device posture meet "
                "the configured policy."
            )

    final_risk = round(final_risk, 2)

    risk_breakdown = {
        "original_score": round(original_risk, 2),
        "device_adjustment": device_adjustment,
        "location_adjustment": location_adjustment,
        "network_adjustment": network_adjustment,
        "compliance_adjustment": compliance_adjustment,
        "posture_adjustment": posture_adjustment,
        "device_posture_score": request.device_posture_score,
        "failed_login_adjustment": failed_login_adjustment,
        "behavior_adjustment": behavior_adjustment,
        "session_adjustment": session_adjustment,
        "resource_adjustment": resource_adjustment,
        "total_adjustment": total_adjustment,
        "network_trusted": request.network_trusted,
        "device_compliant": request.device_compliant,
        "failed_login_attempts": request.failed_login_attempts,
        "unusual_activity": request.unusual_activity,
        "session_age_minutes": request.session_age_minutes,
        "resource_sensitivity": request.resource_sensitivity,
        "final_score": final_risk,
        "identity_verified": request.identity_verified,
        "device_trusted": request.device_trusted,
        "location_flagged": location_adjustment > 0,
        "score_cap": 100,
    }

    create_audit_log(
        db=db,
        event_type="ZERO_TRUST",
        message=(
            f"User {request.user} requested {request.resource}. "
            f"Decision: {decision}. Risk: {final_risk}. "
            f"Policy: {threshold}."
        ),
        severity=(
            "HIGH" if decision == "BLOCK"
            else "WARNING" if decision == "MFA"
            else "INFO"
        ),
        action=decision,
    )

    return ZeroTrustResponse(
        decision=decision,
        risk_score=final_risk,
        identity=identity,
        device=device,
        context=context,
        reason=reason,
        risk_breakdown=risk_breakdown,
        policy_threshold=threshold,
    )


# =========================================================


# =========================================================
# PERSISTENT ZERO TRUST SESSION MANAGEMENT
# =========================================================

@app.post("/api/sessions", status_code=201)
def create_user_session(
    request: ZeroTrustRequest,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    result = zero_trust_check(request, db)

    record = UserSession(
        user=request.user,
        device=request.device,
        resource=request.resource,
        location=request.location,
        risk_score=result.risk_score,
        decision=result.decision,
        identity_verified=int(request.identity_verified),
        device_trusted=int(request.device_trusted),
        network_trusted=int(request.network_trusted),
        device_compliant=int(request.device_compliant),
        device_posture_score=request.device_posture_score,
        failed_login_attempts=request.failed_login_attempts,
        unusual_activity=int(request.unusual_activity),
        session_age_minutes=request.session_age_minutes,
        resource_sensitivity=request.resource_sensitivity,
        status="ACTIVE",
    )

    db.add(record)
    db.flush()

    db.add(SessionEvent(
        session_id=record.id,
        event_type="SESSION_CREATED",
        message=f"Session created for {request.user}",
        risk_score=result.risk_score,
        decision=result.decision,
    ))

    db.commit()
    db.refresh(record)

    return {
        "message": "Session registered",
        "session": serialize_user_session(record),
    }


def serialize_user_session(record):
    return {
        "id": record.id,
        "user": record.user,
        "device": record.device,
        "resource": record.resource,
        "location": record.location,
        "risk": record.risk_score,
        "decision": record.decision,
        "status": record.status,
        "age": record.session_age_minutes,
        "created_at": (
            record.created_at.isoformat()
            if record.created_at else None
        ),
        "updated_at": (
            record.updated_at.isoformat()
            if record.updated_at else None
        ),
    }


@app.get("/api/sessions")
def list_user_sessions(
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    query = db.query(UserSession)

    if status:
        normalized = status.strip().upper()
        if normalized not in {"ACTIVE", "TERMINATED"}:
            raise HTTPException(
                status_code=400,
                detail="Status must be ACTIVE or TERMINATED",
            )
        query = query.filter(UserSession.status == normalized)

    records = query.order_by(UserSession.created_at.desc()).limit(200).all()

    return {
        "count": len(records),
        "sessions": [serialize_user_session(item) for item in records],
    }


@app.post("/api/sessions/{session_id}/reassess")
def reassess_user_session(
    session_id: int,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    record = db.query(UserSession).filter(
        UserSession.id == session_id
    ).first()

    if record is None:
        raise HTTPException(status_code=404, detail="Session not found")

    if record.status != "ACTIVE":
        raise HTTPException(status_code=409, detail="Session is terminated")

    request = ZeroTrustRequest(
        user=record.user,
        device=record.device,
        resource=record.resource,
        location=record.location,
        risk_score=record.risk_score,
        identity_verified=bool(record.identity_verified),
        device_trusted=bool(record.device_trusted),
        network_trusted=bool(record.network_trusted),
        device_compliant=bool(record.device_compliant),
        device_posture_score=record.device_posture_score,
        failed_login_attempts=record.failed_login_attempts,
        unusual_activity=bool(record.unusual_activity),
        session_age_minutes=record.session_age_minutes,
        resource_sensitivity=record.resource_sensitivity,
    )

    result = zero_trust_check(request, db)

    record.risk_score = result.risk_score
    record.decision = result.decision
    record.updated_at = datetime.utcnow()

    db.add(SessionEvent(
        session_id=record.id,
        event_type="SESSION_REASSESSED",
        message=f"Session reassessed: {result.decision}",
        risk_score=result.risk_score,
        decision=result.decision,
    ))

    db.commit()
    db.refresh(record)

    return {
        "message": "Session risk reassessed",
        "session": serialize_user_session(record),
        "risk_breakdown": result.risk_breakdown,
        "reason": result.reason,
    }


@app.post("/api/sessions/{session_id}/terminate")
def terminate_user_session(
    session_id: int,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    record = db.query(UserSession).filter(
        UserSession.id == session_id
    ).first()

    if record is None:
        raise HTTPException(status_code=404, detail="Session not found")

    if record.status == "TERMINATED":
        raise HTTPException(status_code=409, detail="Session already terminated")

    record.status = "TERMINATED"
    record.updated_at = datetime.utcnow()

    db.add(SessionEvent(
        session_id=record.id,
        event_type="SESSION_TERMINATED",
        message=f"Session terminated for {record.user}",
        risk_score=record.risk_score,
        decision="TERMINATED",
    ))

    db.commit()
    db.refresh(record)

    return {
        "message": "Session marked as terminated",
        "session": serialize_user_session(record),
    }


@app.get("/api/sessions/events")
def list_session_events(
    session_id: Optional[int] = None,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    query = db.query(SessionEvent)

    if session_id is not None:
        query = query.filter(SessionEvent.session_id == session_id)

    events = query.order_by(
        SessionEvent.created_at.desc()
    ).limit(200).all()

    return {
        "count": len(events),
        "events": [
            {
                "id": event.id,
                "session_id": event.session_id,
                "event_type": event.event_type,
                "message": event.message,
                "risk_score": event.risk_score,
                "decision": event.decision,
                "created_at": (
                    event.created_at.isoformat()
                    if event.created_at else None
                ),
            }
            for event in events
        ],
    }





# CUSTOM FIREWALL RULE MANAGEMENT
# Database-backed rules created through the Firewall Rule Builder.

class FirewallRuleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    source: str = Field(default="Any", max_length=128)
    destination: str = Field(default="Any", max_length=128)
    port: str = Field(min_length=1, max_length=32)
    protocol: str = Field(default="TCP", max_length=16)
    action: str = Field(default="BLOCK", max_length=16)
    priority: int = Field(default=50, ge=1, le=1000)
    description: str = Field(default="", max_length=500)


class FirewallRuleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=128)
    source: Optional[str] = Field(default=None, max_length=128)
    destination: Optional[str] = Field(default=None, max_length=128)
    port: Optional[str] = Field(default=None, max_length=32)
    protocol: Optional[str] = Field(default=None, max_length=16)
    action: Optional[str] = Field(default=None, max_length=16)
    priority: Optional[int] = Field(default=None, ge=1, le=1000)
    description: Optional[str] = Field(default=None, max_length=500)


def serialize_custom_firewall_rule(rule):
    return {
        "id": rule.id,
        "name": rule.name,
        "source": rule.source,
        "destination": rule.destination,
        "port": rule.port,
        "protocol": rule.protocol,
        "action": rule.action,
        "status": rule.status,
        "priority": rule.priority,
        "description": rule.description or "",
        "custom": True,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
    }


def validate_firewall_rule_values(values):
    protocol = str(values.get("protocol", "TCP")).strip().upper()
    action = str(values.get("action", "BLOCK")).strip().upper()
    port = str(values.get("port", "")).strip()
    source_ip = str(values.get("source", "Any")).strip()
    destination_ip = str(values.get("destination", "Any")).strip()

    if protocol not in {"TCP", "UDP", "ICMP", "ANY"}:
        raise HTTPException(status_code=422, detail="Protocol must be TCP, UDP, ICMP or ANY.")

    if action not in {"ALLOW", "BLOCK", "MONITOR"}:
        raise HTTPException(status_code=422, detail="Action must be ALLOW, BLOCK or MONITOR.")

    if protocol == "ICMP" and port != "*":
        raise HTTPException(status_code=422, detail="ICMP rules must use * for the port.")

    if port != "*":
        parts = port.split("-")
        try:
            if len(parts) == 1:
                first = last = int(parts[0])
            elif len(parts) == 2:
                first, last = int(parts[0]), int(parts[1])
            else:
                raise ValueError

            if not (1 <= first <= last <= 65535):
                raise ValueError
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail="Port must be *, a number from 1 to 65535, or a valid range such as 8000-8100.",
            )

    for field_name, value in (("Source", source_ip), ("Destination", destination_ip)):
        if value.lower() != "any":
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError:
                raise HTTPException(
                    status_code=422,
                    detail=f"{field_name} must be Any, an IP address or a CIDR range.",
                )

    values["protocol"] = protocol
    values["action"] = action
    values["port"] = port
    values["source"] = source_ip
    values["destination"] = destination_ip


@app.post("/api/firewall/rules")
def create_custom_firewall_rule(
    payload: FirewallRuleCreate,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    values = payload.model_dump()
    validate_firewall_rule_values(values)

    rule = FirewallRule(
        **values,
        status="ACTIVE",
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return serialize_custom_firewall_rule(rule)


@app.put("/api/firewall/rules/{rule_id}")
def update_custom_firewall_rule(
    rule_id: int,
    payload: FirewallRuleUpdate,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Custom firewall rule not found.")

    values = payload.model_dump(exclude_unset=True)
    validate_firewall_rule_values({
        "source": values.get("source", rule.source),
        "destination": values.get("destination", rule.destination),
        "port": values.get("port", rule.port),
        "protocol": values.get("protocol", rule.protocol),
        "action": values.get("action", rule.action),
    })

    for key, value in values.items():
        if value is not None:
            setattr(rule, key, value)

    rule.protocol = rule.protocol.upper()
    rule.action = rule.action.upper()
    rule.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(rule)
    return serialize_custom_firewall_rule(rule)


@app.post("/api/firewall/rules/{rule_id}/status")
def set_custom_firewall_rule_status(
    rule_id: int,
    enabled: bool,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Custom firewall rule not found.")

    rule.status = "ACTIVE" if enabled else "DISABLED"
    rule.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(rule)
    return serialize_custom_firewall_rule(rule)


@app.delete("/api/firewall/rules/{rule_id}")
def delete_custom_firewall_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Custom firewall rule not found.")

    db.delete(rule)
    db.commit()
    return {"message": "Custom firewall rule deleted.", "id": rule_id}


# FIREWALL RULES
# =========================================================

firewall_rules = [
    {
        "id": -1,
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
        "id": -2,
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
        "id": -3,
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
        "id": -4,
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



# FIREWALL RULE CONFLICT DETECTION
# Compares default and custom rules without changing enforcement.

def _conflict_source_overlap(source_a, source_b):
    import ipaddress

    a = str(source_a or "Any").strip()
    b = str(source_b or "Any").strip()

    if a.lower() == "any" or b.lower() == "any":
        return True, False

    try:
        net_a = ipaddress.ip_network(a, strict=False)
        net_b = ipaddress.ip_network(b, strict=False)

        if net_a.version != net_b.version:
            return False, False

        return net_a.overlaps(net_b), False
    except ValueError:
        # Legacy labels such as "Internal Network" are not CIDRs.
        # Conservatively report possible overlap, not confirmed overlap.
        return True, True


def _conflict_port_overlap(port_a, port_b):
    a = str(port_a or "*").strip()
    b = str(port_b or "*").strip()
    return a == "*" or b == "*" or a == b


def _conflict_protocol_overlap(protocol_a, protocol_b):
    a = str(protocol_a or "TCP").upper()
    b = str(protocol_b or "TCP").upper()
    return a == "ANY" or b == "ANY" or a == b


def _conflict_rule_view(rule):
    return {
        "id": rule.get("id"),
        "name": rule.get("name"),
        "source": rule.get("source", "Any"),
        "destination": rule.get("destination", "Any"),
        "port": str(rule.get("port", "*")),
        "protocol": str(rule.get("protocol", "TCP")).upper(),
        "action": str(rule.get("action", "BLOCK")).upper(),
        "status": str(rule.get("status", "ACTIVE")).upper(),
        "priority": int(rule.get("priority", 0)),
        "custom": bool(rule.get("custom", False)),
    }


@app.get("/api/firewall/rules/conflicts")
def firewall_rule_conflicts(
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    custom_rules = db.query(FirewallRule).all()

    all_rules = [
        _conflict_rule_view({**rule, "custom": False})
        for rule in firewall_rules
    ]

    all_rules.extend(
        _conflict_rule_view(serialize_custom_firewall_rule(rule))
        for rule in custom_rules
    )

    active_rules = [
        rule for rule in all_rules if rule["status"] == "ACTIVE"
    ]

    findings = []

    for index, first in enumerate(active_rules):
        for second in active_rules[index + 1:]:
            source_overlap, uncertain_source = _conflict_source_overlap(
                first["source"], second["source"]
            )

            if not source_overlap:
                continue

            if not _conflict_port_overlap(first["port"], second["port"]):
                continue

            if not _conflict_protocol_overlap(
                first["protocol"], second["protocol"]
            ):
                continue

            same_action = first["action"] == second["action"]

            exact_match = (
                first["source"].strip().lower()
                == second["source"].strip().lower()
                and first["port"] == second["port"]
                and first["protocol"] == second["protocol"]
            )

            if same_action and exact_match:
                conflict_type = "DUPLICATE"
                severity = "LOW"
                message = "Rules have identical matching conditions and actions."
            elif not same_action:
                conflict_type = "ACTION_CONFLICT"
                severity = "HIGH"
                message = (
                    f"Overlapping rules use different actions: "
                    f"{first['action']} and {second['action']}."
                )
            else:
                conflict_type = "OVERLAP"
                severity = "MEDIUM"
                message = "Rules overlap and may both match the same traffic."

            if uncertain_source:
                severity = "MEDIUM" if severity == "LOW" else severity
                message += (
                    " Source scope uses a descriptive label, so overlap "
                    "is conservative and requires manual verification."
                )

            destination_note = None
            if first["destination"] != second["destination"]:
                destination_note = (
                    "Destination values differ, but destination matching "
                    "is not currently enforced by the traffic evaluator."
                )

            findings.append({
                "type": conflict_type,
                "severity": severity,
                "message": message,
                "rule_a": first,
                "rule_b": second,
                "same_priority": first["priority"] == second["priority"],
                "destination_note": destination_note,
                "source_overlap_uncertain": uncertain_source,
            })

    return {
        "total_rules": len(all_rules),
        "active_rules": len(active_rules),
        "disabled_rules": len(all_rules) - len(active_rules),
        "conflict_count": len(findings),
        "high_severity": sum(
            item["severity"] == "HIGH" for item in findings
        ),
        "medium_severity": sum(
            item["severity"] == "MEDIUM" for item in findings
        ),
        "low_severity": sum(
            item["severity"] == "LOW" for item in findings
        ),
        "conflicts": findings,
        "simulation_only": True,
    }


@app.get("/api/firewall/rules")
def get_firewall_rules(db: Session = Depends(get_db)):
    custom_rules = db.query(FirewallRule).all()

    default_rules = [
        {**rule, "custom": False}
        for rule in firewall_rules
    ]

    persistent_rules = [
        serialize_custom_firewall_rule(rule)
        for rule in custom_rules
    ]

    return sorted(
        default_rules + persistent_rules,
        key=lambda rule: (
            -int(rule.get("priority", 0)),
            int(rule["id"]) + (1000000 if rule.get("custom") else 0),
        ),
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


def ip_scope_matches(rule_scope: str, address: str | None) -> bool:
    """Match Any, an IP address, or a CIDR network."""
    scope = str(rule_scope or "Any").strip()

    if scope.lower() == "any":
        return True

    try:
        network = ipaddress.ip_network(scope, strict=False)
    except ValueError:
        # Preserve legacy descriptive scopes for existing default rules.
        return True

    if not address:
        return False

    try:
        candidate = ipaddress.ip_address(address)
    except ValueError:
        return False

    return candidate.version == network.version and candidate in network


def source_matches(rule_source: str, source_ip: str | None) -> bool:
    """Backward-compatible source matching."""
    return ip_scope_matches(rule_source, source_ip)


def destination_matches(rule_destination: str, destination_ip: str | None) -> bool:
    """Match a destination IP/CIDR or a legacy descriptive scope."""
    return ip_scope_matches(rule_destination, destination_ip)


def port_matches(rule_port: str, traffic_port: int | None) -> bool:
    """Match wildcard, exact port, or inclusive port range."""
    pattern = str(rule_port or "").strip()

    if pattern == "*":
        return True

    if traffic_port is None:
        return False

    try:
        candidate = int(traffic_port)
        parts = pattern.split("-")

        if len(parts) == 1:
            first = last = int(parts[0])
        elif len(parts) == 2:
            first, last = int(parts[0]), int(parts[1])
        else:
            return False

        return 1 <= first <= last <= 65535 and first <= candidate <= last
    except (TypeError, ValueError):
        return False


def protocol_matches(rule_protocol: str, traffic_protocol: str) -> bool:
    """Match a specific protocol or ANY."""
    expected = str(rule_protocol or "TCP").strip().upper()
    actual = str(traffic_protocol or "").strip().upper()
    return expected == "ANY" or expected == actual


def get_matching_firewall_rules(db, port, protocol, source_ip=None, destination_ip=None):
    """Return active matching rules in deterministic priority order."""
    custom_rules = db.query(FirewallRule).all()

    custom_rule_dicts = [
        {
            "id": rule.id,
            "name": rule.name,
            "source": rule.source,
            "destination": rule.destination,
            "port": rule.port,
            "protocol": rule.protocol,
            "action": rule.action,
            "status": rule.status,
            "priority": rule.priority,
            "custom": True,
        }
        for rule in custom_rules
    ]

    all_rules = list(firewall_rules) + custom_rule_dicts

    matching = [
        rule for rule in all_rules
        if str(rule.get("status", "")).upper() == "ACTIVE"
        and port_matches(rule.get("port", ""), port)
        and protocol_matches(rule.get("protocol", "TCP"), protocol)
        and source_matches(rule.get("source", "Any"), source_ip)
        and destination_matches(rule.get("destination", "Any"), destination_ip)
    ]

    return sorted(
        matching,
        key=lambda rule: (
            -int(rule.get("priority", 0)),
            int(rule.get("id", 0)) + (1000000 if rule.get("custom") else 0),
        ),
    )


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
    destination_ip: str | None = None,
    db: Session = Depends(get_db),
):
    if not 1 <= port <= 65535:
        raise HTTPException(
            status_code=422,
            detail="Port must be between 1 and 65535",
        )

    protocol = protocol.strip().upper()
    if protocol not in {"TCP", "UDP", "ICMP"}:
        raise HTTPException(
            status_code=422,
            detail="Protocol must be TCP, UDP or ICMP",
        )

    if source_ip:
        source_ip = _valid_source_ip(source_ip)
    if destination_ip:
        destination_ip = _valid_source_ip(destination_ip)

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
        matching_rules = get_matching_firewall_rules(
            db, port, protocol, source_ip, destination_ip
        )
        matched = bool(matching_rules)
        rule = matching_rules[0] if matched else None
        action = rule["action"] if rule else "BLOCK"
        rule_name = rule["name"] if rule else "Default Deny Policy"
        priority = rule.get("priority", 0) if rule else 0

        matched_rule_type = (
            "CUSTOM" if rule and rule.get("custom")
            else "DEFAULT" if rule
            else "DEFAULT_DENY"
        )

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
        "destination_ip": destination_ip,
        "priority": priority,
        "rule_type": (
            "TEMPORARY_BLOCK" if forced_block_reason
            else matched_rule_type
        ),
        "monitor_only": action == "MONITOR",
        "temporary_block": bool(forced_block_reason),
        "block_reason": block_details["reason"] if forced_block_reason else None,
        "simulation_mode": True,
    }




# =========================================================
# ADVANCED FIREWALL: POLICY SIMULATOR AND RULE ANALYTICS
# =========================================================

@app.get("/api/firewall/simulate")
def simulate_firewall_policy(
    port: int,
    protocol: str = "TCP",
    source_ip: str | None = None,
    destination_ip: str | None = None,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    """Dry-run firewall policy evaluation without changing protection state."""

    if not 1 <= port <= 65535:
        raise HTTPException(status_code=422, detail="Port must be between 1 and 65535")

    protocol = protocol.strip().upper()
    if protocol not in {"TCP", "UDP", "ICMP"}:
        raise HTTPException(status_code=422, detail="Protocol must be TCP, UDP or ICMP")

    if source_ip:
        source_ip = _valid_source_ip(source_ip)
    if destination_ip:
        destination_ip = _valid_source_ip(destination_ip)

    matching_rules = get_matching_firewall_rules(
        db, port, protocol, source_ip, destination_ip
    )
    winner = matching_rules[0] if matching_rules else None
    action = winner["action"] if winner else "BLOCK"

    return {
        "simulation_only": True,
        "input": {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "port": port,
            "protocol": protocol,
        },
        "decision": action,
        "matched": winner is not None,
        "winning_rule": winner,
        "rule_type": (
            "CUSTOM" if winner and winner.get("custom")
            else "DEFAULT" if winner
            else "DEFAULT_DENY"
        ),
        "priority": winner.get("priority", 0) if winner else 0,
        "matching_rule_count": len(matching_rules),
        "matching_rules": matching_rules,
        "explanation": (
            f"Highest-priority matching rule '{winner['name']}' "
            f"selected action {action}."
            if winner else
            "No active rule matched. Default-deny policy selected BLOCK."
        ),
        "note": "This dry run does not modify firewall state or rate-limit counters.",
    }


@app.get("/api/firewall/analytics")
def firewall_rule_analytics(
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    """Summarize recorded firewall decisions from persistent audit logs."""

    logs = (
        db.query(AuditLog)
        .filter(AuditLog.event_type == "FIREWALL_DECISION")
        .order_by(AuditLog.id.desc())
        .limit(1000)
        .all()
    )

    action_counts = {"ALLOW": 0, "BLOCK": 0, "MONITOR": 0, "OTHER": 0}
    severity_counts = {}
    source_counts = {}
    rule_counts = {}
    unknown_source_decisions = 0
    identified_source_decisions = 0

    for log in logs:
        action = (log.action or "").upper()
        if action in action_counts:
            action_counts[action] += 1
        else:
            action_counts["OTHER"] += 1

        severity = (log.severity or "UNKNOWN").upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        source = (log.source_ip or "").strip() or "Unknown"
        if source.lower() == "unknown":
            unknown_source_decisions += 1
            source = "Unknown"
        else:
            identified_source_decisions += 1

        source_counts[source] = source_counts.get(source, 0) + 1

        message = log.message or ""
        rule_name = "Unknown"
        for part in message.split(";"):
            if part.strip().startswith("Rule="):
                rule_name = part.strip()[5:]
                break
        rule_counts[rule_name] = rule_counts.get(rule_name, 0) + 1

    top_sources = sorted(
        [{"source_ip": k, "hits": v} for k, v in source_counts.items()],
        key=lambda item: item["hits"],
        reverse=True,
    )[:10]

    top_rules = sorted(
        [{"rule": k, "hits": v} for k, v in rule_counts.items()],
        key=lambda item: item["hits"],
        reverse=True,
    )[:10]

    return {
        "total_decisions": len(logs),
        "sample_limit": 1000,
        "actions": action_counts,
        "severities": severity_counts,
        "top_sources": top_sources,
        "top_rules": top_rules,
        "source_attribution": {
            "identified": identified_source_decisions,
            "unknown": unknown_source_decisions,
            "identified_percentage": round(
                identified_source_decisions / len(logs) * 100, 2
            ) if logs else 0,
            "unknown_percentage": round(
                unknown_source_decisions / len(logs) * 100, 2
            ) if logs else 0,
        },
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




@app.post("/api/response-actions", status_code=201)
def create_response_action(
    payload: ResponseActionCreate,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    if payload.incident_id is not None:
        incident = db.query(Incident).filter(
            Incident.id == payload.incident_id
        ).first()
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")

    action = ResponseAction(
        incident_id=payload.incident_id,
        threat_type=payload.threat_type.strip(),
        risk_score=payload.risk_score,
        recommended_action=payload.recommended_action.strip(),
        requested_by=admin["sub"],
        status="PENDING",
        simulation_mode=1,
    )
    db.add(action)
    db.flush()
    create_audit_log(
        db,
        event_type="RESPONSE_ACTION_CREATED",
        message=f"Response action {action.id} created for {action.threat_type}",
        severity="INFO",
        action="PENDING",
    )
    db.refresh(action)
    return action


@app.get("/api/response-actions")
def list_response_actions(
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    return db.query(ResponseAction).order_by(
        ResponseAction.created_at.desc()
    ).limit(100).all()


@app.post("/api/response-actions/{action_id}/review")
def review_response_action(
    action_id: int,
    payload: ResponseActionReview,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    if payload.decision not in ("APPROVED", "REJECTED"):
        raise HTTPException(status_code=422, detail="Decision must be APPROVED or REJECTED")

    action = db.query(ResponseAction).filter(
        ResponseAction.id == action_id
    ).with_for_update().first()
    if action is None:
        raise HTTPException(status_code=404, detail="Response action not found")
    if action.status != "PENDING":
        raise HTTPException(status_code=409, detail="Only pending actions can be reviewed")

    action.status = payload.decision
    action.reviewed_by = admin["sub"]
    action.review_note = payload.review_note.strip()
    action.reviewed_at = datetime.utcnow()
    db.add(action)
    create_audit_log(
        db,
        event_type="RESPONSE_ACTION_REVIEWED",
        message=f"Response action {action.id} {action.status.lower()} by {admin['sub']}",
        severity="INFO" if action.status == "APPROVED" else "WARNING",
        action=action.status,
    )
    db.refresh(action)
    return action


@app.post("/api/response-actions/{action_id}/rollback")
def rollback_response_action(
    action_id: int,
    payload: ResponseActionRollback,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    action = db.query(ResponseAction).filter(
        ResponseAction.id == action_id
    ).with_for_update().first()
    if action is None:
        raise HTTPException(status_code=404, detail="Response action not found")
    if action.status != "APPROVED" or action.simulation_mode != 1:
        raise HTTPException(
            status_code=409,
            detail="Only approved simulated actions can be rolled back",
        )
    if action.rollback_status == "ROLLED_BACK":
        raise HTTPException(status_code=409, detail="Action already rolled back")

    action.rollback_status = "ROLLED_BACK"
    action.rolled_back_at = datetime.utcnow()
    action.review_note = (
        f"{action.review_note}\nRollback by {admin['sub']}: "
        f"{payload.review_note.strip()}"
    ).strip()
    db.add(action)
    create_audit_log(
        db,
        event_type="RESPONSE_ACTION_ROLLED_BACK",
        message=f"Simulated response action {action.id} rolled back by {admin['sub']}",
        severity="WARNING",
        action="ROLLED_BACK",
    )
    db.refresh(action)
    return action


@app.get("/api/logs")
def get_logs(
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    return db.query(AuditLog).order_by(
        AuditLog.created_at.desc()
    ).limit(100).all()



@app.get("/api/analytics/block-spike-alerts")
def get_block_spike_alerts(
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    """Evaluate recent audit activity and return persisted BLOCK spike alerts."""

    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .limit(100)
        .all()
    )

    valid_events = []
    valid_block_events = []

    for log in logs:
        timestamp = log.created_at
        if not timestamp:
            continue

        if timestamp.tzinfo is not None:
            timestamp = timestamp.replace(tzinfo=None)

        valid_events.append(timestamp)

        action = str(log.action or "").upper()
        event_type = str(log.event_type or "").upper()

        if action == "BLOCK" or "BLOCK" in event_type:
            valid_block_events.append(timestamp)

    if valid_events:
        latest_timestamp = max(valid_events)
        latest_hour = latest_timestamp.replace(
            minute=0, second=0, microsecond=0
        )
        coverage_start = latest_hour - timedelta(hours=5)
        oldest_event = min(valid_events)

        hourly_blocks = []
        for index in range(6):
            start = latest_hour - timedelta(hours=5 - index)
            end = start + timedelta(hours=1)
            hourly_blocks.append(
                sum(1 for timestamp in valid_block_events
                    if start <= timestamp < end)
            )

        enough_data = oldest_event <= coverage_start
    else:
        latest_hour = None
        hourly_blocks = []
        enough_data = False

    if enough_data:
        latest_blocks = hourly_blocks[5]
        baseline = sum(hourly_blocks[:5]) / 5
        threshold = max(3, baseline * 2)

        spike_detected = (
            latest_blocks >= 3
            and latest_blocks >= baseline * 2
        )
        critical_spike = (
            spike_detected
            and latest_blocks >= 6
            and (baseline == 0 or latest_blocks >= baseline * 3)
        )
    else:
        latest_blocks = 0
        baseline = 0.0
        threshold = 3.0
        spike_detected = False
        critical_spike = False

    persisted_alert = None

    if enough_data and spike_detected:
        detection_key = latest_hour.strftime("%Y-%m-%dT%H:00:00")
        severity = "CRITICAL" if critical_spike else "HIGH"

        persisted_alert = (
            db.query(BlockSpikeAlert)
            .filter(BlockSpikeAlert.detection_key == detection_key)
            .first()
        )

        if persisted_alert is None:
            persisted_alert = BlockSpikeAlert(
                detection_key=detection_key,
                severity=severity,
                latest_block_count=latest_blocks,
                baseline_average=baseline,
                detection_threshold=threshold,
                status="OPEN",
                detected_at=datetime.utcnow(),
            )
            db.add(persisted_alert)
            try:
                db.commit()
                db.refresh(persisted_alert)
            except IntegrityError:
                db.rollback()
                persisted_alert = (
                    db.query(BlockSpikeAlert)
                    .filter(BlockSpikeAlert.detection_key == detection_key)
                    .first()
                )
        else:
            # Update the detection data without resetting acknowledgement.
            persisted_alert.severity = severity
            persisted_alert.latest_block_count = latest_blocks
            persisted_alert.baseline_average = baseline
            persisted_alert.detection_threshold = threshold
            db.commit()
            db.refresh(persisted_alert)

    alerts = (
        db.query(BlockSpikeAlert)
        .order_by(BlockSpikeAlert.detected_at.desc())
        .limit(50)
        .all()
    )

    return {
        "detection": {
            "status": (
                "INSUFFICIENT DATA" if not enough_data
                else "CRITICAL SPIKE" if critical_spike
                else "HIGH SPIKE" if spike_detected
                else "NO SPIKE DETECTED"
            ),
            "enough_data": enough_data,
            "latest_blocks": latest_blocks,
            "baseline": baseline,
            "threshold": threshold,
            "hourly_blocks": hourly_blocks,
        },
        "alerts": [
            {
                "id": alert.id,
                "detection_key": alert.detection_key,
                "severity": alert.severity,
                "latest_block_count": alert.latest_block_count,
                "baseline_average": alert.baseline_average,
                "detection_threshold": alert.detection_threshold,
                "status": alert.status,
                "detected_at": alert.detected_at.isoformat()
                    if alert.detected_at else None,
                "acknowledged_at": alert.acknowledged_at.isoformat()
                    if alert.acknowledged_at else None,
                "acknowledged_by": alert.acknowledged_by,
            }
            for alert in alerts
        ],
    }


@app.post("/api/analytics/block-spike-alerts/{alert_id}/acknowledge")
def acknowledge_block_spike_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    """Acknowledge a persisted BLOCK spike alert."""

    alert = (
        db.query(BlockSpikeAlert)
        .filter(BlockSpikeAlert.id == alert_id)
        .first()
    )

    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    if alert.status != "ACKNOWLEDGED":
        alert.status = "ACKNOWLEDGED"
        alert.acknowledged_at = datetime.utcnow()
        alert.acknowledged_by = str(admin.get("sub") or "admin")
        db.commit()
        db.refresh(alert)

    return {
        "id": alert.id,
        "status": alert.status,
        "acknowledged_at": (
            alert.acknowledged_at.isoformat()
            if alert.acknowledged_at else None
        ),
        "acknowledged_by": alert.acknowledged_by,
    }


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
    q = question.lower().strip()

    latest = (
        db.query(Threat)
        .order_by(Threat.created_at.desc())
        .first()
    )

    threats = (
        db.query(Threat)
        .order_by(Threat.created_at.desc())
        .limit(100)
        .all()
    )

    incidents = (
        db.query(Incident)
        .order_by(Incident.created_at.desc())
        .limit(100)
        .all()
    )

    rules = db.query(FirewallRule).all()
    sessions = (
        db.query(UserSession)
        .order_by(UserSession.updated_at.desc())
        .limit(100)
        .all()
    )

    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .limit(100)
        .all()
    )

    def count_values(items, attribute):
        result = {}
        for item in items:
            value = getattr(item, attribute, None) or "UNKNOWN"
            value = str(value).upper()
            result[value] = result.get(value, 0) + 1
        return result

    def threat_context():
        if latest is None:
            return None
        return {
            "id": latest.id,
            "type": latest.threat_type,
            "threat_type": latest.threat_type,
            "source_ip": latest.source_ip,
            "destination_ip": latest.destination_ip,
            "port": latest.port,
            "protocol": latest.protocol,
            "anomaly_score": latest.anomaly_score,
            "risk_score": latest.risk_score,
            "severity": latest.severity,
            "action": latest.action,
        }

    def average(values):
        values = [float(v or 0) for v in values]
        return round(sum(values) / len(values), 2) if values else 0

    # Identify an IP address explicitly mentioned in the question.
    import re
    ip_match = re.search(
        r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])',
        question
    )
    requested_ip = ip_match.group(0) if ip_match else None

    # SOURCE IP INVESTIGATION
    if requested_ip:
        matching_threats = [
            t for t in threats if t.source_ip == requested_ip
        ]
        matching_logs = [
            log for log in logs if log.source_ip == requested_ip
        ]

        matching_incidents = [
            incident for incident in incidents
            if any(
                t.id == incident.threat_id
                for t in matching_threats
            )
        ]

        if matching_threats:
            risk = average(t.risk_score for t in matching_threats)
            types = count_values(matching_threats, "threat_type")
            actions = count_values(matching_threats, "action")

            answer = (
                f"Source IP investigation: {requested_ip}\n"
                f"Threat records found: {len(matching_threats)}\n"
                f"Related incidents: {len(matching_incidents)}\n"
                f"Matching audit events in the latest 100 logs: "
                f"{len(matching_logs)}\n"
                f"Average threat risk: {risk}/100\n"
                f"Threat types: {types}\n"
                f"Recorded actions: {actions}\n"
                "Recommendation: review the associated events and "
                "incident history. Consider a temporary block only "
                "after validating the source and business impact."
            )
        else:
            answer = (
                f"No threat record for source IP {requested_ip} was "
                "found in the latest 100 threat records. "
                f"Matching audit events in the latest 100 logs: "
                f"{len(matching_logs)}."
            )

    # INCIDENT INVESTIGATION
    elif any(word in q for word in (
        "incident", "investigation status", "case status"
    )):
        statuses = count_values(incidents, "status")
        severities = count_values(incidents, "severity")
        high_risk = sum(
            1 for item in incidents
            if (item.risk_score or 0) >= 70
        )

        answer = (
            f"Incident investigation summary (latest {len(incidents)} "
            "records):\n"
            f"Total incidents: {len(incidents)}\n"
            f"Statuses: {statuses}\n"
            f"Severity distribution: {severities}\n"
            f"Incidents with risk score >= 70: {high_risk}\n"
            f"Average incident risk: "
            f"{average(i.risk_score for i in incidents)}/100.\n"
            "Recommendation: prioritize unresolved high-risk incidents, "
            "record investigation notes, and verify resolution evidence."
        )

    # FIREWALL INVESTIGATION
    elif "firewall" in q or "firewall rule" in q:
        active_rules = [
            rule for rule in rules
            if str(rule.status).upper() == "ACTIVE"
        ]
        actions = count_values(active_rules, "action")

        answer = (
            f"Firewall policy review:\n"
            f"Total configured rules: {len(rules)}\n"
            f"Active rules: {len(active_rules)}\n"
            f"Active rule actions: {actions}\n"
            f"Disabled rules: {len(rules) - len(active_rules)}\n"
            "Recommendation: review broad source or destination "
            "matches, check conflicting rules, and use least-privilege "
            "policies. SentinelAI firewall evaluation is a simulation "
            "and does not itself enforce OS-level packet filtering."
        )

    # ZERO TRUST INVESTIGATION
    elif "zero trust" in q or "zero-trust" in q or (
        "session" in q and ("risk" in q or "access" in q)
    ):
        decisions = count_values(sessions, "decision")
        statuses = count_values(sessions, "status")

        risky = [
            s for s in sessions if (s.risk_score or 0) >= 70
        ]
        identity_failures = sum(
            1 for s in sessions if not s.identity_verified
        )
        untrusted_devices = sum(
            1 for s in sessions if not s.device_trusted
        )
        noncompliant = sum(
            1 for s in sessions if not s.device_compliant
        )

        answer = (
            f"Zero Trust session review:\n"
            f"Sessions examined: {len(sessions)}\n"
            f"Access decisions: {decisions}\n"
            f"Session statuses: {statuses}\n"
            f"High-risk sessions (>=70): {len(risky)}\n"
            f"Identity verification failures: {identity_failures}\n"
            f"Untrusted devices: {untrusted_devices}\n"
            f"Non-compliant devices: {noncompliant}\n"
            "Recommendation: reassess high-risk sessions, verify "
            "identity, validate device posture, and revoke access "
            "when policy requirements are not satisfied."
        )

    # SECURITY OPERATIONS SUMMARY
    elif any(word in q for word in (
        "summary", "overall", "network risk", "security posture",
        "security operations", "current network", "security status"
    )):
        severities = count_values(threats, "severity")
        actions = count_values(threats, "action")
        open_incidents = sum(
            1 for i in incidents
            if str(i.status).upper() in ("OPEN", "INVESTIGATING")
        )
        risky_sessions = sum(
            1 for s in sessions if (s.risk_score or 0) >= 70
        )

        answer = (
            "SentinelAI security operations summary:\n"
            f"Threat records examined: {len(threats)}\n"
            f"Threat severity distribution: {severities}\n"
            f"Threat response actions: {actions}\n"
            f"Average threat risk: "
            f"{average(t.risk_score for t in threats)}/100\n"
            f"Incident records examined: {len(incidents)}\n"
            f"Open or investigating incidents: {open_incidents}\n"
            f"Active firewall rules: "
            f"{sum(1 for r in rules if str(r.status).upper() == 'ACTIVE')}\n"
            f"Zero Trust sessions examined: {len(sessions)}\n"
            f"High-risk sessions: {risky_sessions}\n"
            f"Recent audit events examined: {len(logs)}.\n"
            "Recommendation: prioritize critical threats, unresolved "
            "incidents, high-risk sessions, and firewall policy conflicts."
        )

    # THREAT HISTORY AND INVESTIGATION
    elif any(word in q for word in (
        "threat", "attack", "blocked", "risk", "score",
        "recommend", "recommendation", "detected"
    )):
        if latest is None:
            answer = (
                "No threat records are available yet. Create a demo "
                "attack or submit network traffic for analysis."
            )
        else:
            if "recommend" in q:
                answer = (
                    f"Recommended response for the latest "
                    f"{latest.threat_type} event:\n"
                    f"Source: {latest.source_ip}\n"
                    f"Risk: {latest.risk_score}/100\n"
                    f"Severity: {latest.severity}\n"
                    f"Recorded action: {latest.action}\n"
                    "Recommendation: investigate the source, review "
                    "related incidents, validate the firewall decision, "
                    "and monitor subsequent traffic. Avoid treating a "
                    "simulated action as a real network block."
                )
            elif "why" in q and ("block" in q or "allow" in q):
                answer = (
                    f"The latest event is {latest.threat_type}, with "
                    f"risk {latest.risk_score}/100 and anomaly score "
                    f"{latest.anomaly_score}/100. Its severity is "
                    f"{latest.severity} and recorded action is "
                    f"{latest.action}. Source {latest.source_ip}, "
                    f"destination {latest.destination_ip}, port "
                    f"{latest.port}/{latest.protocol}. These recorded "
                    "values explain the classification, but the exact "
                    "decision logic should be checked in the threat "
                    "detection and risk engine."
                )
            elif "risk" in q or "score" in q:
                answer = (
                    f"Latest threat risk: {latest.risk_score}/100\n"
                    f"Anomaly score: {latest.anomaly_score}/100\n"
                    f"Severity: {latest.severity}\n"
                    f"Action: {latest.action}\n"
                    f"Average risk across the latest {len(threats)} "
                    f"threat records: "
                    f"{average(t.risk_score for t in threats)}/100."
                )
            else:
                answer = (
                    f"Latest detected threat: {latest.threat_type}\n"
                    f"Source: {latest.source_ip}\n"
                    f"Destination: {latest.destination_ip}\n"
                    f"Port/protocol: {latest.port}/{latest.protocol}\n"
                    f"Packets: {latest.packets}\n"
                    f"Bytes transferred: {latest.bytes_transferred}\n"
                    f"Risk: {latest.risk_score}/100\n"
                    f"Severity: {latest.severity}\n"
                    f"Recorded action: {latest.action}\n"
                    f"Threat records examined: {len(threats)}."
                )

    else:
        answer = (
            "I can investigate your SentinelAI database. Ask about "
            "threat history, incident status, firewall rules, a source "
            "IP address, Zero Trust sessions, or the overall security "
            "operations summary."
        )

    return {
        "answer": answer,
        "threat": threat_context()
    }



# ============================================================
# SECURITY ANALYTICS
# ============================================================



# ============================================================
# SENTINELAI HYBRID AI COPILOT
# ============================================================

class CopilotAnalyzeRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=4000)
    network_event: Optional[dict] = None


@app.post("/api/copilot/analyze")
def analyze_with_copilot(
    payload: CopilotAnalyzeRequest,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    try:
        result = run_copilot(
            question=payload.question,
            db=db,
            network_event=payload.network_event,
        )

        return {
            **result,
            "administrator": admin.get("sub", "admin"),
        }

    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        )

    except RuntimeError:
        raise HTTPException(
            status_code=503,
            detail="Copilot AI provider is temporarily unavailable. Please try again.",
        )


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




@app.get("/api/threats/timeline")
def threat_timeline(
    hours: int = 24,
    severity: Optional[str] = None,
    include_test: bool = True,
    source_ip: Optional[str] = None,
    db: Session = Depends(get_db)
):
    if hours not in (1, 24, 168):
        raise HTTPException(
            status_code=400,
            detail="hours must be 1, 24, or 168"
        )

    allowed_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    if severity:
        severity = severity.strip().upper()
        if severity not in allowed_severities:
            raise HTTPException(
                status_code=400,
                detail="Invalid severity filter"
            )

    cutoff = datetime.utcnow() - timedelta(hours=hours)

    query = db.query(Threat).filter(
        Threat.created_at >= cutoff
    )

    if severity:
        query = query.filter(Threat.severity == severity)

    if source_ip:
        source_ip = source_ip.strip()
        if len(source_ip) > 64:
            raise HTTPException(
                status_code=400,
                detail="Invalid source IP filter"
            )
        query = query.filter(Threat.source_ip == source_ip)

    records = query.order_by(Threat.created_at.desc()).all()

    events = []

    for threat in records:
        threat_name = (threat.threat_type or "").upper()

        is_test = any(
            marker in threat_name
            for marker in ("TEST", "SIMULATION", "STAGE_")
        )

        if not include_test and is_test:
            continue

        events.append({
            "id": threat.id,
            "threat_type": threat.threat_type,
            "source_ip": threat.source_ip,
            "destination_ip": threat.destination_ip,
            "port": threat.port,
            "protocol": threat.protocol,
            "risk_score": threat.risk_score,
            "severity": threat.severity,
            "action": threat.action,
            "status": threat.status,
            "created_at": (
                threat.created_at.isoformat()
                if threat.created_at else None
            ),
            "is_test": is_test
        })

    return {
        "time_range_hours": hours,
        "severity_filter": severity or "ALL",
        "include_test": include_test,
        "total": len(events),
        "events": events
    }

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


# DATASET LAB MODEL EVALUATION
@app.post("/api/datasets/evaluate")
async def evaluate_uploaded_dataset(
    file: UploadFile = File(...),
    label_column: Optional[str] = None,
):
    """Evaluate a labelled CSV on a bounded, held-out test split."""
    import os
    import tempfile

    from dataset_evaluator import evaluate_dataset

    filename = file.filename or "dataset.csv"
    if not filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a CSV file.")

    temp_path = None
    total_bytes = 0
    max_bytes = 10 * 1024 * 1024 * 1024  # 100 MiB for model evaluation

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".csv", prefix="sentinelai_eval_", delete=False
        ) as temp:
            temp_path = temp.name

            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break

                total_bytes += len(chunk)
                if total_bytes > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail="Model evaluation supports CSV files up to 10 GiB.",
                    )

                temp.write(chunk)

        if total_bytes == 0:
            raise HTTPException(status_code=400, detail="The CSV file is empty.")

        try:
            result = evaluate_dataset(temp_path, label_column=label_column)
        except (ValueError, KeyError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except (UnicodeDecodeError, pd.errors.ParserError) as exc:
            raise HTTPException(
                status_code=400, detail=f"Could not read the CSV: {exc}"
            ) from exc

        result["filename"] = filename
        return result

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        await file.close()



# =========================================================
# DATASET INTELLIGENCE ENGINE
# =========================================================

@app.post("/api/datasets/intelligence")
async def analyze_dataset_intelligence(file: UploadFile = File(...)):
    """Profile an uploaded CSV across all rows using bounded-memory chunks."""
    import os
    import tempfile
    from dataset_intelligence import profile_dataset

    filename = file.filename or "dataset.csv"

    if not filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a CSV file.")

    temp_path = None
    total_bytes = 0
    max_bytes = 10 * 1024 * 1024 * 1024

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".csv",
            prefix="sentinelai_intelligence_", delete=False
        ) as temp:
            temp_path = temp.name

            while True:
                chunk = await file.read(8 * 1024 * 1024)
                if not chunk:
                    break

                total_bytes += len(chunk)

                if total_bytes > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail="Dataset intelligence supports CSV files up to 10 GiB."
                    )

                temp.write(chunk)

        if total_bytes == 0:
            raise HTTPException(status_code=400, detail="The CSV file is empty.")

        try:
            result = profile_dataset(temp_path, chunksize=25_000)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except (UnicodeDecodeError, pd.errors.ParserError) as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Could not read the CSV: {exc}"
            ) from exc

        result["filename"] = filename
        result["file_size_bytes"] = total_bytes

        return result

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        await file.close()


# PERSISTENT MULTI-DEVICE MONITORING
# Health telemetry is stored in the database.
# Physical location remains separately opt-in.
# =========================================================

import os as _device_monitor_os
import hmac as _device_monitor_hmac
from datetime import datetime as _device_monitor_datetime, timezone as _device_monitor_timezone


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


def _device_monitor_authorize_device(
    authorization: str | None,
    device_id: str,
    db: Session,
) -> None:
    """Authenticate registered devices individually; retain legacy fallback for unregistered devices."""
    parts = (authorization or "").split(None, 1)

    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid device-monitor token.")

    supplied_token = parts[1].strip()

    credential = (
        db.query(DeviceCredential)
        .filter(DeviceCredential.device_id == device_id)
        .first()
    )

    if credential is not None:
        if not credential.is_active:
            raise HTTPException(
                status_code=401,
                detail="Device credential has been revoked.",
            )

        supplied_hash = hashlib.sha256(
            supplied_token.encode("utf-8")
        ).hexdigest()

        if not hmac.compare_digest(supplied_hash, credential.token_hash):
            raise HTTPException(
                status_code=401,
                detail="Invalid device credential.",
            )

        credential.last_used_at = datetime.utcnow()
        return

    # Migration fallback: devices not yet individually registered
    # continue using the existing shared device-monitor token.
    _device_monitor_authorize(authorization)


def _device_monitor_number(value, default=None):
    if value is None:
        return default
    try:
        number = float(value)
        if number != number or number in (float("inf"), float("-inf")):
            return default
        return number
    except (TypeError, ValueError):
        return default


def _device_monitor_serialize(agent, telemetry=None):
    last_seen = agent.last_seen
    online = bool(
        last_seen
        and (_device_monitor_datetime.utcnow() - last_seen).total_seconds() < 45
    )

    location = None
    if agent.latitude is not None and agent.longitude is not None:
        location = {
            "latitude": agent.latitude,
            "longitude": agent.longitude,
            "accuracy_m": agent.location_accuracy_m or 0,
            "updated_at": (
                agent.location_updated_at.replace(tzinfo=_device_monitor_timezone.utc).isoformat()
                if agent.location_updated_at else None
            ),
        }

    result = {
        "device_id": agent.device_id,
        "device_name": agent.device_name,
        "platform": agent.platform,
        "os_version": agent.os_version,
        "local_ip": agent.local_ip,
        "status": "ONLINE" if online else "OFFLINE",
        "last_seen": (
            last_seen.replace(tzinfo=_device_monitor_timezone.utc).isoformat()
            if last_seen else None
        ),
        "location": location,
    }

    if telemetry:
        result.update({
            "cpu_percent": telemetry.cpu_percent,
            "cpu_cores": telemetry.cpu_cores,
            "memory_percent": telemetry.memory_percent,
            "memory_used_gb": telemetry.memory_used_gb,
            "memory_total_gb": telemetry.memory_total_gb,
            "disk_percent": telemetry.disk_percent,
            "battery_percent": telemetry.battery_percent,
            "battery_power_plugged": (
                bool(telemetry.battery_power_plugged)
                if telemetry.battery_power_plugged is not None else None
            ),
            "network_sent_mb": telemetry.network_sent_mb,
            "network_recv_mb": telemetry.network_recv_mb,
            "captured_at": (
                telemetry.captured_at.replace(tzinfo=_device_monitor_timezone.utc).isoformat()
                if telemetry.captured_at else None
            ),
        })

    return result


@app.post("/api/device-monitor/report")
def device_monitor_report(
    payload: dict,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    device_id = str(payload.get("device_id", "")).strip()[:120]
    device_name = str(payload.get("device_name", "")).strip()[:160]

    if not device_id or not device_name:
        raise HTTPException(
            status_code=400,
            detail="device_id and device_name are required.",
        )

    _device_monitor_authorize_device(authorization, device_id, db)

    now = _device_monitor_datetime.utcnow()

    try:
        agent = (
            db.query(DeviceAgent)
            .filter(DeviceAgent.device_id == device_id)
            .first()
        )

        if agent is None:
            agent = DeviceAgent(
                device_id=device_id,
                device_name=device_name,
                first_seen=now,
            )
            db.add(agent)

        agent.device_name = device_name
        agent.platform = str(payload.get("platform") or "Unknown")[:80]
        agent.os_version = str(payload.get("os_version") or "")[:120]
        agent.local_ip = str(payload.get("local_ip") or "")[:64]
        agent.status = "ONLINE"
        agent.last_seen = now

        telemetry = DeviceTelemetry(
            device_id=device_id,
            cpu_percent=_device_monitor_number(payload.get("cpu_percent")),
            cpu_cores=(
                int(payload["cpu_cores"])
                if str(payload.get("cpu_cores", "")).isdigit()
                else None
            ),
            memory_percent=_device_monitor_number(payload.get("memory_percent")),
            memory_used_gb=_device_monitor_number(payload.get("memory_used_gb")),
            memory_total_gb=_device_monitor_number(payload.get("memory_total_gb")),
            disk_percent=_device_monitor_number(payload.get("disk_percent")),
            battery_percent=_device_monitor_number(payload.get("battery_percent")),
            battery_power_plugged=(
                int(bool(payload["battery_power_plugged"]))
                if payload.get("battery_power_plugged") is not None else None
            ),
            network_sent_mb=_device_monitor_number(payload.get("network_sent_mb")),
            network_recv_mb=_device_monitor_number(payload.get("network_recv_mb")),
            captured_at=now,
        )

        db.add(telemetry)
        db.commit()

        # SentinelAI-X: observe committed endpoint telemetry for concept drift.
        # This is isolated so drift-monitor failures cannot break normal reporting.
        try:
            drift_metrics = {
                "cpu_percent": telemetry.cpu_percent,
                "memory_percent": telemetry.memory_percent,
                "disk_percent": telemetry.disk_percent,
                "battery_percent": telemetry.battery_percent,
            }

            for metric_name, metric_value in drift_metrics.items():
                if metric_value is None:
                    continue

                drift_events = sentinel_x_drift_monitor.update(
                    device_id=device_id,
                    metric=metric_name,
                    value=float(metric_value),
                )
                persist_sentinel_x_observation(
                    db, device_id, metric_name, float(metric_value), drift_events
                )

        except Exception:
            logger.exception(
                "SentinelAI-X drift monitoring failed for device %s",
                device_id,
            )

        # Intelligence runs after telemetry is safely committed.
        try:
            intelligence_result = assess_and_persist(db, telemetry)
            logger.info(
                "Device assessment saved: device=%s severity=%s risk=%s",
                device_id,
                intelligence_result.get("severity"),
                intelligence_result.get("risk_score"),
            )
        except Exception:
            db.rollback()
            logger.exception(
                "Device intelligence assessment failed for device %s",
                device_id,
            )

        return {
            "ok": True,
            "device_id": device_id,
            "last_seen": now.replace(tzinfo=_device_monitor_timezone.utc).isoformat(),
        }

    except Exception:
        db.rollback()
        raise




# =========================================================
# DEVICE INTELLIGENCE: ADMIN ASSESSMENTS AND ALERTS
# =========================================================

def serialize_device_assessment(record):
    return {
        "id": record.id,
        "device_id": record.device_id,
        "risk_score": record.risk_score,
        "severity": record.severity,
        "confidence": record.confidence,
        "baseline_samples": record.baseline_samples,
        "anomaly_count": record.anomaly_count,
        "evidence": record.evidence or [],
        "network_delta_mb": record.network_delta_mb,
        "recommended_action": record.recommended_action,
        "assessed_at": (
            record.assessed_at.isoformat() if record.assessed_at else None
        ),
    }


def serialize_device_alert(record):
    return {
        "id": record.id,
        "device_id": record.device_id,
        "anomaly_type": record.anomaly_type,
        "severity": record.severity,
        "risk_score": record.risk_score,
        "title": record.title,
        "description": record.description,
        "evidence": record.evidence or [],
        "status": record.status,
        "first_detected_at": (
            record.first_detected_at.isoformat()
            if record.first_detected_at else None
        ),
        "last_detected_at": (
            record.last_detected_at.isoformat()
            if record.last_detected_at else None
        ),
        "acknowledged_at": (
            record.acknowledged_at.isoformat()
            if record.acknowledged_at else None
        ),
        "acknowledged_by": record.acknowledged_by,
        "resolved_at": (
            record.resolved_at.isoformat()
            if record.resolved_at else None
        ),
    }


@app.get("/api/device-monitor/assessments")
def list_device_assessments(
    device_id: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    if not 1 <= limit <= 200:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 200.")

    query = db.query(DeviceAssessment)

    if device_id:
        query = query.filter(DeviceAssessment.device_id == device_id.strip())

    records = (
        query.order_by(
            DeviceAssessment.assessed_at.desc(),
            DeviceAssessment.id.desc(),
        )
        .limit(limit)
        .all()
    )

    return {
        "count": len(records),
        "assessments": [serialize_device_assessment(item) for item in records],
    }


@app.get("/api/device-monitor/alerts")
def list_device_alerts(
    device_id: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    if not 1 <= limit <= 200:
        raise HTTPException(status_code=400, detail="Limit must be between 1 and 200.")

    query = db.query(DeviceAlert)

    if device_id:
        query = query.filter(DeviceAlert.device_id == device_id.strip())

    if status:
        normalized_status = status.strip().upper()
        if normalized_status not in {"OPEN", "ACKNOWLEDGED", "RESOLVED"}:
            raise HTTPException(
                status_code=400,
                detail="Status must be OPEN, ACKNOWLEDGED, or RESOLVED.",
            )
        query = query.filter(DeviceAlert.status == normalized_status)

    if severity:
        normalized_severity = severity.strip().upper()
        if normalized_severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise HTTPException(
                status_code=400,
                detail="Invalid severity.",
            )
        query = query.filter(DeviceAlert.severity == normalized_severity)

    records = (
        query.order_by(DeviceAlert.last_detected_at.desc(), DeviceAlert.id.desc())
        .limit(limit)
        .all()
    )

    return {
        "count": len(records),
        "alerts": [serialize_device_alert(item) for item in records],
    }


@app.get("/api/device-monitor/alerts/{alert_id}")
def get_device_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    record = db.query(DeviceAlert).filter(DeviceAlert.id == alert_id).first()

    if record is None:
        raise HTTPException(status_code=404, detail="Device alert not found.")

    return {"alert": serialize_device_alert(record)}


@app.post("/api/device-monitor/alerts/{alert_id}/acknowledge")
def acknowledge_device_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    record = db.query(DeviceAlert).filter(DeviceAlert.id == alert_id).first()

    if record is None:
        raise HTTPException(status_code=404, detail="Device alert not found.")

    if record.status == "RESOLVED":
        raise HTTPException(
            status_code=409,
            detail="Resolved alerts cannot be acknowledged.",
        )

    if record.status == "OPEN":
        record.status = "ACKNOWLEDGED"
        record.acknowledged_at = datetime.utcnow()
        record.acknowledged_by = str(admin.get("sub", ""))[:128]
        db.commit()
        db.refresh(record)

    return {
        "message": "Alert acknowledged.",
        "alert": serialize_device_alert(record),
    }


@app.post("/api/device-monitor/alerts/{alert_id}/resolve")
def resolve_device_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    admin: dict = Depends(get_current_admin),
):
    record = db.query(DeviceAlert).filter(DeviceAlert.id == alert_id).first()

    if record is None:
        raise HTTPException(status_code=404, detail="Device alert not found.")

    if record.status != "RESOLVED":
        record.status = "RESOLVED"
        record.resolved_at = datetime.utcnow()
        db.commit()
        db.refresh(record)

    return {
        "message": "Alert resolved.",
        "alert": serialize_device_alert(record),
    }


@app.post("/api/device-monitor/location")
def device_monitor_location(
    payload: dict,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    _device_monitor_authorize(authorization)

    device_id = str(payload.get("device_id", "")).strip()[:120]

    if not device_id:
        raise HTTPException(status_code=400, detail="device_id is required.")

    agent = (
        db.query(DeviceAgent)
        .filter(DeviceAgent.device_id == device_id)
        .first()
    )

    if agent is None:
        raise HTTPException(
            status_code=404,
            detail="Start the laptop monitor agent first, then try location sharing again.",
        )

    try:
        latitude = float(payload.get("latitude"))
        longitude = float(payload.get("longitude"))
        accuracy = float(payload.get("accuracy_m", 0))
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="Valid latitude, longitude, and accuracy are required.",
        )

    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
        raise HTTPException(status_code=400, detail="Location coordinates are out of range.")

    if accuracy < 0 or accuracy != accuracy or accuracy == float("inf"):
        raise HTTPException(status_code=400, detail="Location accuracy is invalid.")

    now = _device_monitor_datetime.utcnow()

    agent.latitude = latitude
    agent.longitude = longitude
    agent.location_accuracy_m = accuracy
    agent.location_updated_at = now

    db.commit()

    return {
        "ok": True,
        "location_updated_at": now.replace(
            tzinfo=_device_monitor_timezone.utc
        ).isoformat(),
    }


@app.get("/api/device-monitor/latest")
def device_monitor_latest(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    _device_monitor_authorize(authorization)

    agent = (
        db.query(DeviceAgent)
        .order_by(DeviceAgent.last_seen.desc())
        .first()
    )

    if agent is None:
        return {"device": None, "message": "No laptop agent has reported yet."}

    telemetry = (
        db.query(DeviceTelemetry)
        .filter(DeviceTelemetry.device_id == agent.device_id)
        .order_by(DeviceTelemetry.captured_at.desc())
        .first()
    )

    return {"device": _device_monitor_serialize(agent, telemetry)}


@app.get("/api/device-monitor/devices")
def device_monitor_devices(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    _device_monitor_authorize(authorization)

    agents = (
        db.query(DeviceAgent)
        .order_by(DeviceAgent.last_seen.desc())
        .all()
    )

    devices = []

    for agent in agents:
        telemetry = (
            db.query(DeviceTelemetry)
            .filter(DeviceTelemetry.device_id == agent.device_id)
            .order_by(DeviceTelemetry.captured_at.desc())
            .first()
        )
        devices.append(_device_monitor_serialize(agent, telemetry))

    return {
        "devices": devices,
        "total": len(devices),
        "online": sum(1 for item in devices if item["status"] == "ONLINE"),
        "offline": sum(1 for item in devices if item["status"] == "OFFLINE"),
    }


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
        restricted_processes = 0

        for process in psutil.process_iter(["pid"]):
            try:
                for conn in process.connections(kind="inet"):
                    local = conn.laddr
                    remote = conn.raddr

                    connections.append({
                        "status": conn.status,
                        "protocol": (
                            "TCP" if conn.type == 1
                            else "UDP" if conn.type == 2
                            else "OTHER"
                        ),
                        "local_ip": local.ip if local else None,
                        "local_port": local.port if local else None,
                        "remote_ip": remote.ip if remote else None,
                        "remote_port": remote.port if remote else None,
                        "pid": process.pid,
                    })

                    if len(connections) >= 100:
                        break

            except psutil.AccessDenied:
                restricted_processes += 1
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except OSError:
                restricted_processes += 1

            if len(connections) >= 100:
                break

        connection_access = (
            "permission_limited" if restricted_processes else "available"
        )

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
            "restricted_processes": restricted_processes,
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


@app.post("/api/auth/logout")
def admin_logout(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
    admin: dict = Depends(get_current_admin),
):
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authentication required")

    token_hash = hashlib.sha256(
        credentials.credentials.encode("utf-8")
    ).hexdigest()

    db = SessionLocal()
    try:
        db.add(
            RevokedToken(
                token_hash=token_hash,
                expires_at=admin["exp"],
            )
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail="Could not complete server-side logout",
        )
    finally:
        db.close()

    return {"message": "Logged out successfully"}




# =========================================================
# SENTINELAI-X RESEARCH MODEL EVALUATION
# =========================================================

@app.post("/api/x/datasets/research-evaluate")
async def evaluate_sentinel_x_dataset(
    file: UploadFile = File(...),
    label_column: Optional[str] = None,
    max_rows_per_class: int = 5000,
    include_autoencoder: bool = True,
):
    """Run SentinelAI-X supervised and unsupervised research experiments."""

    import os
    import tempfile
    import pandas as pd

    from sentinel_x.research_engine import evaluate_research_dataset

    filename = file.filename or "dataset.csv"

    if not filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Please upload a CSV file.")

    if not 100 <= max_rows_per_class <= 20000:
        raise HTTPException(
            status_code=400,
            detail="max_rows_per_class must be between 100 and 20000.",
        )

    max_bytes = 512 * 1024 * 1024
    total_bytes = 0
    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".csv",
            prefix="sentinelai_x_research_",
            delete=False,
        ) as temp:
            temp_path = temp.name

            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break

                total_bytes += len(chunk)
                if total_bytes > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail="SentinelAI-X research evaluation supports CSV files up to 512 MiB.",
                    )

                temp.write(chunk)

        if total_bytes == 0:
            raise HTTPException(status_code=400, detail="The CSV file is empty.")

        try:
            result = evaluate_research_dataset(
                temp_path,
                label_column=label_column,
                max_rows_per_class=max_rows_per_class,
                include_autoencoder=include_autoencoder,
            )
        except (ValueError, KeyError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except (UnicodeDecodeError, pd.errors.ParserError) as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Could not read the CSV: {exc}",
            ) from exc

        result["filename"] = filename
        result["upload_size_bytes"] = total_bytes
        result["upload_limit_bytes"] = max_bytes
        return result

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        await file.close()




# =========================================================
# SENTINELAI-X CONCEPT DRIFT MONITORING API
# =========================================================

from math import isfinite
from sentinel_x.drift_detector import DriftMonitor


class DriftObservationRequest(BaseModel):
    device_id: str = Field(..., min_length=1, max_length=128)
    metric: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_.-]+$",
    )
    value: float


sentinel_x_drift_monitor = DriftMonitor()


def persist_sentinel_x_observation(db, device_id, metric, value, events):
    """Persist one metric's detector state and any newly detected events."""
    from datetime import datetime

    key = f"{device_id}\\n{metric}"
    exported = sentinel_x_drift_monitor.state_dict()
    detector_state = exported.get(key)

    if detector_state is None:
        raise RuntimeError("Detector state was not available for persistence")

    record = (
        db.query(SentinelXDetectorState)
        .filter(
            SentinelXDetectorState.device_id == device_id,
            SentinelXDetectorState.metric == metric,
        )
        .first()
    )

    if record is None:
        record = SentinelXDetectorState(
            device_id=device_id,
            metric=metric,
            state=detector_state,
        )
        db.add(record)
    else:
        record.state = detector_state
        record.updated_at = datetime.utcnow()

    for event in events:
        db.add(
            SentinelXDriftEvent(
                device_id=event["device_id"],
                metric=event["metric"],
                detector=event["detector"],
                detected_at=datetime.fromisoformat(
                    event["detected_at"].replace("Z", "+00:00")
                ).replace(tzinfo=None),
                value=float(event["value"]),
                severity=event["severity"],
                message=event["message"],
            )
        )

    db.commit()


def restore_sentinel_x_monitor():
    """Restore detector states and retained event history from the database."""
    db = SessionLocal()
    try:
        state_rows = db.query(SentinelXDetectorState).all()
        saved_state = {
            f"{row.device_id}\\n{row.metric}": row.state
            for row in state_rows
        }

        if saved_state:
            sentinel_x_drift_monitor.load_state_dict(saved_state)

        event_rows = (
            db.query(SentinelXDriftEvent)
            .order_by(SentinelXDriftEvent.detected_at.desc())
            .limit(1000)
            .all()
        )

        with sentinel_x_drift_monitor._lock:
            sentinel_x_drift_monitor._events.clear()
            for row in reversed(event_rows):
                sentinel_x_drift_monitor._events.append({
                    "device_id": row.device_id,
                    "metric": row.metric,
                    "detector": row.detector,
                    "detected_at": row.detected_at.isoformat(),
                    "value": row.value,
                    "severity": row.severity,
                    "message": row.message,
                })

        logger.info(
            "SentinelAI-X restored %s detector states and %s drift events",
            len(state_rows),
            len(event_rows),
        )
    except Exception:
        db.rollback()
        logger.exception("SentinelAI-X persistence recovery failed")
    finally:
        db.close()


restore_sentinel_x_monitor()


@app.post("/api/x/drift/observe")
def observe_sentinel_x_drift(
    payload: DriftObservationRequest,
    db: Session = Depends(get_db),
):
    """Submit one device metric observation to both drift detectors."""

    device_id = payload.device_id.strip()
    metric = payload.metric.strip()

    if not device_id:
        raise HTTPException(
            status_code=422,
            detail="device_id cannot be empty.",
        )

    if not isfinite(payload.value):
        raise HTTPException(
            status_code=422,
            detail="value must be a finite number.",
        )

    try:
        events = sentinel_x_drift_monitor.update(
            device_id=device_id,
            metric=metric,
            value=payload.value,
        )
        try:
            persist_sentinel_x_observation(
                db, device_id, metric, payload.value, events
            )
        except Exception:
            db.rollback()
            logger.exception(
                "SentinelAI-X drift persistence failed for device %s",
                device_id,
            )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {
        "status": "accepted",
        "device_id": device_id,
        "metric": metric,
        "value": payload.value,
        "drift_detected": bool(events),
        "events": events,
        "monitor": sentinel_x_drift_monitor.get_status(),
    }


@app.get("/api/x/analytics/drift")
def get_sentinel_x_drift(
    device_id: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """Retrieve retained drift events and detector monitoring status."""

    if limit < 1 or limit > 1000:
        raise HTTPException(
            status_code=422,
            detail="limit must be between 1 and 1000.",
        )

    if device_id is not None and not device_id.strip():
        raise HTTPException(
            status_code=422,
            detail="device_id cannot be empty.",
        )

    query = db.query(SentinelXDriftEvent)
    if device_id:
        query = query.filter(
            SentinelXDriftEvent.device_id == device_id.strip()
        )

    rows = (
        query.order_by(SentinelXDriftEvent.detected_at.desc())
        .limit(limit)
        .all()
    )

    events = [
        {
            "device_id": row.device_id,
            "metric": row.metric,
            "detector": row.detector,
            "detected_at": row.detected_at.isoformat(),
            "value": row.value,
            "severity": row.severity,
            "message": row.message,
        }
        for row in reversed(rows)
    ]

    return {
        "monitor": sentinel_x_drift_monitor.get_status(),
        "events": events,
        "storage": "database",
    }


# SentinelAI read-only network topology API
app.include_router(network_topology_router)
