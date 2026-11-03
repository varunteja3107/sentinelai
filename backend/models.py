from sqlalchemy import Column, Integer, String, Float, DateTime, Index, Boolean
from datetime import datetime

from database import Base


class Threat(Base):

    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)

    threat_type = Column(String, nullable=False)

    source_ip = Column(String, nullable=False)

    destination_ip = Column(String, nullable=False)

    protocol = Column(String, default="TCP")

    port = Column(Integer, default=0)

    packets = Column(Integer, default=0)

    bytes_transferred = Column(Integer, default=0)

    anomaly_score = Column(Float, default=0)

    risk_score = Column(Float, default=0)

    severity = Column(String, default="LOW")

    action = Column(String, default="ALLOW")

    status = Column(String, default="OPEN")

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


class Device(Base):

    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(String)

    ip_address = Column(String)

    device_type = Column(String)

    trust_score = Column(Float, default=100)

    status = Column(String, default="ONLINE")

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


class Incident(Base):

    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)

    title = Column(String)

    severity = Column(String)

    risk_score = Column(Float)

    status = Column(String, default="OPEN")
    notes = Column(String, default="")

    threat_id = Column(Integer)

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


class AuditLog(Base):

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    event_type = Column(String)

    message = Column(String)

    severity = Column(String, default="INFO")

    source_ip = Column(String, default="")

    action = Column(String, default="")

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )
class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, nullable=True, index=True)
    threat_type = Column(String, nullable=False)
    risk_score = Column(Float, default=0)
    recommended_action = Column(String, nullable=False)
    status = Column(String, default="PENDING", nullable=False)
    requested_by = Column(String, default="system", nullable=False)
    reviewed_by = Column(String, default="")
    review_note = Column(String, default="")
    simulation_mode = Column(Integer, default=1, nullable=False)
    rollback_status = Column(String, default="NOT_APPLICABLE")
    created_at = Column(DateTime, default=datetime.utcnow)
    reviewed_at = Column(DateTime, nullable=True)
    rolled_back_at = Column(DateTime, nullable=True)


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    expires_at = Column(Integer, nullable=False)
    revoked_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user = Column(String(128), nullable=False)
    device = Column(String(128), nullable=False)
    resource = Column(String(256), nullable=False)
    location = Column(String(128), default="Unknown")
    risk_score = Column(Float, default=0)
    decision = Column(String(20), default="ALLOW")
    identity_verified = Column(Integer, default=1)
    device_trusted = Column(Integer, default=1)
    network_trusted = Column(Integer, default=1)
    device_compliant = Column(Integer, default=1)
    device_posture_score = Column(Integer, default=100)
    failed_login_attempts = Column(Integer, default=0)
    unusual_activity = Column(Integer, default=0)
    session_age_minutes = Column(Integer, default=0)
    resource_sensitivity = Column(String(20), default="NORMAL")
    status = Column(String(20), default="ACTIVE")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class SessionEvent(Base):
    __tablename__ = "session_events"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, nullable=False, index=True)
    event_type = Column(String(50), nullable=False)
    message = Column(String(500), default="")
    risk_score = Column(Float, default=0)
    decision = Column(String(20), default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class FirewallRule(Base):
    __tablename__ = "firewall_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    source = Column(String(128), default="Any", nullable=False)
    destination = Column(String(128), default="Any", nullable=False)
    port = Column(String(32), nullable=False)
    protocol = Column(String(16), default="TCP", nullable=False)
    action = Column(String(16), default="BLOCK", nullable=False)
    status = Column(String(16), default="ACTIVE", nullable=False)
    priority = Column(Integer, default=50, nullable=False)
    description = Column(String(500), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

class BlockSpikeAlert(Base):
    __tablename__ = "block_spike_alerts"

    id = Column(Integer, primary_key=True, index=True)
    detection_key = Column(String(64), unique=True, nullable=False, index=True)
    severity = Column(String(20), nullable=False)
    latest_block_count = Column(Integer, nullable=False)
    baseline_average = Column(Float, nullable=False)
    detection_threshold = Column(Float, nullable=False)
    status = Column(String(20), default="OPEN", nullable=False)
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String(128), default="", nullable=False)


class DeviceAgent(Base):
    __tablename__ = "device_agents"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(120), unique=True, nullable=False, index=True)
    device_name = Column(String(160), nullable=False)
    platform = Column(String(80), default="Unknown")
    os_version = Column(String(120), default="")
    local_ip = Column(String(64), default="")
    status = Column(String(20), default="OFFLINE", nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, nullable=True, index=True)

    # Location is optional and only populated through explicit browser consent.
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    location_accuracy_m = Column(Float, nullable=True)
    location_updated_at = Column(DateTime, nullable=True)


class DeviceTelemetry(Base):
    __tablename__ = "device_telemetry"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(120), nullable=False, index=True)
    cpu_percent = Column(Float, nullable=True)
    cpu_cores = Column(Integer, nullable=True)
    memory_percent = Column(Float, nullable=True)
    memory_used_gb = Column(Float, nullable=True)
    memory_total_gb = Column(Float, nullable=True)
    disk_percent = Column(Float, nullable=True)
    battery_percent = Column(Float, nullable=True)
    battery_power_plugged = Column(Integer, nullable=True)
    network_sent_mb = Column(Float, nullable=True)
    network_recv_mb = Column(Float, nullable=True)
    captured_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


Index(
    "ix_device_telemetry_device_captured",
    DeviceTelemetry.device_id,
    DeviceTelemetry.captured_at,
)


class AdminUser(Base):
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(128), nullable=False, unique=True, index=True)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), nullable=False, default="admin")
    is_active = Column(Boolean, nullable=False, default=True)
    created_by = Column(String(128), nullable=False, default="bootstrap")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
