from sqlalchemy import Column, Integer, String, Float, DateTime
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
