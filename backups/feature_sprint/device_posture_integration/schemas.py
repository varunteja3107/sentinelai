from pydantic import BaseModel
from typing import Any, Optional


class ThreatCreate(BaseModel):

    threat_type: str

    source_ip: str

    destination_ip: str

    protocol: str = "TCP"

    port: int = 0

    packets: int = 0

    bytes_transferred: int = 0


class ThreatResponse(BaseModel):

    id: int

    threat_type: str

    source_ip: str

    destination_ip: str

    protocol: str

    port: int

    packets: int

    bytes_transferred: int

    anomaly_score: float

    risk_score: float

    severity: str

    action: str

    status: str

    explanation: Optional[dict[str, Any]] = None

    class Config:
        from_attributes = True


from pydantic import Field


class ZeroTrustRequest(BaseModel):
    user: str = Field(min_length=1, max_length=128)
    device: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=256)
    location: str = Field(min_length=1, max_length=128)
    risk_score: float = Field(default=20, ge=0, le=100)
    identity_verified: bool = True
    device_trusted: bool = True
    network_trusted: bool = True
    device_compliant: bool = True
    failed_login_attempts: int = Field(default=0, ge=0, le=20)
    unusual_activity: bool = False
    session_age_minutes: int = Field(default=0, ge=0, le=10080)
    resource_sensitivity: str = Field(
        default="NORMAL",
        pattern="^(LOW|NORMAL|HIGH|CRITICAL)$"
    )


class ZeroTrustResponse(BaseModel):
    decision: str
    risk_score: float
    identity: str
    device: str
    context: str
    reason: str
    risk_breakdown: dict[str, Any] = Field(default_factory=dict)
    policy_threshold: str = ""


class ResponsePlaybookRequest(BaseModel):
    threat_type: str = Field(min_length=1, max_length=100)
    severity: str = Field(default="MEDIUM", max_length=20)
    risk_score: float = Field(default=0, ge=0, le=100)
class ResponseActionCreate(BaseModel):
    incident_id: Optional[int] = Field(default=None, ge=1)
    threat_type: str = Field(min_length=1, max_length=100)
    risk_score: float = Field(ge=0, le=100)
    recommended_action: str = Field(min_length=1, max_length=500)
    requested_by: str = Field(default="system", min_length=1, max_length=128)


class ResponseActionReview(BaseModel):
    reviewed_by: str = Field(min_length=1, max_length=128)
    decision: str = Field(pattern="^(APPROVED|REJECTED)$")
    review_note: str = Field(default="", max_length=2000)


class ResponseActionRollback(BaseModel):
    reviewed_by: str = Field(min_length=1, max_length=128)
    review_note: str = Field(default="", max_length=2000)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    username: str
    role: str
