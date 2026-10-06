from pydantic import BaseModel


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

    class Config:
        from_attributes = True


class ZeroTrustRequest(BaseModel):

    user: str

    device: str

    resource: str

    location: str

    risk_score: float = 20

    identity_verified: bool = True

    device_trusted: bool = True


class ZeroTrustResponse(BaseModel):

    decision: str

    risk_score: float

    identity: str

    device: str

    context: str

    reason: str
