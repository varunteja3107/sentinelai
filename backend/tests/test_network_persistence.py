import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base
from models import DeviceAlert, SentinelXNetworkObservation
from device_intelligence_service import assess_network_and_persist


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)

    TestingSession = sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False,
    )
    session = TestingSession()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


DEVICE_ID = "test-network-device"

ENDPOINT = {
    "remote_ip": "203.0.113.90",
    "remote_port": 8443,
    "protocol": "TCP",
}


def add_observation(db, connections):
    observation = SentinelXNetworkObservation(
        device_id=DEVICE_ID,
        connections=connections,
        connection_count=len(connections),
        restricted_processes=0,
        warnings=[],
    )
    db.add(observation)
    db.commit()
    db.refresh(observation)

    result = assess_network_and_persist(db, observation)
    return observation, result


def test_historical_finding_creates_database_alert(db):
    for _ in range(4):
        add_observation(db, [ENDPOINT])

    alerts = db.query(DeviceAlert).filter(
        DeviceAlert.device_id == DEVICE_ID,
        DeviceAlert.anomaly_type == "network_historical_endpoint_recurrence",
    ).all()

    assert len(alerts) == 1
    assert alerts[0].status == "OPEN"
    assert alerts[0].evidence[0]["observation_count"] == 4


def test_recurring_finding_updates_existing_alert(db):
    for _ in range(5):
        add_observation(db, [ENDPOINT])

    alerts = db.query(DeviceAlert).filter(
        DeviceAlert.device_id == DEVICE_ID,
        DeviceAlert.anomaly_type == "network_historical_endpoint_recurrence",
    ).all()

    assert len(alerts) == 1
    assert alerts[0].evidence[0]["observation_count"] == 5


def test_alert_resolves_after_three_missing_snapshots(db):
    for _ in range(4):
        add_observation(db, [ENDPOINT])

    alert = db.query(DeviceAlert).filter(
        DeviceAlert.device_id == DEVICE_ID,
        DeviceAlert.anomaly_type == "network_historical_endpoint_recurrence",
    ).one()

    add_observation(db, [])
    db.refresh(alert)
    assert alert.status == "OPEN"

    add_observation(db, [])
    db.refresh(alert)
    assert alert.status == "OPEN"

    add_observation(db, [])
    db.refresh(alert)
    assert alert.status == "RESOLVED"
    assert alert.resolved_at is not None


def test_acknowledged_alert_stays_acknowledged_while_active(db):
    for _ in range(4):
        add_observation(db, [ENDPOINT])

    alert = db.query(DeviceAlert).filter(
        DeviceAlert.device_id == DEVICE_ID,
        DeviceAlert.anomaly_type == "network_historical_endpoint_recurrence",
    ).one()

    alert.status = "ACKNOWLEDGED"
    alert.acknowledged_by = "test-admin"
    db.commit()

    add_observation(db, [ENDPOINT])
    db.refresh(alert)

    assert alert.status == "ACKNOWLEDGED"
    assert alert.acknowledged_by == "test-admin"


def test_multiple_historical_endpoints_do_not_create_critical_risk(db):
    endpoints = [
        {
            "remote_ip": f"203.0.113.{number}",
            "remote_port": 443,
            "protocol": "TCP",
        }
        for number in range(100, 108)
    ]

    for _ in range(4):
        add_observation(db, endpoints)

    alert = db.query(DeviceAlert).filter(
        DeviceAlert.device_id == DEVICE_ID,
        DeviceAlert.anomaly_type == "network_historical_endpoint_recurrence",
    ).one()

    assert alert.risk_score == 5
    assert alert.severity == "LOW"
    assert len(alert.evidence) == 8


def test_connection_volume_spike_creates_and_updates_one_alert(db):
    def connections(count):
        return [
            {
                "remote_ip": f"198.51.100.{index}",
                "remote_port": 443,
                "protocol": "TCP",
            }
            for index in range(1, count + 1)
        ]

    for _ in range(4):
        add_observation(db, connections(10))

    add_observation(db, connections(50))

    alert_type = "network_connection_volume_spike"

    alerts = db.query(DeviceAlert).filter(
        DeviceAlert.device_id == DEVICE_ID,
        DeviceAlert.anomaly_type == alert_type,
        DeviceAlert.status == "OPEN",
    ).all()

    assert len(alerts) == 1
    assert alerts[0].severity == "MEDIUM"
    assert alerts[0].risk_score == 15

    first_detected = alerts[0].first_detected_at

    add_observation(db, connections(50))

    alerts = db.query(DeviceAlert).filter(
        DeviceAlert.device_id == DEVICE_ID,
        DeviceAlert.anomaly_type == alert_type,
        DeviceAlert.status == "OPEN",
    ).all()

    assert len(alerts) == 1
    assert alerts[0].first_detected_at == first_detected
    assert alerts[0].risk_score == 15
    assert alerts[0].severity == "MEDIUM"
