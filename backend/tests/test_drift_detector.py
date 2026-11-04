import pytest

from sentinel_x.drift_detector import (
    AdaptiveWindowDetector,
    PageHinkleyDetector,
    DriftMonitor,
)


def test_adaptive_window_detects_sudden_shift():
    detector = AdaptiveWindowDetector(
        delta=0.01,
        min_window=10,
        max_window=200,
    )

    for _ in range(60):
        detector.update(0.0)

    detected = False
    for _ in range(60):
        if detector.update(5.0):
            detected = True
            break

    assert detected
    assert detector.detections >= 1


def test_adaptive_window_stable_stream_does_not_drift():
    detector = AdaptiveWindowDetector(
        delta=0.01,
        min_window=10,
        max_window=200,
    )

    results = [detector.update(1.0) for _ in range(100)]

    assert not any(results)


def test_page_hinkley_detects_increase():
    detector = PageHinkleyDetector(
        threshold=5,
        alpha=0.001,
        min_instances=10,
        direction="increase",
    )

    for _ in range(50):
        detector.update(1.0)

    detected = False
    for _ in range(30):
        if detector.update(10.0):
            detected = True
            break

    assert detected


def test_page_hinkley_detects_decrease():
    detector = PageHinkleyDetector(
        threshold=5,
        alpha=0.001,
        min_instances=10,
        direction="decrease",
    )

    for _ in range(50):
        detector.update(10.0)

    detected = False
    for _ in range(30):
        if detector.update(1.0):
            detected = True
            break

    assert detected


def test_monitor_keeps_devices_independent():
    monitor = DriftMonitor()

    for _ in range(30):
        monitor.update("device-A", "cpu", 10.0)

    for _ in range(30):
        monitor.update("device-B", "cpu", 10.0)

    status = monitor.get_status()

    assert status["devices_monitored"] == 2
    assert status["metrics_monitored"] == 2


def test_monitor_records_drift_events():
    monitor = DriftMonitor(
        adwin_delta=0.01,
        page_hinkley_threshold=5,
    )

    for _ in range(60):
        monitor.update("device-A", "network_bytes", 0.0)

    for _ in range(60):
        monitor.update("device-A", "network_bytes", 10.0)

    events = monitor.get_events(device_id="device-A")

    assert len(events) >= 1
    assert all(event["device_id"] == "device-A" for event in events)
    assert all(event["metric"] == "network_bytes" for event in events)


def test_monitor_rejects_invalid_values():
    monitor = DriftMonitor()

    with pytest.raises(ValueError):
        monitor.update("device-A", "cpu", float("nan"))

    with pytest.raises(ValueError):
        monitor.update("device-A", "cpu", float("inf"))


def test_detector_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        AdaptiveWindowDetector(delta=1.5)

    with pytest.raises(ValueError):
        PageHinkleyDetector(threshold=-1)
