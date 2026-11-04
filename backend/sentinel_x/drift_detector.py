"""
SentinelAI-X concept drift detection.

Includes:
- AdaptiveWindowDetector: ADWIN-inspired adaptive window mean-shift detector.
- PageHinkleyDetector: cumulative change detector.
- DriftMonitor: independent per-device, per-metric monitoring.

This module uses only Python's standard library.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from math import isfinite, sqrt, log
from threading import RLock
from typing import Optional


@dataclass
class DriftEvent:
    device_id: str
    metric: str
    detector: str
    detected_at: str
    value: float
    severity: str
    message: str

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "metric": self.metric,
            "detector": self.detector,
            "detected_at": self.detected_at,
            "value": self.value,
            "severity": self.severity,
            "message": self.message,
        }


class AdaptiveWindowDetector:
    """
    ADWIN-inspired adaptive window detector.

    Tests candidate splits in a bounded observation window and detects
    sufficiently large differences between the two window means.

    This is a simplified research implementation, not River ADWIN.
    """

    def __init__(
        self,
        delta: float = 0.002,
        min_window: int = 20,
        max_window: int = 512,
        clock: int = 1,
    ):
        if not 0 < delta < 1:
            raise ValueError("delta must be between 0 and 1")
        if min_window < 4:
            raise ValueError("min_window must be at least 4")
        if max_window < min_window * 2:
            raise ValueError("max_window must be at least twice min_window")
        if clock < 1:
            raise ValueError("clock must be positive")

        self.delta = delta
        self.min_window = min_window
        self.max_window = max_window
        self.clock = clock
        self.window = deque()
        self.drift_detected = False
        self.detections = 0
        self.last_difference = 0.0
        self.samples_seen = 0

    def update(self, value: float) -> bool:
        value = float(value)
        if not isfinite(value):
            raise ValueError("Drift observations must be finite numbers")

        self.samples_seen += 1
        self.drift_detected = False
        self.window.append(value)

        while len(self.window) > self.max_window:
            self.window.popleft()

        if self.samples_seen % self.clock != 0:
            return False

        n = len(self.window)
        if n < self.min_window * 2:
            return False

        values = list(self.window)
        total = sum(values)

        # Initialize the prefix with the complete first candidate window.
        prefix = sum(values[:self.min_window])

        for cut in range(self.min_window, n - self.min_window + 1):
            left_n = cut
            right_n = n - cut

            left_mean = prefix / left_n
            right_mean = (total - prefix) / right_n

            harmonic_n = (left_n * right_n) / n
            log_term = max(1.0, log(2.0 * n / self.delta))
            threshold = sqrt(
                max(0.0, 0.5 * log_term / harmonic_n)
            )

            difference = abs(left_mean - right_mean)
            self.last_difference = difference

            if difference > threshold:
                self.drift_detected = True
                self.detections += 1

                # Retain the newer segment after a detected change.
                self.window = deque(values[cut:])
                break

            # Advance the prefix by one observation for the next split.
            if cut < n - self.min_window:
                prefix += values[cut]

        return self.drift_detected


    def state_dict(self) -> dict:
        """Return JSON-serializable adaptive-window detector state."""
        return {
            "delta": self.delta,
            "min_window": self.min_window,
            "max_window": self.max_window,
            "clock": self.clock,
            "window": list(self.window),
            "drift_detected": self.drift_detected,
            "detections": self.detections,
            "last_difference": self.last_difference,
            "samples_seen": self.samples_seen,
        }

    def load_state_dict(self, state: dict) -> None:
        """Restore a previously exported adaptive-window state."""
        if not isinstance(state, dict):
            raise ValueError("Detector state must be a dictionary")

        window = [float(value) for value in state.get("window", [])]
        if len(window) > self.max_window or any(not isfinite(v) for v in window):
            raise ValueError("Invalid adaptive-window state")

        samples_seen = int(state.get("samples_seen", 0))
        detections = int(state.get("detections", 0))
        if samples_seen < len(window) or samples_seen < 0 or detections < 0:
            raise ValueError("Invalid adaptive-window counters")

        self.window = deque(window)
        self.drift_detected = bool(state.get("drift_detected", False))
        self.detections = detections
        self.last_difference = float(state.get("last_difference", 0.0))
        self.samples_seen = samples_seen


class PageHinkleyDetector:
    """Page-Hinkley cumulative mean-change detector."""

    def __init__(
        self,
        threshold: float = 20.0,
        alpha: float = 0.005,
        min_instances: int = 30,
        direction: str = "both",
    ):
        if threshold <= 0:
            raise ValueError("threshold must be positive")
        if not 0 <= alpha < 1:
            raise ValueError("alpha must be between 0 and 1")
        if min_instances < 2:
            raise ValueError("min_instances must be at least 2")
        if direction not in {"both", "increase", "decrease"}:
            raise ValueError("direction must be both, increase or decrease")

        self.threshold = threshold
        self.alpha = alpha
        self.min_instances = min_instances
        self.direction = direction
        self.reset()

    def reset(self):
        self.count = 0
        self.mean = 0.0
        self.sum_increase = 0.0
        self.sum_decrease = 0.0
        self.min_increase = 0.0
        self.max_decrease = 0.0
        self.drift_detected = False

    def update(self, value: float) -> bool:
        value = float(value)
        if not isfinite(value):
            raise ValueError("Drift observations must be finite numbers")

        self.drift_detected = False
        self.count += 1

        self.mean += (value - self.mean) / self.count

        deviation = value - self.mean - self.alpha

        self.sum_increase += deviation
        self.sum_decrease += deviation

        self.min_increase = min(
            self.min_increase, self.sum_increase
        )
        self.max_decrease = max(
            self.max_decrease, self.sum_decrease
        )

        if self.count < self.min_instances:
            return False

        increase_change = (
            self.sum_increase - self.min_increase
        ) > self.threshold

        decrease_change = (
            self.max_decrease - self.sum_decrease
        ) > self.threshold

        if self.direction == "increase":
            self.drift_detected = increase_change
        elif self.direction == "decrease":
            self.drift_detected = decrease_change
        else:
            self.drift_detected = increase_change or decrease_change

        if self.drift_detected:
            self.reset()
            self.drift_detected = True

        return self.drift_detected


    def state_dict(self) -> dict:
        """Return JSON-serializable Page-Hinkley detector state."""
        return {
            "threshold": self.threshold,
            "alpha": self.alpha,
            "min_instances": self.min_instances,
            "direction": self.direction,
            "count": self.count,
            "mean": self.mean,
            "sum_increase": self.sum_increase,
            "sum_decrease": self.sum_decrease,
            "min_increase": self.min_increase,
            "max_decrease": self.max_decrease,
            "drift_detected": self.drift_detected,
        }

    def load_state_dict(self, state: dict) -> None:
        """Restore a previously exported Page-Hinkley state."""
        if not isinstance(state, dict):
            raise ValueError("Detector state must be a dictionary")

        count = int(state.get("count", 0))
        if count < 0:
            raise ValueError("Invalid Page-Hinkley counter")

        numeric_fields = (
            "mean", "sum_increase", "sum_decrease",
            "min_increase", "max_decrease",
        )
        values = {
            key: float(state.get(key, 0.0))
            for key in numeric_fields
        }
        if any(not isfinite(value) for value in values.values()):
            raise ValueError("Invalid Page-Hinkley state")

        self.count = count
        for key, value in values.items():
            setattr(self, key, value)
        self.drift_detected = bool(state.get("drift_detected", False))


class DriftMonitor:
    """Maintains independent drift detectors for each device and metric."""

    def __init__(
        self,
        adwin_delta: float = 0.002,
        page_hinkley_threshold: float = 20.0,
        max_events: int = 1000,
    ):
        if max_events < 1:
            raise ValueError("max_events must be positive")

        self.adwin_delta = adwin_delta
        self.page_hinkley_threshold = page_hinkley_threshold
        self.max_events = max_events

        self._detectors = {}
        self._events = deque(maxlen=max_events)
        self._lock = RLock()

    @staticmethod
    def _key(device_id: str, metric: str) -> tuple:
        if not isinstance(device_id, str) or not device_id.strip():
            raise ValueError("device_id must be a non-empty string")
        if not isinstance(metric, str) or not metric.strip():
            raise ValueError("metric must be a non-empty string")
        return device_id.strip(), metric.strip()

    def update(
        self,
        device_id: str,
        metric: str,
        value: float,
    ) -> list[dict]:
        key = self._key(device_id, metric)
        value = float(value)

        if not isfinite(value):
            raise ValueError("Drift observations must be finite numbers")

        with self._lock:
            if key not in self._detectors:
                self._detectors[key] = {
                    "adwin": AdaptiveWindowDetector(
                        delta=self.adwin_delta
                    ),
                    "page_hinkley": PageHinkleyDetector(
                        threshold=self.page_hinkley_threshold
                    ),
                }

            detectors = self._detectors[key]
            detected = []

            for name, detector in detectors.items():
                if detector.update(value):
                    event = DriftEvent(
                        device_id=key[0],
                        metric=key[1],
                        detector=name,
                        detected_at=datetime.now(
                            timezone.utc
                        ).isoformat(),
                        value=value,
                        severity="high" if name == "adwin" else "medium",
                        message=(
                            f"{name} detected a change in "
                            f"{key[1]} for device {key[0]}"
                        ),
                    )

                    event_dict = event.to_dict()
                    self._events.append(event_dict)
                    detected.append(event_dict)

            return detected


    def state_dict(self) -> dict:
        """Export all per-device detector states for durable storage."""
        with self._lock:
            result = {}
            for (device_id, metric), detectors in self._detectors.items():
                result[f"{device_id}\\n{metric}"] = {
                    name: detector.state_dict()
                    for name, detector in detectors.items()
                }
            return result

    def load_state_dict(self, state: dict) -> None:
        """Restore per-device detector states without creating new events."""
        if not isinstance(state, dict):
            raise ValueError("Monitor state must be a dictionary")

        restored = {}
        for composite_key, detector_states in state.items():
            if not isinstance(composite_key, str) or "\\n" not in composite_key:
                raise ValueError("Invalid monitor state key")

            device_id, metric = composite_key.split("\\n", 1)
            key = self._key(device_id, metric)

            if not isinstance(detector_states, dict):
                raise ValueError("Invalid detector collection")

            adaptive = AdaptiveWindowDetector(delta=self.adwin_delta)
            page_hinkley = PageHinkleyDetector(
                threshold=self.page_hinkley_threshold
            )

            if "adwin" in detector_states:
                adaptive.load_state_dict(detector_states["adwin"])
            if "page_hinkley" in detector_states:
                page_hinkley.load_state_dict(detector_states["page_hinkley"])

            restored[key] = {
                "adwin": adaptive,
                "page_hinkley": page_hinkley,
            }

        with self._lock:
            self._detectors = restored
            self._events.clear()


    def get_events(
        self,
        device_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        if limit < 1:
            raise ValueError("limit must be positive")

        with self._lock:
            events = list(self._events)

        if device_id is not None:
            events = [
                event for event in events
                if event["device_id"] == device_id
            ]

        return events[-limit:]

    def get_status(self) -> dict:
        with self._lock:
            return {
                "devices_monitored": len({
                    device_id
                    for device_id, _ in self._detectors
                }),
                "metrics_monitored": len(self._detectors),
                "events_retained": len(self._events),
                "detector_types": [
                    "adaptive_window",
                    "page_hinkley",
                ],
            }
