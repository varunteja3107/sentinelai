"""Explainable, per-device anomaly detection and risk scoring."""

from collections import deque
from statistics import median
from threading import RLock
from typing import Any


class DeviceIntelligenceEngine:
    """Maintains independent rolling baselines for registered devices."""

    def __init__(self, baseline_size: int = 30):
        if baseline_size < 5:
            raise ValueError("baseline_size must be at least 5")

        self.baseline_size = baseline_size
        self._history = {}
        self._lock = RLock()

    @staticmethod
    def _number(value):
        try:
            result = float(value)
            if result != result or result in (float("inf"), float("-inf")):
                return None
            return result
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _severity(score):
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        return "LOW"

    def _device_history(self, device_id):
        if device_id not in self._history:
            self._history[device_id] = {
                "cpu": deque(maxlen=self.baseline_size),
                "memory": deque(maxlen=self.baseline_size),
                "disk": deque(maxlen=self.baseline_size),
                "network": deque(maxlen=self.baseline_size),
                "last_network_sent": None,
                "last_network_recv": None,
                "anomaly_streak": 0,
            }
        return self._history[device_id]

    def seed_baseline(self, device_id: str, samples, anomaly_streak: int = 0):
        """Load historical telemetry without scoring historical anomalies."""

        if not isinstance(device_id, str) or not device_id.strip():
            raise ValueError("A valid device_id is required")

        with self._lock:
            state = self._device_history(device_id)

            # Reset this device's baseline before loading persisted history.
            for key in ("cpu", "memory", "disk", "network"):
                state[key].clear()

            state["last_network_sent"] = None
            state["last_network_recv"] = None
            if isinstance(anomaly_streak, bool) or not isinstance(anomaly_streak, int) or anomaly_streak < 0:
                raise ValueError("anomaly_streak must be a non-negative integer")
            state["anomaly_streak"] = anomaly_streak

            previous_sent = None
            previous_received = None

            for sample in samples:
                metrics = {
                    key: self._number(sample.get(key))
                    for key in (
                        "cpu_percent",
                        "memory_percent",
                        "disk_percent",
                        "network_sent_mb",
                        "network_recv_mb",
                    )
                }

                for metric in ("cpu_percent", "memory_percent", "disk_percent"):
                    value = metrics[metric]
                    if value is not None:
                        if not 0 <= value <= 100:
                            raise ValueError(f"{metric} must be between 0 and 100")

                for metric, history_name in (
                    ("cpu_percent", "cpu"),
                    ("memory_percent", "memory"),
                    ("disk_percent", "disk"),
                ):
                    value = metrics[metric]
                    if value is not None:
                        state[history_name].append(value)

                sent = metrics["network_sent_mb"]
                received = metrics["network_recv_mb"]

                if sent is not None and received is not None:
                    if previous_sent is not None and previous_received is not None:
                        delta_sent = sent - previous_sent
                        delta_received = received - previous_received

                        if delta_sent >= 0 and delta_received >= 0:
                            state["network"].append(
                                delta_sent + delta_received
                            )

                    previous_sent = sent
                    previous_received = received

            state["last_network_sent"] = previous_sent
            state["last_network_recv"] = previous_received

            return self.get_device_baseline(device_id)

    def analyze(self, device_id: str, telemetry: dict[str, Any]):
        if not isinstance(device_id, str) or not device_id.strip():
            raise ValueError("A valid device_id is required")

        metrics = {
            key: self._number(telemetry.get(key))
            for key in (
                "cpu_percent",
                "memory_percent",
                "disk_percent",
                "network_sent_mb",
                "network_recv_mb",
            )
        }

        for key in ("cpu_percent", "memory_percent", "disk_percent"):
            value = metrics[key]
            if value is not None and not 0 <= value <= 100:
                raise ValueError(f"{key} must be between 0 and 100")

        with self._lock:
            state = self._device_history(device_id)
            evidence = []
            score = 0
            network_delta = None

            weights = {
                "cpu_percent": 20,
                "memory_percent": 20,
                "disk_percent": 10,
            }

            for metric, history_name in (
                ("cpu_percent", "cpu"),
                ("memory_percent", "memory"),
                ("disk_percent", "disk"),
            ):
                value = metrics[metric]
                history = state[history_name]

                if value is None:
                    continue

                # Fixed safety indicators do not alone imply malware.
                if metric == "disk_percent" and value >= 95:
                    score += 10
                    evidence.append({
                        "metric": metric,
                        "value": value,
                        "reason": "Disk capacity is critically high",
                    })

                if len(history) >= 5:
                    baseline = median(history)
                    deviation = value - baseline

                    if metric in ("cpu_percent", "memory_percent"):
                        threshold = max(25.0, baseline * 0.75)
                    else:
                        threshold = 15.0

                    if deviation >= threshold:
                        points = weights[metric]
                        score += points
                        evidence.append({
                            "metric": metric,
                            "value": round(value, 2),
                            "baseline": round(baseline, 2),
                            "deviation": round(deviation, 2),
                            "reason": "Metric is unusually elevated versus device baseline",
                        })

                history.append(value)

            sent = metrics["network_sent_mb"]
            received = metrics["network_recv_mb"]

            if sent is not None and received is not None:
                previous_sent = state["last_network_sent"]
                previous_received = state["last_network_recv"]

                if previous_sent is not None and previous_received is not None:
                    delta_sent = sent - previous_sent
                    delta_received = received - previous_received

                    if delta_sent >= 0 and delta_received >= 0:
                        network_delta = round(
                            delta_sent + delta_received, 2
                        )

                        network_history = state["network"]

                        if len(network_history) >= 5:
                            baseline = median(network_history)

                            if (
                                network_delta > 1.0
                                and network_delta > max(50.0, baseline * 4)
                            ):
                                score += 25
                                evidence.append({
                                    "metric": "network_delta_mb",
                                    "value": network_delta,
                                    "baseline": round(baseline, 2),
                                    "reason": "Network activity is unusually high versus device baseline",
                                })

                        network_history.append(network_delta)

                state["last_network_sent"] = sent
                state["last_network_recv"] = received

            if evidence:
                state["anomaly_streak"] += 1
            else:
                state["anomaly_streak"] = 0

            if state["anomaly_streak"] >= 3:
                score += 15
                evidence.append({
                    "metric": "repeated_anomalies",
                    "value": state["anomaly_streak"],
                    "reason": "Anomalies persisted across consecutive reports",
                })

            score = min(100, max(0, score))

            samples = min(
                len(state["cpu"]),
                len(state["memory"]),
                len(state["disk"]),
            )

            confidence = (
                "LOW" if samples < 5
                else "MEDIUM" if samples < 15
                else "HIGH"
            )

            return {
                "device_id": device_id,
                "risk_score": score,
                "severity": self._severity(score),
                "confidence": confidence,
                "baseline_samples": samples,
                "anomaly_count": len(evidence),
                "evidence": evidence,
                "network_delta_mb": network_delta,
                "recommended_action": (
                    "INVESTIGATE" if score >= 50
                    else "MONITOR" if score >= 25
                    else "CONTINUE_MONITORING"
                ),
            }

    def get_device_baseline(self, device_id):
        with self._lock:
            state = self._history.get(device_id)
            if state is None:
                return None

            return {
                "device_id": device_id,
                "cpu_samples": len(state["cpu"]),
                "memory_samples": len(state["memory"]),
                "disk_samples": len(state["disk"]),
                "network_samples": len(state["network"]),
            }
