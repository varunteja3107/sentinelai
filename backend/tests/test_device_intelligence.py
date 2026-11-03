import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from device_intelligence import DeviceIntelligenceEngine


def normal_telemetry():
    return {
        "cpu_percent": 12,
        "memory_percent": 45,
        "disk_percent": 40,
        "network_sent_mb": 100,
        "network_recv_mb": 200,
    }


class DeviceIntelligenceTests(unittest.TestCase):

    def setUp(self):
        self.engine = DeviceIntelligenceEngine(baseline_size=30)

    def warmup(self, device_id, count=10, telemetry=None):
        sample = telemetry or normal_telemetry()
        for _ in range(count):
            self.engine.analyze(device_id, sample)

    def test_normal_activity_is_low_risk(self):
        self.warmup("mac-normal")

        result = self.engine.analyze(
            "mac-normal", normal_telemetry()
        )

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["severity"], "LOW")
        self.assertEqual(result["anomaly_count"], 0)

    def test_cpu_spike_generates_evidence(self):
        self.warmup("mac-cpu")

        data = normal_telemetry()
        data["cpu_percent"] = 90

        result = self.engine.analyze("mac-cpu", data)

        self.assertGreaterEqual(result["risk_score"], 20)
        self.assertTrue(
            any(item["metric"] == "cpu_percent"
                for item in result["evidence"])
        )

    def test_network_burst_is_detected(self):
        self.warmup("mac-network")

        data = normal_telemetry()
        data["network_sent_mb"] = 300
        data["network_recv_mb"] = 500

        result = self.engine.analyze("mac-network", data)

        self.assertEqual(result["network_delta_mb"], 500)
        self.assertTrue(
            any(item["metric"] == "network_delta_mb"
                for item in result["evidence"])
        )

    def test_repeated_disk_anomalies_increase_risk(self):
        self.warmup("mac-disk")

        results = []

        for _ in range(3):
            data = normal_telemetry()
            data["disk_percent"] = 99
            results.append(
                self.engine.analyze("mac-disk", data)
            )

        self.assertGreater(
            results[-1]["risk_score"],
            results[0]["risk_score"]
        )
        self.assertTrue(
            any(item["metric"] == "repeated_anomalies"
                for item in results[-1]["evidence"])
        )

    def test_restored_streak_triggers_repeated_anomaly_bonus(self):
        self.warmup('mac-restored-streak')
        self.engine.seed_baseline('mac-restored-streak', [normal_telemetry()] * 10, anomaly_streak=2)
        data = normal_telemetry()
        data['disk_percent'] = 99
        result = self.engine.analyze('mac-restored-streak', data)
        self.assertTrue(any(item['metric'] == 'repeated_anomalies' for item in result['evidence']))

    def test_normal_report_resets_restored_streak(self):
        self.warmup('mac-reset-streak')
        self.engine.seed_baseline('mac-reset-streak', [normal_telemetry()] * 10, anomaly_streak=2)
        result = self.engine.analyze('mac-reset-streak', normal_telemetry())
        self.assertFalse(any(item['metric'] == 'repeated_anomalies' for item in result['evidence']))

    def test_negative_restored_streak_is_rejected(self):
        with self.assertRaises(ValueError):
            self.engine.seed_baseline('mac-invalid-streak', [], anomaly_streak=-1)

    def test_devices_have_independent_baselines(self):
        self.warmup("device-a", count=8)

        device_b = {
            "cpu_percent": 70,
            "memory_percent": 80,
            "disk_percent": 60,
            "network_sent_mb": 500,
            "network_recv_mb": 700,
        }

        self.warmup("device-b", count=8, telemetry=device_b)

        result_a = self.engine.analyze(
            "device-a", normal_telemetry()
        )
        next_device_b = {**device_b, "network_sent_mb": 501, "network_recv_mb": 701}
        result_b = self.engine.analyze(
            "device-b", next_device_b
        )

        self.assertEqual(result_a["risk_score"], 0)
        self.assertEqual(result_b["risk_score"], 0)

        baseline_a = self.engine.get_device_baseline("device-a")
        baseline_b = self.engine.get_device_baseline("device-b")

        self.assertEqual(baseline_a["cpu_samples"], 9)
        self.assertEqual(baseline_b["cpu_samples"], 9)

    def test_invalid_device_id_is_rejected(self):
        with self.assertRaises(ValueError):
            self.engine.analyze("", normal_telemetry())

    def test_invalid_cpu_value_is_rejected(self):
        data = normal_telemetry()
        data["cpu_percent"] = 150

        with self.assertRaises(ValueError):
            self.engine.analyze("mac-invalid", data)

    def test_network_counter_reset_does_not_create_false_anomaly(self):
        self.warmup("mac-reboot")

        reset_data = normal_telemetry()
        reset_data["network_sent_mb"] = 5
        reset_data["network_recv_mb"] = 8

        result = self.engine.analyze("mac-reboot", reset_data)

        self.assertIsNone(result["network_delta_mb"])
        self.assertFalse(
            any(item["metric"] == "network_delta_mb"
                for item in result["evidence"])
        )

    def test_network_counter_resumes_from_reset_values(self):
        self.warmup("mac-reboot-resume")

        reset_data = normal_telemetry()
        reset_data["network_sent_mb"] = 5
        reset_data["network_recv_mb"] = 8
        self.engine.analyze("mac-reboot-resume", reset_data)

        next_data = normal_telemetry()
        next_data["network_sent_mb"] = 7
        next_data["network_recv_mb"] = 11

        result = self.engine.analyze("mac-reboot-resume", next_data)

        self.assertEqual(result["network_delta_mb"], 5)
        self.assertFalse(
            any(item["metric"] == "network_delta_mb"
                for item in result["evidence"])
        )



if __name__ == "__main__":
    unittest.main(verbosity=2)
