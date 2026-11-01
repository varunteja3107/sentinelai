import unittest

from threat_explanations import (
    explain_detection,
    match_indicator,
    normalize_indicator,
)


class ThreatExplanationTests(unittest.TestCase):
    def test_high_traffic_signals_are_reported(self):
        result = explain_detection(
            packets=1500,
            bytes_transferred=200000,
            port=3389,
            failed_attempts=15,
            threat_type="PORT_SCAN",
            anomaly_score=82,
            confidence=91,
        )

        codes = {signal["code"] for signal in result["signals"]}

        self.assertIn("HIGH_PACKET_VOLUME", codes)
        self.assertIn("HIGH_BYTE_VOLUME", codes)
        self.assertIn("REPEATED_FAILURES", codes)
        self.assertIn("SENSITIVE_SERVICE_PORT", codes)
        self.assertIn("HIGH_ANOMALY_SCORE", codes)

    def test_normal_observation_has_fallback_explanation(self):
        result = explain_detection(
            packets=20,
            bytes_transferred=5000,
            port=443,
            failed_attempts=0,
            threat_type="BENIGN",
            anomaly_score=15,
            confidence=90,
        )

        self.assertEqual(len(result["signals"]), 1)
        self.assertEqual(
            result["signals"][0]["code"],
            "NO_CONFIGURED_HEURISTIC_TRIGGERED",
        )

    def test_invalid_score_is_rejected(self):
        with self.assertRaises(ValueError):
            explain_detection(10, 1000, 443, 0, "BENIGN", 120, 90)

    def test_exact_ip_match(self):
        result = match_indicator(
            "192.0.2.10",
            ["192.0.2.10", "example.org"],
        )

        self.assertTrue(result["matched"])
        self.assertEqual(result["matches"], ["192.0.2.10"])

    def test_domain_matching_is_case_insensitive(self):
        result = match_indicator(
            "EXAMPLE.ORG.",
            ["example.org"],
        )

        self.assertTrue(result["matched"])

    def test_non_matching_indicator(self):
        result = match_indicator("example.net", ["example.org"])

        self.assertFalse(result["matched"])

    def test_invalid_indicator_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_indicator("not a valid indicator")


if __name__ == "__main__":
    unittest.main()
