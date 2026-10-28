import json
import unittest
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:8000"


def post_json(path, payload):
    request = urllib.request.Request(
        BASE_URL + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, json.loads(
                response.read().decode("utf-8")
            )
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            pass
        return exc.code, body


class ThreatAnalysisTests(unittest.TestCase):

    def test_valid_event_returns_threat_record(self):
        status, body = post_json(
            "/api/threats/analyze",
            {
                "threat_type": "TEST_BENIGN_TRAFFIC",
                "source_ip": "192.0.2.10",
                "destination_ip": "192.0.2.20",
                "protocol": "TCP",
                "port": 443,
                "packets": 10,
                "bytes_transferred": 1200,
            },
        )

        self.assertEqual(status, 200, body)

        for field in (
            "id",
            "threat_type",
            "source_ip",
            "destination_ip",
            "anomaly_score",
            "risk_score",
            "severity",
            "action",
            "status",
        ):
            self.assertIn(field, body)

        self.assertEqual(body["threat_type"], "TEST_BENIGN_TRAFFIC")
        self.assertEqual(body["status"], "OPEN")
        self.assertGreaterEqual(body["risk_score"], 0)
        self.assertLessEqual(body["risk_score"], 100)

    def test_sensitive_port_event_returns_valid_scores(self):
        status, body = post_json(
            "/api/threats/analyze",
            {
                "threat_type": "TEST_SUSPICIOUS_EVENT",
                "source_ip": "192.0.2.30",
                "destination_ip": "192.0.2.40",
                "protocol": "TCP",
                "port": 3389,
                "packets": 950,
                "bytes_transferred": 85000,
            },
        )

        self.assertEqual(status, 200, body)
        self.assertGreaterEqual(body["risk_score"], 0)
        self.assertLessEqual(body["risk_score"], 100)
        self.assertIn(
            body["severity"].upper(),
            {"LOW", "MEDIUM", "HIGH", "CRITICAL"},
        )
        self.assertIn(
            body["action"].upper(),
            {"ALLOW", "MFA", "LIMIT", "BLOCK"},
        )
        self.assertEqual(body["status"], "OPEN")

    def test_missing_required_fields_are_rejected(self):
        status, body = post_json(
            "/api/threats/analyze",
            {"threat_type": "INCOMPLETE_TEST"},
        )

        self.assertEqual(status, 422, body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
