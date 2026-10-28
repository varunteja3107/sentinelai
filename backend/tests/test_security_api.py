import os
import unittest
import urllib.error
import urllib.parse
import urllib.request
import json

BASE_URL = os.getenv("SENTINELAI_API", "http://127.0.0.1:8000")


def request_json(path, method="GET", payload=None):
    data = None
    headers = {}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"detail": body}
        return exc.code, parsed


class SentinelAISecurityTests(unittest.TestCase):

    def test_health_endpoint(self):
        status, body = request_json("/api/health")
        self.assertEqual(status, 200, body)

    def test_zero_trust_blocks_unverified_identity(self):
        status, body = request_json(
            "/api/zero-trust/check",
            "POST",
            {
                "user": "test-user",
                "device": "test-device",
                "resource": "test-resource",
                "location": "trusted",
                "risk_score": 0,
                "identity_verified": False,
                "device_trusted": True,
            },
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("decision"), "BLOCK")
        self.assertEqual(body.get("risk_score"), 100)

    def test_zero_trust_blocks_high_risk(self):
        status, body = request_json(
            "/api/zero-trust/check",
            "POST",
            {
                "user": "test-user",
                "device": "test-device",
                "resource": "test-resource",
                "location": "trusted",
                "risk_score": 85,
                "identity_verified": True,
                "device_trusted": True,
            },
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("decision"), "BLOCK")

    def test_firewall_known_telnet_rule(self):
        status, body = request_json(
            "/api/firewall/evaluate?port=23&protocol=TCP",
            method="POST",
        )
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("matched"), body)
        self.assertEqual(body.get("action"), "BLOCK")

    def test_firewall_known_dns_rule(self):
        status, body = request_json(
            "/api/firewall/evaluate?port=53&protocol=UDP",
            method="POST",
        )
        self.assertEqual(status, 200, body)
        self.assertTrue(body.get("matched"), body)
        self.assertEqual(body.get("action"), "ALLOW")

    def test_firewall_blocks_unmatched_traffic(self):
        status, body = request_json(
            "/api/firewall/evaluate?port=45678&protocol=TCP",
            method="POST",
        )
        self.assertEqual(status, 200, body)
        self.assertFalse(body.get("matched"), body)
        self.assertEqual(body.get("action"), "BLOCK")
        self.assertEqual(body.get("rule"), "Default Deny Policy")

    def test_live_system_telemetry(self):
        status, body = request_json("/api/live/system")
        self.assertEqual(status, 200, body)
        self.assertEqual(body.get("source"), "local_machine")
        self.assertIn("cpu_percent", body)
        self.assertIn("memory", body)
        self.assertIn("disk", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
