import unittest

from response_playbooks import recommend_response


class ResponsePlaybookTests(unittest.TestCase):
    def test_port_scan_recommends_investigation(self):
        result = recommend_response("PORT_SCAN", "MEDIUM", 40)
        self.assertEqual(result["playbook_title"], "Port-scan investigation")
        self.assertFalse(result["approval_required"])

    def test_critical_risk_requires_approval(self):
        result = recommend_response("PORT_SCAN", "MEDIUM", 85)
        self.assertTrue(result["approval_required"])
        self.assertEqual(result["severity"], "CRITICAL")

    def test_ddos_recommends_approval(self):
        result = recommend_response("DDoS", "HIGH", 70)
        self.assertTrue(result["approval_required"])
        self.assertTrue(result["simulation_mode"])

    def test_unknown_threat_uses_fallback(self):
        result = recommend_response("UNRECOGNIZED_EVENT")
        self.assertEqual(
            result["playbook_title"],
            "General threat investigation",
        )

    def test_risk_above_100_is_rejected(self):
        with self.assertRaises(ValueError):
            recommend_response("PORT_SCAN", risk_score=101)

    def test_negative_risk_is_rejected(self):
        with self.assertRaises(ValueError):
            recommend_response("PORT_SCAN", risk_score=-1)

    def test_module_does_not_execute_actions(self):
        result = recommend_response("MALWARE", "CRITICAL", 90)
        self.assertEqual(result["execution_mode"], "RECOMMENDATION_ONLY")
        self.assertIn("No firewall", result["limitation"])


if __name__ == "__main__":
    unittest.main()
