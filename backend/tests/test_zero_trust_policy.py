import unittest

from schemas import ZeroTrustRequest
from pydantic import ValidationError


class ZeroTrustSchemaTests(unittest.TestCase):
    def base_request(self, **overrides):
        payload = {
            "user": "test-user",
            "device": "test-device",
            "resource": "dashboard",
            "location": "trusted",
            "risk_score": 20,
            "identity_verified": True,
            "device_trusted": True,
        }
        payload.update(overrides)
        return ZeroTrustRequest(**payload)

    def test_default_risk_is_20(self):
        request = self.base_request()
        self.assertEqual(request.risk_score, 20)

    def test_zero_risk_is_valid(self):
        request = self.base_request(risk_score=0)
        self.assertEqual(request.risk_score, 0)

    def test_risk_100_is_valid(self):
        request = self.base_request(risk_score=100)
        self.assertEqual(request.risk_score, 100)

    def test_risk_above_100_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.base_request(risk_score=101)

    def test_negative_risk_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.base_request(risk_score=-1)

    def test_empty_user_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.base_request(user="")

    def test_empty_device_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.base_request(device="")

    def test_empty_resource_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.base_request(resource="")

    def test_empty_location_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.base_request(location="")


if __name__ == "__main__":
    unittest.main(verbosity=2)
