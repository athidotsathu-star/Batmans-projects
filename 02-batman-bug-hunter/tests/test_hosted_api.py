"""Smoke tests for the hosted API's authentication and ownership gate."""
import os
import tempfile
import unittest

_TEMP = tempfile.TemporaryDirectory()
os.environ["DATABASE_PATH"] = os.path.join(_TEMP.name, "test.sqlite3")
os.environ["FRONTEND_ORIGIN"] = "https://batman-bug-hunter.pages.dev"

from batman_hunter.hosted_api import APP

class HostedApiTests(unittest.TestCase):
    def setUp(self):
        APP.config.update(TESTING=True)
        self.client = APP.test_client()
        self.email = "test-user@example.invalid"
        self.password = "a-long-test-password-123"

    def register_and_login(self):
        self.client.post("/api/auth/register", json={"email":self.email,"password":self.password})
        response = self.client.post("/api/auth/login", json={"email":self.email,"password":self.password})
        self.assertEqual(response.status_code, 200)
        self.token = response.get_json()["token"]
        self.headers = {"Authorization":"Bearer "+self.token}

    def test_health_is_public(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")

    def test_registration_and_login(self):
        response = self.client.post("/api/auth/register", json={"email":self.email,"password":self.password})
        self.assertEqual(response.status_code, 201)
        response = self.client.post("/api/auth/login", json={"email":self.email,"password":self.password})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["token"])

    def test_password_minimum_is_enforced(self):
        response = self.client.post("/api/auth/register", json={"email":"short@example.invalid","password":"short"})
        self.assertEqual(response.status_code, 400)

    def test_reports_require_authentication(self):
        response = self.client.get("/api/reports")
        self.assertEqual(response.status_code, 401)

    def test_scan_requires_verified_domain(self):
        self.register_and_login()
        response = self.client.post("/api/scan", json={"target":"https://example.com"}, headers=self.headers)
        self.assertEqual(response.status_code, 403)
        self.assertIn("Verify ownership", response.get_json()["error"])

    def test_challenge_is_account_scoped(self):
        self.register_and_login()
        response = self.client.post("/api/targets/challenge", json={"hostname":"example.com"}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["record_type"], "TXT")
        self.assertEqual(response.get_json()["record_name"], "_batman-bug-hunter.example.com")

if __name__ == "__main__":
    unittest.main()
