"""Smoke tests for the local dashboard routes."""
import unittest

from batman_hunter.web import app


class DashboardTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_dashboard_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"New assessment", response.data)

    def test_crypto_lab_loads(self):
        response = self.client.get("/crypto")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Encrypt / decrypt", response.data)

    def test_scan_requires_authorization(self):
        response = self.client.post("/scan", data={"target": "http://127.0.0.1:8000"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Confirm that you own this target", response.data)

    def test_crypto_encrypt_route(self):
        response = self.client.post("/crypto", data={
            "mode": "encrypt",
            "plaintext": "dashboard test",
            "passphrase": "correct horse battery staple",
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"BBH1.", response.data)


if __name__ == "__main__":
    unittest.main()
