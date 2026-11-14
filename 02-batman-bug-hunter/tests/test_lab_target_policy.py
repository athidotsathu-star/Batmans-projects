import unittest
from unittest.mock import patch

from batman_hunter.target_policy import is_lab_ip, resolve_target, TargetPolicyError
from batman_hunter.recon import scan_host

class LabTargetPolicyTests(unittest.TestCase):
    def test_accepts_rfc1918_loopback_and_ula(self):
        for ip in ("10.2.3.4", "172.16.0.1", "192.168.1.20", "127.0.0.1", "::1", "fd12:3456::1"):
            self.assertTrue(is_lab_ip(ip), ip)

    def test_rejects_link_local_and_public(self):
        for ip in ("169.254.1.2", "8.8.8.8", "1.1.1.1", "fe80::1", "2001:4860:4860::8888"):
            self.assertFalse(is_lab_ip(ip), ip)

    @patch("batman_hunter.target_policy.socket.getaddrinfo")
    def test_rejects_mixed_public_and_private_dns_answers(self, resolver):
        resolver.return_value = [
            (2, 1, 6, "", ("192.168.1.10", 0)),
            (2, 1, 6, "", ("8.8.8.8", 0)),
        ]
        with self.assertRaises(TargetPolicyError):
            resolve_target("lab.example", allow_private=True)

    @patch("batman_hunter.target_policy.socket.getaddrinfo")
    def test_private_lab_hostname_returns_only_validated_addresses(self, resolver):
        resolver.return_value = [(2, 1, 6, "", ("192.168.1.10", 0))]
        self.assertEqual(resolve_target("lab.example", allow_private=True), ("192.168.1.10",))

    def test_recon_rejects_public_literal_before_probing(self):
        with self.assertRaises(ValueError):
            scan_host("8.8.8.8", [53])

    def test_recon_rejects_url_input(self):
        with self.assertRaises(ValueError):
            scan_host("http://192.168.1.10", [80])

    def test_recon_rejects_empty_port_list(self):
        with self.assertRaises(ValueError):
            scan_host("127.0.0.1", [])

if __name__ == "__main__":
    unittest.main()
