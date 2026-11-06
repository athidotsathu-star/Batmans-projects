import socket
import unittest
from unittest.mock import Mock, patch

from batman_hunter.nmap_adapter import _parse_ports, _resolve_target, run_nmap


class TargetResolutionTests(unittest.TestCase):
    def test_accepts_public_ipv4(self):
        self.assertEqual(str(_resolve_target("8.8.8.8")), "8.8.8.8")

    def test_accepts_private_lab_ipv4(self):
        self.assertEqual(str(_resolve_target("192.168.1.10")), "192.168.1.10")

    def test_accepts_loopback_for_local_tests(self):
        self.assertEqual(str(_resolve_target("127.0.0.1")), "127.0.0.1")

    def test_resolves_single_public_hostname(self):
        record = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        with patch("batman_hunter.nmap_adapter.socket.getaddrinfo", return_value=[record]):
            self.assertEqual(str(_resolve_target("example.test")), "93.184.216.34")

    def test_rejects_ambiguous_multi_address_hostname(self):
        records = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.35", 0)),
        ]
        with patch("batman_hunter.nmap_adapter.socket.getaddrinfo", return_value=records):
            with self.assertRaisesRegex(ValueError, "multiple IP addresses"):
                _resolve_target("multi.example.test")

    def test_rejects_invalid_hostname(self):
        with patch("batman_hunter.nmap_adapter.socket.getaddrinfo", side_effect=OSError):
            with self.assertRaisesRegex(ValueError, "could not be resolved"):
                _resolve_target("missing.example.test")


class PortValidationTests(unittest.TestCase):
    def test_deduplicates_ports(self):
        self.assertEqual(_parse_ports("80,443,80"), [80, 443])

    def test_rejects_invalid_port(self):
        with self.assertRaises(ValueError):
            _parse_ports("80,70000")

    def test_rejects_more_than_64_entries(self):
        with self.assertRaises(ValueError):
            _parse_ports(",".join(str(port) for port in range(1, 66)))


class NmapExecutionTests(unittest.TestCase):
    @patch("batman_hunter.nmap_adapter.subprocess.run")
    @patch("batman_hunter.nmap_adapter.shutil.which", return_value="/usr/bin/nmap")
    def test_public_target_uses_resolved_address_and_parses_xml(self, _which, run):
        run.return_value = Mock(returncode=0, stderr="", stdout=(
            '<nmaprun><host><ports><port protocol="tcp" portid="443">'
            '<state state="open" reason="syn-ack" />'
            '<service name="https" product="Example" version="1.2" />'
            '</port></ports></host></nmaprun>'
        ))
        result = run_nmap("8.8.8.8", "443")
        self.assertEqual(result["scope_type"], "public")
        self.assertEqual(result["open_ports"][0]["port"], 443)
        self.assertEqual(result["open_ports"][0]["version"], "1.2")
        command = run.call_args.args[0]
        self.assertEqual(command[-1], "8.8.8.8")
        self.assertIn("-sT", command)


if __name__ == "__main__":
    unittest.main()
