import unittest
from unittest.mock import patch
from batman_hunter.nmap_adapter import run_nmap

class NmapLabPolicyTests(unittest.TestCase):
    @patch("batman_hunter.nmap_adapter.shutil.which")
    def test_blocks_public_ip(self, which):
        with self.assertRaises(ValueError):
            run_nmap("8.8.8.8", "53")
        which.assert_not_called()

    @patch("batman_hunter.nmap_adapter.shutil.which")
    def test_blocks_link_local_ip(self, which):
        with self.assertRaises(ValueError):
            run_nmap("169.254.1.1", "80")
        which.assert_not_called()

    @patch("batman_hunter.nmap_adapter.shutil.which", return_value=None)
    def test_private_lab_ip_passes_policy_then_checks_nmap_install(self, which):
        with self.assertRaisesRegex(RuntimeError, "Nmap is not installed"):
            run_nmap("192.168.1.10", "80")
        which.assert_called_once()

if __name__ == "__main__":
    unittest.main()
