import unittest
from unittest.mock import patch

from batman_hunter.core import ScanError, report_json, validate_target, _report


class TargetValidationTests(unittest.TestCase):
    def test_adds_https_when_scheme_missing(self):
        with patch("batman_hunter.core._is_public_host", return_value=True):
            self.assertEqual(validate_target("example.com"), "https://example.com")

    def test_rejects_non_http_scheme(self):
        with self.assertRaises(ScanError):
            validate_target("ftp://example.com", allow_private=True)

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ScanError):
            validate_target("https://user:pass@example.com", allow_private=True)

    def test_blocks_loopback_by_default(self):
        with self.assertRaises(ScanError):
            validate_target("http://127.0.0.1")

    def test_allows_loopback_only_when_lab_flag_is_set(self):
        self.assertEqual(
            validate_target("http://127.0.0.1:8000", allow_private=True),
            "http://127.0.0.1:8000",
        )

    def test_report_serializes_findings_and_counts(self):
        report = _report("https://example.com", [], [], 1)
        self.assertEqual(report["summary"]["High"], 0)
        self.assertIn('"target": "https://example.com"', report_json(report))


if __name__ == "__main__":
    unittest.main()
