import unittest
from batman_hunter.lab_testing import _validate_lab_url
from batman_hunter.risk import score_findings
from batman_hunter.windows_events import analyze_auth_events_csv
from batman_hunter.html_reporting import build_html

class V3Tests(unittest.TestCase):
    def test_lab_rejects_public_target(self):
        with self.assertRaises(ValueError): _validate_lab_url("https://example.com/?q=test")
    def test_lab_accepts_loopback(self):
        self.assertIn("127.0.0.1",_validate_lab_url("http://127.0.0.1:3000/?q=test"))
    def test_risk_priority(self):
        result=score_findings([{"severity":"High","confidence":"High"}])
        self.assertEqual(result["highest_priority"],"P2")
    def test_auth_ip_correlation(self):
        csv="EventID,TargetUserName,IpAddress,TimeCreated\n"+("4625,alice,10.0.0.9,2026-01-01T00:00:00Z\n"*6)+"4624,alice,10.0.0.9,2026-01-01T00:01:00Z\n"
        result=analyze_auth_events_csv(csv)
        self.assertEqual(result["alerts"][0]["successful_logons_same_ip"],1)
    def test_html_report_escapes(self):
        report=build_html("<script>x</script>",{"a":"<x>"},[])
        self.assertNotIn("<script>x</script>",report)
        self.assertIn("&lt;script&gt;",report)

if __name__=="__main__": unittest.main()
