import unittest
from batman_hunter.forensics import hash_bytes, analyze_failed_logons_csv
from batman_hunter.blue_team import triage_failed_logons
from batman_hunter.recon import scan_host

class ModuleTests(unittest.TestCase):
    def test_hashes(self):
        result=hash_bytes(b"abc")
        self.assertEqual(result["sha256"],"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    def test_failed_logons(self):
        csv="EventID,TargetUserName,IpAddress\n"+("4625,alice,10.0.0.5\n"*6)
        result=analyze_failed_logons_csv(csv)
        self.assertEqual(result["failed_logons"],6)
        self.assertEqual(len(triage_failed_logons(csv)["alerts"]),1)
    def test_recon_loopback_ephemeral_closed(self):
        result=scan_host("127.0.0.1",[1],.2)
        self.assertEqual(len(result["ports"]),1)

if __name__=="__main__": unittest.main()
