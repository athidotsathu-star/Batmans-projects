import struct
import unittest
from batman_hunter.wireless import analyze_pcap

class WirelessCaptureTests(unittest.TestCase):
    def test_minimal_classic_pcap(self):
        global_header = bytes.fromhex("d4c3b2a1") + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        frame = b"\x00" * 14
        packet_header = struct.pack("<IIII", 1, 0, len(frame), len(frame))
        result = analyze_pcap(global_header + packet_header + frame)
        self.assertEqual(result["packets"], 1)
        self.assertEqual(result["link_type"], 1)
        self.assertEqual(len(result["sha256"]), 64)

    def test_rejects_invalid_capture(self):
        with self.assertRaises(ValueError): analyze_pcap(b"not a capture")

    def test_rejects_pcapng_with_clear_message(self):
        with self.assertRaisesRegex(ValueError, "PCAPNG"):
            analyze_pcap(bytes.fromhex("0a0d0d0a") + b"\x00" * 24)

if __name__ == "__main__": unittest.main()
