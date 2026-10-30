"""Unit tests for the Storage Subsystem.

Verifies requirements:
- SADS 2.2.1 & 3.3: Storage Subsystem (SQLite metadata & audit logs).
- SEC-REQ-5: Cryptographically hash-chained tamper-evident audit log.
- FR-8: Standards-compliant .pcap file writer.
"""

import unittest
import os
import tempfile
import struct
from storage.database import DatabaseManager
from storage.pcap_store import PcapExporter


class StorageLayerTest(unittest.TestCase):
    def setUp(self):
        self.db = DatabaseManager(":memory:")

    def tearDown(self):
        self.db.close()

    def test_audit_log_hash_chaining(self):
        # Record three sequential events
        e1 = self.db.record_audit_event("engineer", "login", "Successful auth")
        e2 = self.db.record_audit_event("engineer", "start_capture", "interface=wlan0")
        e3 = self.db.record_audit_event("engineer", "stop_capture", "packets=125")

        # Verify chaining: e2's prev_hash must equal e1's entry_hash
        self.assertEqual(e2["prev_hash"], e1["entry_hash"])
        self.assertEqual(e3["prev_hash"], e2["entry_hash"])

        # Chain verification succeeds on unaltered log
        self.assertTrue(self.db.verify_audit_log_integrity())

    def test_audit_log_detects_tampering(self):
        # Record two events
        self.db.record_audit_event("admin", "login", "Admin session")
        self.db.record_audit_event("admin", "change_retention", "days=30")

        self.assertTrue(self.db.verify_audit_log_integrity())

        # Tamper directly with the database row (modify an action maliciously)
        with self.db._conn:
            self.db._conn.execute(
                "UPDATE audit_log SET action = 'tampered_action' WHERE id = 1"
            )

        # Integrity check MUST detect the tampering and fail (SEC-REQ-5)
        self.assertFalse(self.db.verify_audit_log_integrity())

    def test_pcap_exporter_writes_valid_header_and_records(self):
        # Create temporary file
        fd, temp_pcap = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)

        try:
            # Minimal ethernet frame bytes
            dummy_frame = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + b"TESTPAYLOAD"
            written = PcapExporter.write_pcap([dummy_frame], temp_pcap)
            self.assertGreater(written, 0)

            # Validate header structure
            with open(temp_pcap, "rb") as f:
                header = f.read(24)
                magic = struct.unpack("!I", header[0:4])[0]
                self.assertEqual(magic, 0xA1B2C3D4)  # Libpcap microsecond magic
                pkt_hdr = f.read(16)
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack("!IIII", pkt_hdr)
                self.assertEqual(incl_len, len(dummy_frame))
                payload = f.read(incl_len)
                self.assertEqual(payload, dummy_frame)
        finally:
            if os.path.exists(temp_pcap):
                os.remove(temp_pcap)

    def test_alerts_storage_and_filtering(self):
        # Record security alerts into SQLite (FR-08, SADS 3.3)
        a1 = self.db.record_alert("PORT_SCAN_DETECTED", "CRITICAL", "192.168.1.105", "Port sweep")
        a2 = self.db.record_alert("SUSPICIOUS_DNS_QUERY", "WARNING", "192.168.1.10", "DGA domain")
        a3 = self.db.record_alert("PARSING_ANOMALY", "INFO", "192.168.1.55", "Truncated frame")

        self.assertIsNotNone(a1["id"])
        self.assertEqual(a1["severity"], "CRITICAL")

        # Query all alerts
        all_alerts = self.db.get_alerts()
        self.assertEqual(len(all_alerts), 3)

        # Filter by severity
        crit_alerts = self.db.get_alerts(severity="CRITICAL")
        self.assertEqual(len(crit_alerts), 1)
        self.assertEqual(crit_alerts[0]["alert_type"], "PORT_SCAN_DETECTED")

        warn_alerts = self.db.get_alerts(severity="warning")
        self.assertEqual(len(warn_alerts), 1)
        self.assertEqual(warn_alerts[0]["alert_type"], "SUSPICIOUS_DNS_QUERY")


if __name__ == "__main__":
    unittest.main()
