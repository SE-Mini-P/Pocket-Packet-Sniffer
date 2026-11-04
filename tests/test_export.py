"""Unit and integration tests for Export & Reporting Subsystem.

Verifies requirements:
- FR-8: Standards-compliant .pcap/.pcapng export on user request.
- FR-9: Human-readable session summary report (HTML) containing capture duration,
  packet/byte counts, protocol distribution, and detected anomalies.
- FR-10 (Issue #13): Allow users to export selected packet metadata or analysis
  results in supported formats (JSON, CSV, PCAP, HTML).
- SADS 3.2: Export and report endpoints.
"""

import io
import json
import csv
import struct
import unittest

from storage.exporter import AnalysisExporter
from backend.app import app, capture


class AnalysisExporterTest(unittest.TestCase):
    def setUp(self):
        self.sample_packets = [
            {
                "id": 1,
                "timestamp": "2026-10-30T10:00:00Z",
                "protocol": "TCP",
                "source": "192.168.1.100:54321",
                "destination": "93.184.216.34:443",
                "length": 128,
                "info": "TLS Client Hello",
                "flags": {"SYN": True, "ACK": False},
                "src_port": 54321,
                "dst_port": 443,
            },
            {
                "id": 2,
                "timestamp": "2026-10-30T10:00:01Z",
                "protocol": "DNS",
                "source": "192.168.1.100:5353",
                "destination": "8.8.8.8:53",
                "length": 74,
                "info": "Standard query A example.com",
                "src_port": 5353,
                "dst_port": 53,
            },
        ]
        self.sample_session = {
            "id": "session-test-1",
            "interface": {"name": "eth0", "type": "Ethernet"},
            "started_at": "2026-10-30T10:00:00Z",
            "ended_at": "2026-10-30T10:05:00Z",
            "status": "completed",
            "packet_count": 2,
            "analysis": {"protocol_counts": {"TCP": 1, "DNS": 1}, "total_bytes": 202},
        }

    def test_export_json_valid_formatting(self):
        json_output = AnalysisExporter.export_json(self.sample_packets)
        parsed = json.loads(json_output)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["protocol"], "TCP")

    def test_export_csv_headers_and_nested_serialization(self):
        csv_output = AnalysisExporter.export_csv(self.sample_packets)
        reader = csv.DictReader(io.StringIO(csv_output))
        rows = list(reader)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["protocol"], "TCP")
        self.assertEqual(rows[0]["length"], "128")
        # Ensure nested dict 'flags' was serialized into JSON string inside CSV
        flags_parsed = json.loads(rows[0]["flags"])
        self.assertTrue(flags_parsed["SYN"])

    def test_export_csv_empty_returns_empty_string(self):
        self.assertEqual(AnalysisExporter.export_csv([]), "")

    def test_export_pcap_structure_and_magic_header(self):
        pcap_data = AnalysisExporter.export_pcap(self.sample_packets)
        self.assertIsInstance(pcap_data, bytes)
        self.assertGreater(len(pcap_data), 24)  # 24-byte pcap global header + records

        # Verify 32-bit standard pcap magic number: 0xA1B2C3D4 (big-endian)
        magic = struct.unpack("!I", pcap_data[:4])[0]
        self.assertEqual(magic, 0xA1B2C3D4)

    def test_export_html_report_contains_required_sections(self):
        alerts = [
            {
                "timestamp": "2026-10-30T10:01:00Z",
                "severity": "CRITICAL",
                "alert_type": "Scan::Port_Scan",
                "source_ip": "192.168.1.200",
                "details": "Port scan detected",
            }
        ]
        html_report = AnalysisExporter.export_html_report(
            session=self.sample_session,
            packets=self.sample_packets,
            alerts=alerts,
        )
        self.assertIn("Pocket Packet Sniffer", html_report)
        self.assertIn("session-test-1", html_report)
        self.assertIn("eth0", html_report)
        self.assertIn("Protocol Breakdown", html_report)
        self.assertIn("Scan::Port_Scan", html_report)
        self.assertIn("192.168.1.200", html_report)


class ExportApiIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        capture.start()
        capture.stop()
        self.sessions = capture.get_sessions()
        self.session_id = self.sessions[0]["id"] if self.sessions else "session-1"

    def test_api_export_json_packets(self):
        res = self.client.get("/api/export?format=json&data_type=packets")
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/json", res.headers.get("Content-Type", ""))
        self.assertIn("attachment; filename=", res.headers.get("Content-Disposition", ""))
        data = json.loads(res.data.decode("utf-8"))
        self.assertIn("packets", data)

    def test_api_export_csv_packets(self):
        res = self.client.get("/api/export?format=csv&data_type=packets")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/csv", res.headers.get("Content-Type", ""))
        self.assertIn(".csv", res.headers.get("Content-Disposition", ""))

    def test_api_export_pcap(self):
        res = self.client.get("/api/export?format=pcap")
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/vnd.tcpdump.pcap", res.headers.get("Content-Type", ""))
        self.assertIn(".pcap", res.headers.get("Content-Disposition", ""))
        self.assertGreater(len(res.data), 24)

    def test_api_export_html_report(self):
        res = self.client.get("/api/export?format=html")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers.get("Content-Type", ""))
        self.assertIn("<!DOCTYPE html>", res.data.decode("utf-8"))

    def test_api_export_invalid_format_returns_400(self):
        res = self.client.get("/api/export?format=invalid_format")
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json["error_code"], "INVALID_EXPORT_FORMAT")

    def test_api_export_invalid_data_type_returns_400(self):
        res = self.client.get("/api/export?data_type=unknown_type")
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json["error_code"], "INVALID_DATA_TYPE")

    def test_api_session_export_pcap(self):
        res = self.client.get(f"/api/sessions/{self.session_id}/export?format=pcap")
        self.assertEqual(res.status_code, 200)
        self.assertIn(".pcap", res.headers.get("Content-Disposition", ""))

    def test_api_session_export_json(self):
        res = self.client.get(f"/api/sessions/{self.session_id}/export?format=json")
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/json", res.headers.get("Content-Type", ""))

    def test_api_session_export_missing_returns_404(self):
        res = self.client.get("/api/sessions/non_existent_session_id/export")
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json["error_code"], "NOT_FOUND")

    def test_api_session_report_html(self):
        res = self.client.get(f"/api/sessions/{self.session_id}/report")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers.get("Content-Type", ""))
        self.assertIn(self.session_id, res.data.decode("utf-8"))

    def test_api_session_report_missing_returns_404(self):
        res = self.client.get("/api/sessions/missing_session_xyz/report")
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json["error_code"], "NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
