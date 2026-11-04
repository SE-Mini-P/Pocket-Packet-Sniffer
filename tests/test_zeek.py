"""Unit and integration tests for Zeek Analysis Engine.

Verifies requirements:
- FR-5: Zeek analysis engine and structured log emission (conn.log, dns.log, weird.log, notice.log).
- FR-10: Anomaly detection heuristics (port scan, ARP spoofing, flood).
- SADS 2.2.1: Zeek component and log ingestion.
- SADS 3.4: Routing malformed frames to weird.log.
"""

import unittest
from datetime import datetime, timezone

from processing.zeek_engine import ZeekAnalysisEngine, ZeekLogEntry
from backend.app import app


class ZeekAnalysisEngineTest(unittest.TestCase):
    def setUp(self):
        self.engine = ZeekAnalysisEngine()

    def test_log_entry_to_tsv(self):
        entry = ZeekLogEntry("conn", {"uid": "C12345", "id.orig_h": "192.168.1.10", "id.resp_p": 80})
        tsv = entry.to_tsv(["uid", "id.orig_h", "id.resp_p", "missing_field"])
        self.assertEqual(tsv, "C12345\t192.168.1.10\t80\t-")

    def test_conn_log_generation_on_tcp_packet(self):
        pkt = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": "TCP",
            "source": "192.168.1.50:45123",
            "destination": "10.0.0.1:443",
            "length": 120,
            "flags": {"SYN": True, "ACK": False},
        }
        events = self.engine.process_packet(pkt)
        self.assertIsNotNone(events["conn"])
        self.assertEqual(len(self.engine.conn_log), 1)

        conn = self.engine.conn_log[0]
        self.assertEqual(conn["id.orig_h"], "192.168.1.50")
        self.assertEqual(conn["id.resp_p"], 443)
        self.assertEqual(conn["service"], "ssl")
        self.assertEqual(conn["conn_state"], "S0")
        self.assertEqual(conn["orig_bytes"], 120)

    def test_conn_state_transition_on_reply(self):
        forward_pkt = {
            "protocol": "TCP",
            "source": "192.168.1.50:45123",
            "destination": "10.0.0.1:80",
            "length": 60,
            "flags": {"SYN": True},
        }
        reply_pkt = {
            "protocol": "TCP",
            "source": "10.0.0.1:80",
            "destination": "192.168.1.50:45123",
            "length": 60,
            "flags": {"SYN": True, "ACK": True},
        }
        self.engine.process_packet(forward_pkt)
        self.assertEqual(self.engine.conn_log[0]["conn_state"], "S0")

        self.engine.process_packet(reply_pkt)
        self.assertEqual(self.engine.conn_log[0]["conn_state"], "SF")
        self.assertEqual(self.engine.conn_log[0]["resp_bytes"], 60)

    def test_dns_log_generation(self):
        dns_pkt = {
            "protocol": "DNS",
            "source": "192.168.1.10:5353",
            "destination": "1.1.1.1:53",
            "length": 75,
            "info": "Standard query A api.github.com",
            "src_port": 5353,
            "dst_port": 53,
        }
        events = self.engine.process_packet(dns_pkt)
        self.assertIsNotNone(events["dns"])
        self.assertEqual(len(self.engine.dns_log), 1)

        dns = self.engine.dns_log[0]
        self.assertEqual(dns["id.orig_h"], "192.168.1.10")
        self.assertEqual(dns["id.resp_h"], "1.1.1.1")
        self.assertEqual(dns["query"], "api.github.com")
        self.assertEqual(dns["qtype_name"], "A")
        self.assertEqual(dns["rcode_name"], "NOERROR")

    def test_malformed_packet_routed_to_weird_log(self):
        malformed = {
            "is_malformed": True,
            "malformed_reason": "truncated_ipv4_header",
            "info": "Packet truncated to 8 bytes",
            "source": "192.168.1.99",
            "length": 8,
        }
        events = self.engine.process_packet(malformed)
        self.assertIsNotNone(events["weird"])
        self.assertEqual(len(self.engine.weird_log), 1)
        self.assertEqual(self.engine.weird_log[0]["name"], "truncated_ipv4_header")

    def test_illegal_tcp_flags_syn_and_fin_weird_log(self):
        illegal_pkt = {
            "protocol": "TCP",
            "source": "192.168.1.10:5555",
            "destination": "10.0.0.1:80",
            "flags": {"SYN": True, "FIN": True},
            "length": 64,
        }
        events = self.engine.process_packet(illegal_pkt)
        self.assertIsNotNone(events["weird"])
        self.assertEqual(events["weird"]["name"], "tcp_syn_and_fin")

    def test_port_scan_heuristic_triggers_notice(self):
        src = "192.168.1.200"
        dst = "192.168.1.1"
        self.engine.port_scan_threshold = 4

        # Probe 4 distinct ports
        for port in [21, 22, 80, 443]:
            self.engine.process_packet({
                "protocol": "TCP",
                "source": f"{src}:4000{port}",
                "destination": f"{dst}:{port}",
                "src_port": 40000 + port,
                "dst_port": port,
                "length": 60,
                "flags": {"SYN": True},
            })

        self.assertEqual(len(self.engine.notice_log), 1)
        notice = self.engine.notice_log[0]
        self.assertEqual(notice["note"], "Scan::Port_Scan")
        self.assertEqual(notice["src"], src)
        self.assertEqual(notice["dst"], dst)
        self.assertEqual(notice["severity"], "CRITICAL")

    def test_arp_spoofing_detection_triggers_notice(self):
        pkt1 = {
            "protocol": "ARP",
            "source": "192.168.1.1",
            "src_mac": "00:11:22:33:44:55",
            "destination": "192.168.1.100",
            "length": 42,
            "info": "ARP reply 192.168.1.1 is at 00:11:22:33:44:55",
        }
        self.engine.process_packet(pkt1)
        self.assertEqual(len(self.engine.notice_log), 0)

        # Conflicting MAC for same IP
        pkt2 = {
            "protocol": "ARP",
            "source": "192.168.1.1",
            "src_mac": "AA:BB:CC:DD:EE:FF",
            "destination": "192.168.1.100",
            "length": 42,
            "info": "ARP reply 192.168.1.1 is at AA:BB:CC:DD:EE:FF",
        }
        self.engine.process_packet(pkt2)
        self.assertEqual(len(self.engine.notice_log), 1)
        notice = self.engine.notice_log[0]
        self.assertEqual(notice["note"], "Notice::ARP_Spoofing")
        self.assertEqual(notice["severity"], "CRITICAL")
        self.assertIn("00:11:22:33:44:55", notice["msg"])
        self.assertIn("AA:BB:CC:DD:EE:FF", notice["msg"])

    def test_traffic_flood_detection_triggers_notice(self):
        self.engine.flood_threshold = 10
        src = "192.168.1.105"
        for i in range(12):
            self.engine.process_packet({
                "protocol": "UDP",
                "source": f"{src}:5000",
                "destination": "192.168.1.1:53",
                "dst_port": 53,
                "length": 100,
            })
        self.assertTrue(any(n["note"] == "Notice::Traffic_Flood" for n in self.engine.notice_log))

    def test_get_logs_filtering_and_limits(self):
        p1 = {"protocol": "TCP", "source": "10.0.0.1:1000", "destination": "10.0.0.2:80", "dst_port": 80, "length": 50}
        p2 = {"protocol": "DNS", "source": "10.0.0.1:5353", "destination": "8.8.8.8:53", "dst_port": 53, "length": 70, "info": "query A google.com"}
        self.engine.process_packet(p1)
        self.engine.process_packet(p2)

        conn_logs = self.engine.get_logs("conn")
        self.assertEqual(len(conn_logs), 2)  # both establish conn

        dns_logs = self.engine.get_logs("dns")
        self.assertEqual(len(dns_logs), 1)

        all_logs = self.engine.get_logs("all")
        self.assertGreaterEqual(len(all_logs), 3)

        with self.assertRaises(ValueError):
            self.engine.get_logs("unsupported_log_type")

    def test_summary_statistics(self):
        p = {"protocol": "TCP", "source": "1.1.1.1:100", "destination": "2.2.2.2:80", "dst_port": 80, "length": 50}
        self.engine.process_packet(p)
        summary = self.engine.get_summary()
        self.assertEqual(summary["total_connections"], 1)
        self.assertEqual(summary["services_breakdown"].get("http"), 1)

    def test_clear_resets_state(self):
        p = {"protocol": "TCP", "source": "1.1.1.1:100", "destination": "2.2.2.2:80", "dst_port": 80, "length": 50}
        self.engine.process_packet(p)
        self.assertEqual(len(self.engine.conn_log), 1)
        self.engine.clear()
        self.assertEqual(len(self.engine.conn_log), 0)
        self.assertEqual(len(self.engine._flows), 0)


class ZeekApiIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_api_zeek_logs_all(self):
        res = self.client.get("/api/zeek/logs")
        self.assertEqual(res.status_code, 200)
        self.assertIn("logs", res.json)
        self.assertIn("count", res.json)
        self.assertEqual(res.json["log_type"], "all")

    def test_api_zeek_logs_by_type(self):
        res = self.client.get("/api/zeek/logs?type=dns")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json["log_type"], "dns")

    def test_api_zeek_logs_invalid_type_returns_400(self):
        res = self.client.get("/api/zeek/logs?type=invalid_type")
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json["error_code"], "INVALID_LOG_TYPE")

    def test_api_zeek_stats(self):
        res = self.client.get("/api/zeek/stats")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json["status"], "active")
        self.assertIn("zeek_summary", res.json)
        self.assertIn("total_connections", res.json["zeek_summary"])

    def test_api_zeek_analyze_packet(self):
        test_pkt = {
            "protocol": "TCP",
            "source": "192.168.1.99:54321",
            "destination": "93.184.216.34:80",
            "length": 80,
            "dst_port": 80,
            "flags": {"SYN": True},
        }
        res = self.client.post("/api/zeek/analyze", json={"packet": test_pkt})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json["status"], "analyzed")
        self.assertGreaterEqual(res.json["processed_count"], 1)


if __name__ == "__main__":
    unittest.main()
