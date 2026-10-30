import unittest
from copy import deepcopy
from backend.app import app, capture, auth_service
from backend.mock_capture import MOCK_INTERFACES, RAW_MOCK_PACKETS
from processing.metadata import PacketMetadata


class CaptureApiTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        capture._status = "idle"
        capture._started_at = None
        capture._interface = deepcopy(MOCK_INTERFACES["wlan0"])
        capture._packets = [PacketMetadata.from_dict(p) for p in RAW_MOCK_PACKETS]
        # Reset auth state for isolated test runs
        auth_service._failed_attempts.clear()
        auth_service._lockout_until.clear()
        auth_service._sessions.clear()

    # --- Capture & Filter Tests ---

    def test_start_and_stop_capture(self):
        started = self.client.post("/api/capture/start")
        self.assertEqual(started.status_code, 200)
        self.assertEqual(started.json["capture"]["status"], "capturing")
        self.assertIsNotNone(started.json["capture"]["started_at"])

        duplicate = self.client.post("/api/capture/start")
        self.assertEqual(duplicate.status_code, 409)

        stopped = self.client.post("/api/capture/stop")
        self.assertEqual(stopped.status_code, 200)
        self.assertEqual(stopped.json["capture"]["status"], "stopped")

    def test_packet_filters_match_supported_fields(self):
        response = self.client.get("/api/packets?protocol=tcp")
        self.assertEqual(response.status_code, 200)
        packets = response.json["packets"]
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0]["protocol"], "TCP")

        response = self.client.get("/api/packets?search=dhcp")
        self.assertEqual(len(response.json["packets"]), 1)
        self.assertEqual(response.json["packets"][0]["protocol"], "UDP")

    def test_stop_without_capture_returns_error(self):
        response = self.client.post("/api/capture/stop")
        self.assertEqual(response.status_code, 409)
        self.assertIn("not running", response.json["error"])

    # --- Input Validation & Error Handling Tests (Issue #8) ---

    def test_start_capture_with_valid_interface(self):
        response = self.client.post("/api/capture/start", json={"interface": "eth0"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["interface"]["name"], "eth0")

    def test_start_capture_with_invalid_interface_returns_400(self):
        response = self.client.post("/api/capture/start", json={"interface": "invalid_nic"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error_code"], "INVALID_INTERFACE")

    def test_start_capture_with_oversized_filter_returns_400(self):
        oversized = "tcp and " * 50  # > 256 chars
        response = self.client.post("/api/capture/start", json={"filter": oversized})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error_code"], "FILTER_TOO_LONG")

    def test_start_capture_with_disallowed_filter_chars_returns_400(self):
        response = self.client.post("/api/capture/start", json={"filter": "tcp; rm -rf /"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error_code"], "MALFORMED_FILTER")

    def test_query_filter_length_validation(self):
        long_arg = "A" * 150
        response = self.client.get(f"/api/packets?protocol={long_arg}")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error_code"], "FILTER_TOO_LONG")

    def test_404_error_handler_returns_json(self):
        response = self.client.get("/api/nonexistent_route")
        self.assertEqual(response.status_code, 404)
        self.assertIn("error", response.json)
        self.assertEqual(response.json["error_code"], "NOT_FOUND")

    # --- Authentication & RBAC Tests (Issue #14) ---

    def test_login_success_and_logout(self):
        # Login as engineer (SEC-REQ-2)
        login_res = self.client.post("/api/auth/login", json={
            "username": "engineer",
            "password": "EngineerPass123!"
        })
        self.assertEqual(login_res.status_code, 200)
        token = login_res.json["token"]
        self.assertIsNotNone(token)
        self.assertEqual(login_res.json["user"]["role"], "field_engineer")

        # Verify /api/auth/me
        me_res = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_res.status_code, 200)
        self.assertTrue(me_res.json["authenticated"])
        self.assertEqual(me_res.json["user"]["username"], "engineer")

        # Logout
        logout_res = self.client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(logout_res.status_code, 200)

        # Token invalidated
        me_after = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertFalse(me_after.json["authenticated"])

    def test_login_short_password_rejected(self):
        # Passwords < 10 characters rejected (SEC-REQ-2)
        res = self.client.post("/api/auth/login", json={
            "username": "engineer",
            "password": "short"
        })
        self.assertEqual(res.status_code, 401)
        self.assertIn("at least 10 characters", res.json["error"])

    def test_account_lockout_after_five_failed_attempts(self):
        # 4 failed attempts (SEC-REQ-6)
        for i in range(4):
            res = self.client.post("/api/auth/login", json={
                "username": "engineer",
                "password": "WrongPassword123!"
            })
            self.assertEqual(res.status_code, 401)

        # 5th failed attempt triggers lockout
        res_lock = self.client.post("/api/auth/login", json={
            "username": "engineer",
            "password": "WrongPassword123!"
        })
        self.assertEqual(res_lock.status_code, 423)
        self.assertEqual(res_lock.json["error_code"], "AUTH_LOCKED")

        # 6th attempt with correct password still locked out during lockout window
        res_locked_out = self.client.post("/api/auth/login", json={
            "username": "engineer",
            "password": "EngineerPass123!"
        })
        self.assertEqual(res_locked_out.status_code, 423)

    def test_rbac_admin_enforcement(self):
        # Unauthenticated access to admin endpoint
        res_unauth = self.client.get("/api/admin/system")
        self.assertEqual(res_unauth.status_code, 401)

        # Field engineer login
        login_eng = self.client.post("/api/auth/login", json={
            "username": "engineer",
            "password": "EngineerPass123!"
        })
        eng_token = login_eng.json["token"]

        # Field engineer blocked from admin endpoint (SEC-REQ-3)
        res_forbidden = self.client.get("/api/admin/system", headers={"Authorization": f"Bearer {eng_token}"})
        self.assertEqual(res_forbidden.status_code, 403)
        self.assertEqual(res_forbidden.json["error_code"], "FORBIDDEN")

        # Admin login
        login_admin = self.client.post("/api/auth/login", json={
            "username": "admin",
            "password": "AdminPass123!"
        })
        admin_token = login_admin.json["token"]

        # Admin granted access
        res_admin = self.client.get("/api/admin/system", headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(res_admin.status_code, 200)
        self.assertEqual(res_admin.json["status"], "ok")

    # --- Processing & Interfaces API Tests (Issue #1, Issue #6) ---

    def test_get_capture_statistics(self):
        res = self.client.get("/api/capture/stats")
        self.assertEqual(res.status_code, 200)
        data = res.json
        self.assertIn("total_packets", data)
        self.assertIn("total_bytes", data)
        self.assertIn("protocol_distribution", data)
        self.assertIn("top_talkers", data)
        self.assertGreater(data["total_packets"], 0)

    def test_get_interfaces_endpoint(self):
        res = self.client.get("/api/interfaces")
        self.assertEqual(res.status_code, 200)
        self.assertIn("interfaces", res.json)
        self.assertIn("wlan0", res.json["interfaces"])
        self.assertIn("eth0", res.json["interfaces"])
        self.assertIn("ble0", res.json["interfaces"])

    def test_process_packet_with_dictionary(self):
        payload = {
            "packet": {
                "id": 99,
                "protocol": "ICMP",
                "source": "10.0.0.1",
                "destination": "10.0.0.2",
                "length": 64,
                "info": "Echo request (ping)",
            }
        }
        res = self.client.post("/api/packets/process", json=payload)
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json["status"], "processed")
        meta = res.json["metadata"]
        self.assertEqual(meta["protocol"], "ICMP")
        self.assertEqual(meta["source"], "10.0.0.1")

    def test_process_packet_with_raw_hex(self):
        # 14 bytes ethernet + 20 bytes IP + 20 bytes TCP (SYN)
        hex_data = (
            "00112233445566778899aabb0800"  # Eth
            "450000281234400040060000c0a8016408080808"  # IPv4
            "d4310050000003e8000000005002ffff00000000"  # TCP
        )
        res = self.client.post("/api/packets/process", json={"hex": hex_data, "link_type": "ethernet"})
        self.assertEqual(res.status_code, 201)
        meta = res.json["metadata"]
        self.assertEqual(meta["protocol"], "TCP")
        self.assertEqual(meta["source"], "192.168.1.100:54321")
        self.assertEqual(meta["destination"], "8.8.8.8:80")
        self.assertFalse(meta["is_malformed"])

    def test_process_packet_with_malformed_hex_returns_400(self):
        res = self.client.post("/api/packets/process", json={"hex": "not_valid_hex_string!"})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json["error_code"], "MALFORMED_HEX")

    # --- Interface Detection & Selection Tests (Issue #4, FR-02, NFR-02) ---

    def test_get_interfaces_returns_supported_list(self):
        res = self.client.get("/api/interfaces")
        self.assertEqual(res.status_code, 200)
        data = res.json
        self.assertIn("interfaces", data)
        self.assertIn("selected", data)
        ifaces = data["interfaces"] if isinstance(data["interfaces"], dict) else {i["name"]: i for i in data["interfaces"]}
        self.assertIn("wlan0", ifaces)
        self.assertIn("eth0", ifaces)
        self.assertIn("ble0", ifaces)
        self.assertEqual(ifaces["wlan0"]["type"], "WiFi (802.11 monitor mode)")
        self.assertEqual(ifaces["eth0"]["type"], "Ethernet")
        self.assertEqual(ifaces["ble0"]["type"], "Bluetooth Low Energy")

    def test_select_valid_interface(self):
        res = self.client.post("/api/interfaces/select", json={"interface": "eth0"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json["interface"]["name"], "eth0")

        # Verify interface updated in /api/status
        status_res = self.client.get("/api/status")
        self.assertEqual(status_res.json["interface"]["name"], "eth0")

    def test_select_invalid_interface_returns_400(self):
        res = self.client.post("/api/interfaces/select", json={"interface": "invalid_interface_xyz"})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json["error_code"], "INVALID_INTERFACE")

    def test_select_interface_missing_payload_returns_400(self):
        res = self.client.post("/api/interfaces/select", json={})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json["error_code"], "MISSING_INTERFACE")

    def test_select_interface_during_active_capture_returns_409(self):
        # Start capture
        start_res = self.client.post("/api/capture/start")
        self.assertEqual(start_res.status_code, 200)

        # Attempt to change interface while capturing
        select_res = self.client.post("/api/interfaces/select", json={"interface": "eth0"})
        self.assertEqual(select_res.status_code, 409)
        self.assertEqual(select_res.json["error_code"], "CONFLICT")
        self.assertIn("Cannot change interface while capture is running", select_res.json["error"])

    # --- Traffic Statistics Tests (Issue #7, FR-05, FR-6) ---

    def test_get_capture_stats_returns_metrics(self):
        res = self.client.get("/api/capture/stats")
        self.assertEqual(res.status_code, 200)
        stats = res.json
        self.assertIn("total_packets", stats)
        self.assertIn("total_bytes", stats)
        self.assertIn("packets_per_second", stats)
        self.assertIn("protocol_distribution", stats)
        self.assertIn("top_talkers", stats)
        self.assertEqual(stats["total_packets"], 4)
        self.assertGreater(stats["total_bytes"], 0)

    def test_stats_protocol_distribution_accurate(self):
        res = self.client.get("/api/capture/stats")
        self.assertEqual(res.status_code, 200)
        proto_dist = res.json["protocol_distribution"]
        self.assertEqual(proto_dist.get("TCP"), 1)
        self.assertEqual(proto_dist.get("DNS"), 1)
        self.assertEqual(proto_dist.get("UDP"), 1)
        self.assertEqual(proto_dist.get("HTTP"), 1)

    def test_stats_top_talkers_aggregated(self):
        res = self.client.get("/api/capture/stats")
        self.assertEqual(res.status_code, 200)
        top_talkers = res.json["top_talkers"]
        self.assertIsInstance(top_talkers, list)
        self.assertGreater(len(top_talkers), 0)
        # 192.168.1.10 appears in all 4 mock packets
        ip_addresses = [t["ip"] for t in top_talkers]
        self.assertIn("192.168.1.10", ip_addresses)
        talker_10 = next(t for t in top_talkers if t["ip"] == "192.168.1.10")
        self.assertEqual(talker_10["packets"], 4)

    # --- Alerts & Security Observation Tests (Issue #11, FR-08, SADS 3.3) ---

    def test_get_alerts_endpoint(self):
        res = self.client.get("/api/alerts")
        self.assertEqual(res.status_code, 200)
        data = res.json
        self.assertIn("alerts", data)
        self.assertIn("count", data)
        self.assertGreaterEqual(data["count"], 4)
        first = data["alerts"][0]
        self.assertIn("alert_type", first)
        self.assertIn("severity", first)
        self.assertIn("timestamp", first)

    def test_get_alerts_filtered_by_severity(self):
        res = self.client.get("/api/alerts?severity=CRITICAL")
        self.assertEqual(res.status_code, 200)
        alerts = res.json["alerts"]
        self.assertGreater(len(alerts), 0)
        for a in alerts:
            self.assertEqual(a["severity"], "CRITICAL")

        res_warn = self.client.get("/api/alerts?severity=warning")
        self.assertEqual(res_warn.status_code, 200)
        for a in res_warn.json["alerts"]:
            self.assertEqual(a["severity"], "WARNING")

    def test_get_alerts_search_filter(self):
        res = self.client.get("/api/alerts?search=heuristic")
        self.assertEqual(res.status_code, 200)
        alerts = res.json["alerts"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "PORT_SCAN_DETECTED")

    def test_get_alerts_oversized_filter_returns_400(self):
        res = self.client.get("/api/alerts?severity=" + ("A" * 100))
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json["error_code"], "FILTER_TOO_LONG")

    def test_post_alert_success(self):
        payload = {
            "alert_type": "SYN_FLOOD_ANOMALY",
            "severity": "CRITICAL",
            "source_ip": "10.0.0.99",
            "details": "SYN burst rate exceeded 50 handshakes/10s",
        }
        res = self.client.post("/api/alerts", json=payload)
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json["status"], "created")
        created = res.json["alert"]
        self.assertEqual(created["alert_type"], "SYN_FLOOD_ANOMALY")
        self.assertEqual(created["severity"], "CRITICAL")
        self.assertEqual(created["source_ip"], "10.0.0.99")

    def test_post_alert_validation_errors(self):
        # Empty payload
        res = self.client.post("/api/alerts", json=None)
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json["error_code"], "MISSING_PAYLOAD")

        # Missing alert_type
        res = self.client.post("/api/alerts", json={"severity": "INFO"})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json["error_code"], "MISSING_ALERT_TYPE")

        # Invalid severity
        res = self.client.post("/api/alerts", json={"alert_type": "TEST", "severity": "EXTREME"})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json["error_code"], "INVALID_SEVERITY")

        # Field too long
        res = self.client.post("/api/alerts", json={"alert_type": "A" * 70})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json["error_code"], "FIELD_TOO_LONG")

        res_ip = self.client.post("/api/alerts", json={"alert_type": "TEST", "source_ip": "9" * 50})
        self.assertEqual(res_ip.status_code, 400)
        self.assertEqual(res_ip.json["error_code"], "FIELD_TOO_LONG")

        res_details = self.client.post("/api/alerts", json={"alert_type": "TEST", "details": "D" * 600})
        self.assertEqual(res_details.status_code, 400)
        self.assertEqual(res_details.json["error_code"], "FIELD_TOO_LONG")

    # --- Performance & Telemetry Tests (Issue #15, NFR-01, NFR-07) ---

    def test_system_performance_endpoint(self):
        res = self.client.get("/api/system/performance")
        self.assertEqual(res.status_code, 200)
        data = res.json
        self.assertIn("dashboard_response_time_ms", data)
        self.assertIn("cpu_usage", data)
        self.assertIn("memory_usage", data)
        self.assertIn("storage_usage", data)

        lat = data["dashboard_response_time_ms"]
        self.assertIn("mean", lat)
        self.assertIn("p95", lat)
        self.assertLessEqual(lat["mean"], 500.0)

        mem = data["memory_usage"]
        self.assertGreater(mem["rss_mb"], 0.0)
        self.assertEqual(mem["status"], "BOUNDED")

        storage = data["storage_usage"]
        self.assertGreater(storage["ring_buffer_capacity"], 0)
        self.assertEqual(storage["status"], "NOMINAL")


if __name__ == "__main__":
    unittest.main()
