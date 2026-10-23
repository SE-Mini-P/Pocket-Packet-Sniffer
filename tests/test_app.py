import unittest
from backend.app import app, capture, auth_service


class CaptureApiTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        capture._status = "idle"
        capture._started_at = None
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


if __name__ == "__main__":
    unittest.main()
