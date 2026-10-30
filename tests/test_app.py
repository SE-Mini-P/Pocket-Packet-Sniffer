import unittest

from backend.app import app, capture


class CaptureApiTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        capture._status = "idle"
        capture._started_at = None
        capture._sessions = []
        capture._active_session_id = None
        capture._next_session_id = 1

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

    def test_capture_history_contains_analysis_results(self):
        self.client.post("/api/capture/start")
        self.client.post("/api/capture/stop")

        response = self.client.get("/api/sessions")
        self.assertEqual(response.status_code, 200)
        sessions = response.json["sessions"]
        self.assertEqual(len(sessions), 1)
        session = sessions[0]
        self.assertEqual(session["status"], "completed")
        self.assertEqual(session["packet_count"], 4)
        self.assertEqual(session["analysis"]["protocol_counts"]["TCP"], 1)
        self.assertEqual(session["analysis"]["total_bytes"], 1056)
        self.assertIsNotNone(session["ended_at"])

        detail = self.client.get(f"/api/sessions/{session['id']}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json["session"]["id"], session["id"])

    def test_unknown_capture_session_returns_not_found(self):
        response = self.client.get("/api/sessions/session-999")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
