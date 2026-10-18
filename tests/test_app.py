import unittest

from backend.app import app, capture


class CaptureApiTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        capture._status = "idle"
        capture._started_at = None

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


if __name__ == "__main__":
    unittest.main()
