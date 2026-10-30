"""Performance and Resource Usage Verification Test Suite.

Verifies requirements:
- Issue #15: Measure dashboard response time and observe CPU, memory and storage usage.
- NFR-01 / PPS-NF-001: High throughput capture stability.
- NFR-02 / PPS-NF-002: Dashboard UI & API response latency <= 500 ms.
- NFR-07: Resource consumption observability under normal test conditions.
- NFR-REL-1 / PPS-F-010: Bounded memory footprint with circular ring buffer.
"""

import time
import unittest
from backend.app import app, capture
from capture.buffer import CaptureBuffer


class PerformanceAndResourceTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_dashboard_response_times_under_threshold(self):
        """Verify API response times are strictly under the 500ms threshold (NFR-02)."""
        endpoints = [
            "/api/status",
            "/api/interfaces",
            "/api/capture/stats",
            "/api/packets",
            "/api/alerts",
            "/api/system/performance",
        ]

        latencies = []
        for _ in range(15):
            for ep in endpoints:
                start = time.perf_counter()
                res = self.client.get(ep)
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                latencies.append(elapsed_ms)
                self.assertEqual(res.status_code, 200)

        mean_latency = sum(latencies) / len(latencies)
        max_latency = max(latencies)
        sorted_latencies = sorted(latencies)
        p95_latency = sorted_latencies[int(len(sorted_latencies) * 0.95)]

        # NFR-02 / PPS-NF-002 requires response latency <= 500ms
        self.assertLess(mean_latency, 500.0, f"Mean latency {mean_latency:.2f}ms exceeds 500ms")
        self.assertLess(p95_latency, 500.0, f"P95 latency {p95_latency:.2f}ms exceeds 500ms")
        self.assertLess(max_latency, 500.0, f"Max latency {max_latency:.2f}ms exceeds 500ms")

    def test_memory_boundedness_under_burst_load(self):
        """Verify ring buffer memory boundedness under burst load (NFR-REL-1, PPS-F-010)."""
        # Buffer capacity capped at 500 frames for edge constraint
        bounded_buffer = CaptureBuffer(maxsize=500)

        # Ingest 2,500 mock packet frames in rapid succession
        for i in range(2500):
            packet_data = {
                "id": i + 1,
                "timestamp": f"2026-10-30T10:00:{i % 60:02d}Z",
                "protocol": "TCP" if i % 2 == 0 else "UDP",
                "source": f"192.168.1.{i % 250}:5000",
                "destination": "10.0.0.1:80",
                "length": 64 + (i % 512),
                "info": f"Payload {i}",
            }
            bounded_buffer.push(packet_data)

        # Buffer count MUST NOT exceed configured capacity of 500 frames
        self.assertEqual(len(bounded_buffer), 500)
        # 2,000 frames must have been discarded to prevent memory exhaustion
        stats = bounded_buffer.get_stats()
        self.assertEqual(stats["dropped_total"], 2000)
        self.assertEqual(stats["enqueued_total"], 2500)

    def test_resource_observation_telemetry(self):
        """Verify CPU, memory RSS, and storage usage telemetry reporting (NFR-07)."""
        metrics = capture.get_performance_metrics()

        # Check response latency metrics
        self.assertIn("dashboard_response_time_ms", metrics)
        lat = metrics["dashboard_response_time_ms"]
        self.assertIn("mean", lat)
        self.assertIn("p95", lat)
        self.assertEqual(lat["status"], "PASS")

        # Check CPU telemetry
        self.assertIn("cpu_usage", metrics)
        cpu = metrics["cpu_usage"]
        self.assertIn("process_cpu_time_sec", cpu)
        self.assertGreaterEqual(cpu["process_cpu_time_sec"], 0.0)

        # Check Memory RSS telemetry
        self.assertIn("memory_usage", metrics)
        mem = metrics["memory_usage"]
        self.assertIn("rss_mb", mem)
        self.assertGreater(mem["rss_mb"], 0.0)
        self.assertLess(mem["rss_mb"], 512.0)
        self.assertEqual(mem["status"], "BOUNDED")

        # Check Storage telemetry
        self.assertIn("storage_usage", metrics)
        storage = metrics["storage_usage"]
        self.assertIn("ring_buffer_packets", storage)
        self.assertIn("disk_free_gb", storage)
        self.assertGreater(storage["disk_free_gb"], 0.0)
        self.assertEqual(storage["status"], "NOMINAL")


if __name__ == "__main__":
    unittest.main()
