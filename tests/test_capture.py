"""Unit tests for the Capture Layer.

Verifies requirements:
- NFR-REL-1: Bounded packet ring buffer with loss tracking.
- SADS 2.2.1 & 3.5: Mutex-protected ring buffer decoupling producers from consumers.
- FR-1, FR-2, FR-3: Multi-interface definitions & channel selection.
- FR-7: Start/Stop capture lifecycle.
"""

import unittest
from capture.buffer import CaptureBuffer
from capture.interfaces import (
    STANDARD_INTERFACES,
    get_available_interfaces,
    get_interface,
)
from capture.service import CaptureService


class CaptureLayerTest(unittest.TestCase):
    def test_buffer_push_pop_basic(self):
        buf = CaptureBuffer(maxsize=10)
        self.assertEqual(len(buf), 0)

        # Push items
        buf.push({"id": 1, "data": "first"})
        buf.push({"id": 2, "data": "second"})
        self.assertEqual(len(buf), 2)

        # Pop item FIFO
        item1 = buf.pop()
        self.assertEqual(item1["id"], 1)
        self.assertEqual(len(buf), 1)

        item2 = buf.pop()
        self.assertEqual(item2["id"], 2)
        self.assertEqual(len(buf), 0)

        # Pop empty buffer returns None
        self.assertIsNone(buf.pop())

    def test_buffer_bounded_capacity_and_overflow_tracking(self):
        buf = CaptureBuffer(maxsize=5)

        # Push 8 items into capacity 5 buffer
        for i in range(8):
            buf.push({"id": i})

        # Buffer length capped at maxsize 5
        self.assertEqual(len(buf), 5)

        stats = buf.get_stats()
        self.assertEqual(stats["enqueued_total"], 8)
        self.assertEqual(stats["dropped_total"], 3)
        self.assertEqual(stats["current_size"], 5)
        self.assertAlmostEqual(stats["drop_rate_percent"], (3 / 8) * 100, places=2)

        # Remaining items in buffer should be the newest 5 (id 3 to 7)
        oldest_remaining = buf.pop()
        self.assertEqual(oldest_remaining["id"], 3)

    def test_buffer_batch_pop(self):
        buf = CaptureBuffer(maxsize=20)
        for i in range(15):
            buf.push(i)

        batch = buf.pop_batch(max_count=10)
        self.assertEqual(len(batch), 10)
        self.assertEqual(batch, list(range(10)))
        self.assertEqual(len(buf), 5)

        remaining_batch = buf.pop_batch(max_count=10)
        self.assertEqual(len(remaining_batch), 5)
        self.assertEqual(remaining_batch, list(range(10, 15)))

    def test_interfaces_catalog(self):
        interfaces = get_available_interfaces()
        self.assertIn("wlan0", interfaces)
        self.assertIn("eth0", interfaces)
        self.assertIn("ble0", interfaces)

        wlan = get_interface("wlan0")
        self.assertTrue(wlan.is_wireless)
        self.assertIn(6, wlan.supported_channels)

    def test_capture_service_lifecycle(self):
        service = CaptureService(buffer_size=100)
        self.assertEqual(service.status, "idle")

        # Start capture
        status = service.start(bpf_filter="tcp port 80")
        self.assertEqual(service.status, "capturing")
        self.assertIsNotNone(status["capture"]["started_at"])
        self.assertEqual(status["capture"]["filter"], "tcp port 80")

        # Duplicate start raises RuntimeError
        with self.assertRaises(RuntimeError):
            service.start()

        # Stop capture
        service.stop()
        self.assertEqual(service.status, "stopped")

        # Stop when not running raises RuntimeError
        with self.assertRaises(RuntimeError):
            service.stop()

    def test_capture_service_interface_selection(self):
        service = CaptureService()
        service.set_interface("eth0")
        self.assertEqual(service.interface.name, "eth0")

        # Channel selection on wireless
        service.set_interface("wlan0", channel=11)
        self.assertEqual(service.interface.selected_channel, 11)

        # Invalid channel raises ValueError
        with self.assertRaises(ValueError):
            service.set_interface("wlan0", channel=99)


if __name__ == "__main__":
    unittest.main()
