"""Bounded in-memory ring buffer for the Capture Layer.

Implements requirements:
- NFR-REL-1: Packet loss bound (< 0.1% loss during sustained load).
- SADS 2.2.1 & 3.5: Bounded ring buffer decoupling capture producers from consumers,
  with mutex-protected enqueue/dequeue operations to avoid blocking capture under load.
"""

import threading
from collections import deque
from typing import Any, Optional, Dict, List


class CaptureBuffer:
    """Thread-safe bounded ring buffer for captured network frames."""

    def __init__(self, maxsize: int = 10000) -> None:
        if maxsize <= 0:
            raise ValueError("Buffer capacity must be a positive integer")
        self.maxsize = maxsize
        self._buffer: deque = deque(maxlen=maxsize)
        self._lock = threading.Lock()

        # Telemetry metrics (NFR-REL-1)
        self._enqueued_total = 0
        self._dequeued_total = 0
        self._dropped_total = 0

    def push(self, packet: Any) -> bool:
        """Push a packet into the ring buffer.

        If the buffer is full, the oldest packet is overwritten by the ring,
        and the drop counter is incremented.

        Returns:
            True if enqueued without drop, False if buffer was full and a packet was dropped.
        """
        with self._lock:
            self._enqueued_total += 1
            dropped = False
            if len(self._buffer) >= self.maxsize:
                self._dropped_total += 1
                dropped = True
            self._buffer.append(packet)
            return not dropped

    def pop(self) -> Optional[Any]:
        """Pop the next available packet from the front of the queue."""
        with self._lock:
            if not self._buffer:
                return None
            self._dequeued_total += 1
            return self._buffer.popleft()

    def pop_batch(self, max_count: int = 100) -> List[Any]:
        """Pop up to max_count packets in a single atomic batch."""
        with self._lock:
            batch = []
            while self._buffer and len(batch) < max_count:
                self._dequeued_total += 1
                batch.append(self._buffer.popleft())
            return batch

    def clear(self) -> None:
        """Clear all buffered packets and reset active count."""
        with self._lock:
            self._buffer.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Return operational telemetry metrics for the buffer."""
        with self._lock:
            enq = self._enqueued_total
            drp = self._dropped_total
            drop_rate = (drp / enq) if enq > 0 else 0.0
            return {
                "current_size": len(self._buffer),
                "max_capacity": self.maxsize,
                "enqueued_total": enq,
                "dequeued_total": self._dequeued_total,
                "dropped_total": drp,
                "drop_rate_percent": round(drop_rate * 100, 4),
            }

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)
