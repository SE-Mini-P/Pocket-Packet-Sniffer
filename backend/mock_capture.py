"""Mock capture service for the Pocket Packet Sniffer (PPS).

No hardware (Raspberry Pi / ESP32) is available during development, so this
module stands in for the real capture layer. It exposes the same kind of
information the real backend will later provide: which interface is selected
and what the capture status is.

When real capture code is written, replace the internals of ``MockCaptureService``
but keep the shape of ``get_status()`` so the dashboard does not need to change.

Mock behaviour can be tweaked with environment variables (handy for demos):
    PPS_MOCK_INTERFACE   e.g. "wlan0", "eth0", "ble0"       (default: wlan0)
    PPS_MOCK_STATUS      "idle" | "capturing" | "stopped" | "error"
                         (default: idle)
"""

import os
from datetime import datetime, timezone

# Interfaces the real device will eventually expose (SRS FR-1, FR-2, FR-3).
MOCK_INTERFACES = {
    "wlan0": {"name": "wlan0", "type": "WiFi (802.11 monitor mode)"},
    "eth0": {"name": "eth0", "type": "Ethernet"},
    "ble0": {"name": "ble0", "type": "Bluetooth Low Energy"},
}

VALID_STATUSES = {"idle", "capturing", "stopped", "error"}


class MockCaptureService:
    def __init__(self) -> None:
        iface_key = os.getenv("PPS_MOCK_INTERFACE", "wlan0")
        self._interface = MOCK_INTERFACES.get(iface_key, MOCK_INTERFACES["wlan0"])

        status = os.getenv("PPS_MOCK_STATUS", "idle").lower()
        self._status = status if status in VALID_STATUSES else "idle"

        self._started_at = (
            datetime.now(timezone.utc).isoformat()
            if self._status == "capturing"
            else None
        )

    def get_status(self) -> dict:
        """Return the data the dashboard needs to render its header."""
        return {
            "interface": dict(self._interface),
            "capture": {
                "status": self._status,
                "started_at": self._started_at,
            },
        }
