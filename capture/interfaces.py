"""Interface definitions and hardware management for Pocket Packet Sniffer.

Implements requirements:
- FR-1: 802.11 WiFi in monitor mode with channel selection (2.4 / 5 GHz).
- FR-2: Ethernet capture from host NIC at line rates up to 100 Mbps.
- FR-3: BLE advertisement and GATT capture with configurable RSSI threshold.
- FR-15: Multi-interface concurrent support.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class CaptureInterface:
    name: str
    interface_type: str
    is_wireless: bool = False
    supported_channels: List[int] = field(default_factory=list)
    selected_channel: Optional[int] = None
    rssi_threshold: Optional[int] = None
    bpf_filter: Optional[str] = None
    status: str = "available"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.interface_type,
            "is_wireless": self.is_wireless,
            "supported_channels": self.supported_channels,
            "selected_channel": self.selected_channel,
            "rssi_threshold": self.rssi_threshold,
            "status": self.status,
        }


# Standard reference interfaces (SRS FR-1, FR-2, FR-3)
STANDARD_INTERFACES: Dict[str, CaptureInterface] = {
    "wlan0": CaptureInterface(
        name="wlan0",
        interface_type="WiFi (802.11 monitor mode)",
        is_wireless=True,
        supported_channels=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48],
        selected_channel=6,
    ),
    "eth0": CaptureInterface(
        name="eth0",
        interface_type="Ethernet",
        is_wireless=False,
    ),
    "ble0": CaptureInterface(
        name="ble0",
        interface_type="Bluetooth Low Energy",
        is_wireless=True,
        rssi_threshold=-70,
    ),
}


def get_available_interfaces() -> Dict[str, Dict[str, Any]]:
    """Return dictionary of available capture interfaces."""
    return {name: iface.to_dict() for name, iface in STANDARD_INTERFACES.items()}


def get_interface(name: str) -> Optional[CaptureInterface]:
    """Retrieve an interface by name, or None if unrecognized."""
    return STANDARD_INTERFACES.get(name)
