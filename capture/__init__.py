"""Capture Layer package for Pocket Packet Sniffer.

Exports:
- CaptureBuffer: Bounded in-memory ring buffer (NFR-REL-1).
- CaptureInterface, STANDARD_INTERFACES, get_available_interfaces: Interface management.
- CaptureService: Lifecycle coordinator for capture sessions.
"""

from .buffer import CaptureBuffer
from .interfaces import CaptureInterface, STANDARD_INTERFACES, get_available_interfaces, get_interface
from .service import CaptureService

__all__ = [
    "CaptureBuffer",
    "CaptureInterface",
    "STANDARD_INTERFACES",
    "get_available_interfaces",
    "get_interface",
    "CaptureService",
]
