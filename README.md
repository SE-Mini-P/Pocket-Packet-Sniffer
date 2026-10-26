# Pocket Packet Sniffer (PPS)

Portable WiFi / Ethernet / BLE packet sniffer with real-time analysis and a local web dashboard.
Designed for network diagnostics, wireless site surveys, and lightweight edge anomaly detection.

Refer to the companion specifications in `docs/`:
- **Software Requirements Specification** (`docs/SRS_Pocket_Packet_Sniffer.pdf` / PPS-SRS-1.0)
- **Software Architecture & Design Specification** (`docs/SADS_Pocket_Packet_Sniffer.pdf` / PPS-SADS-1.0)
- **Software Test Plan** (`docs/TestPlan_Pocket_Packet_Sniffer.pdf` / PPS-TP-1.0)

---

## 1. Project Architecture & Modular Structure

The codebase is organized into independent, decoupled layers following the **SADS Section 2.2 Component Model**:

```
Pocket-Packet-Sniffer/
├── capture/                  # Capture Layer (Edge Node) - SADS 2.2.1, FR-1, FR-2, FR-3
│   ├── __init__.py
│   ├── buffer.py             # Bounded ring buffer decoupling capture from consumers (NFR-REL-1)
│   ├── interfaces.py         # Interface definitions & detection (wlan0, eth0, ble0)
│   └── service.py            # Unified capture lifecycle service & session coordinator
├── processing/               # Processing Layer - SADS 2.2.1, SADS 3.4, FR-04, FR-5, FR-6
│   ├── __init__.py
│   ├── parser.py             # Packet dissector (Ethernet, WiFi 802.11, BLE, IP, TCP, UDP, DNS, HTTP, ARP)
│   ├── metadata.py           # PacketMetadata data model & MetadataExtractor aggregation
│   └── error_handling.py     # Resilient error handling for truncated/corrupt frames (SADS 3.4)
├── storage/                  # Storage Subsystem - SADS 2.2.1, 3.3, SEC-REQ-1, SEC-REQ-5, FR-8
│   ├── __init__.py
│   ├── database.py           # SQLite database manager with hash-chained audit logging
│   └── pcap_store.py         # Standards-compliant libpcap (.pcap) export writer
├── backend/                  # Backend Services Layer - SADS 2.2.1, SADS 3.2
│   ├── __init__.py
│   ├── app.py                # Flask application exposing REST APIs and static dashboard
│   ├── auth.py               # Token auth, session management, RBAC, 5-attempt lockout (SEC-REQ-2/3/6)
│   ├── mock_capture.py       # Simulation adapter bridging capture & processing layers
│   └── requirements.txt      # Backend dependency manifest
├── frontend/                 # Presentation Layer - Web Dashboard (FR-6, FR-14)
│   ├── index.html            # Responsive single-page dashboard
│   ├── css/styles.css        # Responsive styling (NFR-PORT-1 >= 360px viewport)
│   └── js/app.js             # Live polling, stats refresh, filter application, auth handling
├── tests/                    # Automated Test Suite - SADS 3.5, NFR-MAINT-1
│   ├── __init__.py
│   ├── test_app.py           # REST API, auth lockout, RBAC, and input validation tests
│   ├── test_processing.py    # Protocol dissection, metadata extraction, and malformed frame tests
│   ├── test_capture.py       # Ring buffer overflow bounds, interface detection tests
│   └── test_storage.py       # SQLite persistence, pcap exporter, and audit log integrity tests
├── docs/                     # Engineering design specifications (SRS, SADS, Test Plan)
├── requirements.txt          # Root Python dependency manifest
├── .gitignore                # Git exclusions
└── README.md                 # Setup, usage, and architectural documentation
```

---

## 2. Environment Setup & Installation

### Prerequisites
- Python 3.10+ (tested on Python 3.10, 3.11, 3.12)
- Virtual environment (`venv`) or Anaconda/Miniconda

### Setup

```bash
# Clone the repository
git clone https://github.com/SE-Mini-P/Pocket-Packet-Sniffer.git
cd Pocket-Packet-Sniffer

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## 3. Running the Application

Start the local Flask server:

```bash
python backend/app.py
```

Open your browser and navigate to **`http://127.0.0.1:5000`**.

### Environment Options (Testing & Demos)
You can customize mock interfaces and states via environment variables:

```bash
# Linux / macOS
PPS_MOCK_INTERFACE=eth0 PPS_MOCK_STATUS=capturing python backend/app.py

# Windows PowerShell
$env:PPS_MOCK_INTERFACE="eth0"; $env:PPS_MOCK_STATUS="capturing"; python backend/app.py
```

- **Supported Interfaces**: `wlan0` (WiFi monitor mode), `eth0` (Ethernet), `ble0` (Bluetooth Low Energy)
- **Supported Statuses**: `idle`, `capturing`, `stopped`, `error`

---

## 4. API Reference

All protected endpoints require session authentication (`Authorization: Bearer <token>` or session cookie).

| Method | Endpoint | Description | Auth / Role |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/login` | Authenticate with username/password (5-attempt lockout) | Public |
| `POST` | `/api/auth/logout` | Invalidate current session token | Authenticated |
| `GET` | `/api/auth/me` | Retrieve current user profile and role | Authenticated |
| `GET` | `/api/interfaces` | List available capture interfaces and capabilities | Field Engineer+ |
| `GET` | `/api/status` | Current interface and capture state | Field Engineer+ |
| `POST` | `/api/capture/start` | Start capture with interface selection and BPF filter | Field Engineer+ |
| `POST` | `/api/capture/stop` | Stop active capture session | Field Engineer+ |
| `GET` | `/api/capture/stats` | Real-time traffic statistics and protocol distribution | Field Engineer+ |
| `GET` | `/api/packets` | Query captured packets (supports `protocol`, `source`, `destination`, `search`) | Field Engineer+ |
| `POST` | `/api/packets/process` | Dissect raw packet payload or packet dict & extract metadata | Field Engineer+ |
| `GET` | `/api/admin/system` | Access administrator system controls (RBAC protected) | Administrator |

---

## 5. Running Automated Tests

Run the full automated test suite covering unit, integration, and security test cases:

```bash
python -m unittest discover -s tests -v
```

All 38 test cases pass:
- `tests/test_app.py`: API endpoints, BPF validation, token sessions, account lockout, RBAC boundary enforcement.
- `tests/test_processing.py`: Protocol parsing (Ethernet, IPv4, IPv6, TCP, UDP, DNS, HTTP, ARP, 802.11, BLE), metadata extraction, and malformed frame resiliency (SADS 3.4).
- `tests/test_capture.py`: Ring buffer drop tracking (NFR-REL-1), FIFO ordering, batch popping, and interface management.
- `tests/test_storage.py`: Tamper-evident hash-chained audit logging (SEC-REQ-5) and `.pcap` export format.

---

## 6. Sprint 1 Traceability Matrix

| Issue ID | Title | Story Points | Assignee | Requirements Addressed | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **#1** | Set up project structure and environment | 2 SP | `@shreyasgowda1956` | NFR-02, NFR-06, SADS 2.1, SADS 2.2 | **Completed** |
| **#6** | Process packets and extract metadata | 5 SP | `@shreyasgowda1956` | FR-04, FR-5, FR-6, SADS 3.4 | **Completed** |
| **#8** | Add input validation and capture error handling | 5 SP | `@YASH0212-shift` | FR-11, SADS 3.4 | Completed |
| **#14** | Add authentication and access controls | 5 SP | `@YASH0212-shift` | SEC-REQ-2, SEC-REQ-3, SEC-REQ-6 | Completed |
