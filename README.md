# Pocket Packet Sniffer (PPS)

[![Pocket Packet Sniffer CI](https://github.com/SE-Mini-P/Pocket-Packet-Sniffer/actions/workflows/ci.yml/badge.svg)](https://github.com/SE-Mini-P/Pocket-Packet-Sniffer/actions)
![Tests](https://img.shields.io/badge/Tests-46%20passed-brightgreen)
![Coverage](https://img.shields.io/badge/Coverage-91%25-brightgreen)
![Status](https://img.shields.io/badge/Sprint%202-Frozen%20%28v1.0--RC1%29-blue)

Portable WiFi / Ethernet / BLE packet sniffer with real-time protocol analysis and a self-hosted web dashboard.
Designed for network field diagnostics, wireless site surveys, and lightweight edge anomaly detection.

Refer to the companion specifications in `docs/`:
- **Software Requirements Specification** (`docs/SRS_Pocket_Packet_Sniffer.pdf` / PPS-SRS-1.0)
- **Software Architecture & Design Specification** (`docs/SADS_Pocket_Packet_Sniffer.pdf` / PPS-SADS-1.0)
- **Software Test Plan** (`docs/TestPlan_Pocket_Packet_Sniffer.pdf` / PPS-TP-1.0)
- **Automated Test Results & Verification** ([`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md))
- **Sprint 2 Development Freeze Specification** ([`docs/SPRINT2_FREEZE.md`](docs/SPRINT2_FREEZE.md))

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
├── tests/                    # Automated Test Suite - SADS 3.5, NFR-MAINT-1 (46/46 passing)
│   ├── __init__.py
│   ├── test_app.py           # REST API, auth lockout, RBAC, and input validation tests
│   ├── test_processing.py    # Protocol dissection, metadata extraction, and malformed frame tests
│   ├── test_capture.py       # Ring buffer overflow bounds, interface detection tests
│   └── test_storage.py       # SQLite persistence, pcap exporter, and audit log integrity tests
├── docs/                     # Specifications, test evidence, demo videos & freeze reports
│   ├── demos/                # Sprint demonstration videos
│   ├── SPRINT2_FREEZE.md     # Release baseline and development freeze declaration
│   └── TEST_RESULTS.md       # Comprehensive 46-test execution and 91% coverage report
├── .github/workflows/        # CI/CD Workflows
│   └── ci.yml                # Automated GitHub Actions test & coverage gate (>= 70%)
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

### Default Authentication Credentials (SEC-REQ-2 / SEC-REQ-3)
| Username | Password | Role | Access Scope |
| :--- | :--- | :--- | :--- |
| `engineer` | `EngineerPass123!` | `field_engineer` | Capture controls, filtering, stats, traffic export |
| `admin` | `AdminPass123!` | `admin` | Full system access, configuration, admin controls |

*Note: Security policy enforces minimum 10-character passwords and locks accounts for 5 minutes after 5 consecutive failed login attempts (SEC-REQ-6).*

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
| `POST` | `/api/interfaces/select` | Select active capture interface prior to starting capture | Field Engineer+ |
| `GET` | `/api/status` | Current interface and capture state | Field Engineer+ |
| `POST` | `/api/capture/start` | Start capture with interface selection and BPF filter | Field Engineer+ |
| `POST` | `/api/capture/stop` | Stop active capture session | Field Engineer+ |
| `GET` | `/api/capture/stats` | Real-time traffic statistics and protocol distribution | Field Engineer+ |
| `GET` | `/api/packets` | Query captured packets (supports `protocol`, `source`, `destination`, `search`) | Field Engineer+ |
| `POST` | `/api/packets/process` | Dissect raw packet payload or packet dict & extract metadata | Field Engineer+ |
| `GET` | `/api/admin/system` | Access administrator system controls (RBAC protected) | Administrator |

---

## 5. Running Automated Tests & Code Coverage

Run the full automated test suite covering unit, integration, and security test cases:

```bash
# Run all 46 tests
python -m unittest discover -s tests -v

# Run with Coverage verification (enforces >= 70% threshold)
python -m coverage run -m unittest discover -s tests
python -m coverage report --fail-under=70
```

### Coverage Summary (91% Achieved)
- **Statements:** 1,232
- **Passing Tests:** 46 / 46
- **Pass Rate:** 100%
- See detailed report in [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md).

---

## 6. Sprint Backlog & Traceability Matrix

### Sprint 1: Core Capture & Dashboard MVP (36 Story Points — 100% Complete)
| Issue ID | Title | Story Points | Assignee | Requirements Addressed | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **#1** | Set up project structure and environment | 2 SP | `@shreyasgowda1956` | NFR-02, NFR-06, SADS 2.1, SADS 2.2 | **Closed (PR #20)** |
| **#2** | Build dashboard layout and capture status | 3 SP | `@oneshot-death` | FR-01, NFR-03 | **Closed (PR #3)** |
| **#4** | Detect and select network interfaces | 3 SP | `@krrish676767` | FR-02, NFR-02, SADS 3.2 | **Closed (PR #21)** |
| **#5** | Start and stop packet capture | 5 SP | `@oneshot-death` | FR-03, FR-7, SADS 3.2 | **Closed (PR #17)** |
| **#6** | Process packets and extract metadata | 5 SP | `@shreyasgowda1956` | FR-04, FR-5, FR-6, SADS 3.4 | **Closed (PR #20)** |
| **#7** | Display packet list and traffic statistics | 5 SP | `@krrish676767` | FR-05, FR-6 | **Closed (PR #21)** |
| **#8** | Add input validation and capture error handling | 3 SP | `@YASH0212-shift` | FR-11, SADS 3.4 | **Closed (PR #19)** |
| **#10** | Filter and search captured traffic | 5 SP | `@oneshot-death` | FR-06, SADS 3.2 | **Closed (PR #17)** |
| **#14** | Add authentication and access controls | 5 SP | `@YASH0212-shift` | SEC-REQ-2, SEC-REQ-3, SEC-REQ-6 | **Closed (PR #19)** |

### Sprint 2: Automated Checks & Development Freeze
| Issue ID | Title | Story Points | Assignee | Requirements Addressed | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **#16** | Complete automated checks and documentation | 5 SP | `@YASH0212-shift` | NFR-MAINT-1, NFR-06 | **Closed (PR #24)** |
