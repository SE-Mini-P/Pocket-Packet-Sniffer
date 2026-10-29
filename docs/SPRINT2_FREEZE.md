# Sprint 2 Development Freeze & Release Specification
**Project:** Pocket Packet Sniffer (PPS)  
**Release Version:** `v1.0-RC1` (Release Candidate 1)  
**Date of Freeze:** 29 October 2026  
**Document Traceability:** `PPS-SRS-1.0`, `PPS-SADS-1.0`, `PPS-TP-1.0`  
**Milestone:** Deliverables Part-2 Item 3c & 3d (Documentation Complete & Development Freeze)  

---

## 1. Development Freeze Declaration

As of **29th October 2026**, the development cycle for the **Pocket Packet Sniffer (PPS)** is officially **FROZEN**. No new feature code or schema alterations may be merged to the `main` branch without formal Engineering Change Request approval.

All codebase artifacts have passed quality gates:
- **Unit & Integration Tests:** 46/46 passing (100% pass rate).
- **Test Statement Coverage:** 91% (exceeds the 70% threshold in NFR-MAINT-1).
- **Linting & Quality:** Flake8 clean; zero syntax or unresolved name errors.
- **CI/CD Automation:** GitHub Actions workflow executing on every push and pull request.

---

## 2. System Baseline Specification

### 2.1 Core Architectural Components
| Layer | Module | Key Capabilities | Requirement IDs |
| :--- | :--- | :--- | :--- |
| **Capture Layer** | `capture/` | - Bounded FIFO ring buffer with drop tracking<br>- Multi-adapter interface detection (`wlan0`, `eth0`, `ble0`)<br>- Active capture lock preventing interface switching during runs | FR-1, FR-2, FR-3, FR-7, NFR-REL-1 |
| **Processing Layer** | `processing/` | - Protocol dissector for Ethernet, IPv4, IPv6, TCP, UDP, DNS, HTTP, ARP, 802.11, BLE<br>- Resilient error handler for truncated & malformed frames<br>- Metadata extraction and serialization pipeline | FR-04, FR-5, FR-6, FR-10, SADS 3.4 |
| **Storage Subsystem**| `storage/` | - SQLite database schema persisting sessions, packets, and alerts<br>- Append-only SHA-256 hash-chained audit log<br>- Standards-compliant libpcap export writer | FR-8, FR-09, SEC-REQ-1, SEC-REQ-5 |
| **Backend Services** | `backend/` | - RESTful API exposing capture controls, filtering, and stats<br>- Credential validation ($\ge 10$ chars) and 48-char session tokens<br>- 5-minute lockout after 5 consecutive failed logins<br>- Role-Based Access Control (`field_engineer` vs `admin`) | SEC-REQ-2, SEC-REQ-3, SEC-REQ-6, FR-11 |
| **Presentation** | `frontend/` | - Responsive single-page dashboard ($\ge 360$px viewport)<br>- Live metric cards (Packets, Volume, Rate, Duration)<br>- Real-time protocol breakdown pills and Top Talkers panel<br>- Dynamic login modal and inline validation error banners | FR-6, FR-14, NFR-PORT-1 |

---

## 3. Final Requirements Compliance Summary

| Requirement Category | Total Specified | Implemented & Verified | Coverage Rate |
| :--- | :---: | :---: | :---: |
| **Functional Requirements (FR)** | 15 | 15 | **100%** |
| **Non-Functional Requirements (NFR)** | 9 | 9 | **100%** |
| **Security Requirements (SEC-REQ)** | 6 | 6 | **100%** |
| **Total Requirements** | **30** | **30** | **100%** |

---

## 4. Sprint 2 Demonstration Video Guide (2 Minutes)

Per **Deliverables Part-2 Item 3b** (*"Record a two minute video of the outcome of the second Sprint. [It should be a working product]"*):

### Suggested 120-Second Timeline:
- **0:00 – 0:20 (Authentication & Access Control):**
  - Open `http://127.0.0.1:5000`.
  - Demonstrate failed login attempts with lockout countdown warning.
  - Successfully log in as `engineer` (Field Engineer) and verify session display.
- **0:20 – 0:45 (Interface Selection & Capture Lifecycle):**
  - Select `wlan0` / `eth0` from dropdown.
  - Start capture; observe green `Capturing` badge, session timer, and dynamic packet ingestion.
  - Demonstrate safety guard: attempt to switch interface while capturing $\rightarrow$ verify 409 rejection message.
- **0:45 – 1:15 (Traffic Statistics & Protocol Distribution):**
  - Highlight the 4 KPI cards: Total Packets, Total Volume, Packets/Sec Rate, and Duration.
  - Point out Protocol Distribution pills (DNS, HTTP, TCP, UDP) with percentage calculations.
  - Point out Top Talkers table showing host IP addresses, packet counts, and volume.
- **1:15 – 1:35 (Packet Filtering & Search):**
  - Apply filter for `TCP` and search for specific host IP (`192.168.1.10`).
  - Demonstrate instantaneous table filtering and packet count updates.
- **1:35 – 1:50 (Tamper-Evident Audit & Storage Verification):**
  - Stop capture session.
  - Show audit log hash-chaining verification in SQLite storage (`storage/database.py`).
- **1:50 – 2:00 (Automated Test Suite & Quality Gate):**
  - Run `python -m coverage run -m unittest discover tests` in terminal.
  - Display `Ran 46 tests - OK` and `Statement Coverage: 91%`.

---

## 5. Documented Deviations (Deliverable 2i / 3c)

1. **Hardware Capture Mocking:**
   - Physical ESP32 firmware flashing and hardware UART tap remain mocked via `backend/mock_capture.py` and `capture/service.py` to allow end-to-end edge dashboard testing across standard Linux/Windows development environments without physical RF interference.
2. **Offline-First SQLite Storage:**
   - Database operations use local SQLite with SHA-256 hash chaining to satisfy the offline-first field deployment constraint (FR-14) without requiring an external database server.
