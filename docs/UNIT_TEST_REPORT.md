# Unit Test Report
**Project:** Pocket Packet Sniffer (PPS)  
**Document ID:** PPS-UTR-1.0  
**Associated Documents:** `PPS-SRS-1.0`, `PPS-SADS-1.0`, `PPS-TP-1.0`, [`TEST_RESULTS.md`](TEST_RESULTS.md)  
**Execution Date:** 16 November 2026  
**Runner:** `python -m unittest discover -s tests` (Python 3.14.7 local; Python 3.10 in CI)  

## 1. Summary

Unit tests exercise a single layer in isolation (no HTTP stack): capture buffer and service, packet
dissection, storage and audit log, the Zeek-style analysis engine, and the export formatters.

```
Unit tests executed:  38   Passed: 38   Failed: 0   Errors: 0
Full suite (unit + system validation): 92 / 92 passing
```

| Layer | Test class | Tests | Result |
| :--- | :--- | ---: | :---: |
| Capture | `CaptureLayerTest` | 6 | PASS |
| Processing | `PacketProcessingTest` | 11 | PASS |
| Storage | `StorageLayerTest` | 4 | PASS |
| Analysis (Zeek) | `ZeekAnalysisEngineTest` | 12 | PASS |
| Export | `AnalysisExporterTest` | 5 | PASS |
| **Total** | | **38** | **PASS** |

System-level (API and performance) tests are in [`SYSTEM_VALIDATION_REPORT.md`](SYSTEM_VALIDATION_REPORT.md);
coverage is in [`BRANCH_COVERAGE_REPORT.md`](BRANCH_COVERAGE_REPORT.md).

## 2. Unit Test Cases

> **Test Plan Ref legend.** IDs `TC-FUNC-01..07`, `TC-PERF-08`, `TC-REL-09`, `TC-SEC-01..03` are the
> baseline cases defined in `TestPlan_Pocket_Packet_Sniffer.pdf` (PPS-TP-1.0). **Added (S2)** marks automated
> test cases written during Sprint 2 that have no baseline Test Plan ID (input validation, error handling,
> alerts, audit log, telemetry, Zeek and export internals). They are listed as deviations in
> `SPRINT2_FREEZE.md` §5. The reference mapping is by feature area; the authoritative list of what each test
> does is the test source itself.

### `CaptureLayerTest` (`tests/test_capture.py`) - 6 tests

| Test Method | Verifies | Test Plan Ref | SRS / SADS Req | Result |
| :--- | :--- | :--- | :--- | :---: |
| `test_buffer_batch_pop` | Buffer batch pop | TC-REL-09 | NFR-REL-1 | **PASS** |
| `test_buffer_bounded_capacity_and_overflow_tracking` | Buffer bounded capacity and overflow tracking | TC-REL-09 | NFR-REL-1 | **PASS** |
| `test_buffer_push_pop_basic` | Buffer push pop basic | TC-REL-09 | NFR-REL-1 | **PASS** |
| `test_capture_service_interface_selection` | Capture service interface selection | TC-FUNC-01 | FR-02 | **PASS** |
| `test_capture_service_lifecycle` | Capture service lifecycle | TC-FUNC-01 | FR-03, FR-7 | **PASS** |
| `test_interfaces_catalog` | Interfaces catalog | TC-FUNC-01 | FR-02 | **PASS** |

### `PacketProcessingTest` (`tests/test_processing.py`) - 11 tests

| Test Method | Verifies | Test Plan Ref | SRS / SADS Req | Result |
| :--- | :--- | :--- | :--- | :---: |
| `test_corrupted_ipv4_version_handled_gracefully` | Corrupted ipv4 version handled gracefully | Added (S2) | SADS 3.4 | **PASS** |
| `test_empty_packet_handled_gracefully` | Empty packet handled gracefully | Added (S2) | SADS 3.4 | **PASS** |
| `test_metadata_extractor_and_statistics` | Metadata extractor and statistics | Added (S2) | FR-6 | **PASS** |
| `test_parse_arp_request_and_reply` | Parse arp request and reply | Added (S2) | FR-04, FR-5 | **PASS** |
| `test_parse_ble_advertisement_frame` | Parse ble advertisement frame | TC-FUNC-03 | FR-01 | **PASS** |
| `test_parse_http_payload_detection` | Parse http payload detection | Added (S2) | FR-04, FR-5 | **PASS** |
| `test_parse_valid_ipv4_tcp_frame` | Parse valid ipv4 tcp frame | Added (S2) | FR-04, FR-5 | **PASS** |
| `test_parse_valid_ipv4_udp_dns_frame` | Parse valid ipv4 udp dns frame | Added (S2) | FR-04, FR-5 | **PASS** |
| `test_parse_wifi_beacon_frame` | Parse wifi beacon frame | Added (S2) | FR-04, FR-5 | **PASS** |
| `test_truncated_ethernet_frame_handled_gracefully` | Truncated ethernet frame handled gracefully | Added (S2) | SADS 3.4 | **PASS** |
| `test_truncated_ipv4_header_handled_gracefully` | Truncated ipv4 header handled gracefully | Added (S2) | SADS 3.4 | **PASS** |

### `StorageLayerTest` (`tests/test_storage.py`) - 4 tests

| Test Method | Verifies | Test Plan Ref | SRS / SADS Req | Result |
| :--- | :--- | :--- | :--- | :---: |
| `test_alerts_storage_and_filtering` | Alerts storage and filtering | Added (S2) | FR-08 | **PASS** |
| `test_audit_log_detects_tampering` | Audit log detects tampering | Added (S2) | SEC-REQ-5 | **PASS** |
| `test_audit_log_hash_chaining` | Audit log hash chaining | Added (S2) | SEC-REQ-5 | **PASS** |
| `test_pcap_exporter_writes_valid_header_and_records` | Pcap exporter writes valid header and records | TC-FUNC-05 | FR-8 | **PASS** |

### `ZeekAnalysisEngineTest` (`tests/test_zeek.py`) - 12 tests

| Test Method | Verifies | Test Plan Ref | SRS / SADS Req | Result |
| :--- | :--- | :--- | :--- | :---: |
| `test_arp_spoofing_detection_triggers_notice` | Arp spoofing detection triggers notice | TC-FUNC-06 | FR-10 | **PASS** |
| `test_clear_resets_state` | Clear resets state | Added (S2) | FR-04 | **PASS** |
| `test_conn_log_generation_on_tcp_packet` | Conn log generation on tcp packet | TC-FUNC-04 | FR-5 | **PASS** |
| `test_conn_state_transition_on_reply` | Conn state transition on reply | TC-FUNC-04 | FR-5 | **PASS** |
| `test_dns_log_generation` | Dns log generation | TC-FUNC-04 | FR-5 | **PASS** |
| `test_get_logs_filtering_and_limits` | Get logs filtering and limits | TC-FUNC-04 | FR-5 | **PASS** |
| `test_illegal_tcp_flags_syn_and_fin_weird_log` | Illegal tcp flags syn and fin weird log | TC-FUNC-04 | FR-5 | **PASS** |
| `test_log_entry_to_tsv` | Log entry to tsv | TC-FUNC-04 | FR-5 | **PASS** |
| `test_malformed_packet_routed_to_weird_log` | Malformed packet routed to weird log | Added (S2) | FR-11 / SADS 3.4 | **PASS** |
| `test_port_scan_heuristic_triggers_notice` | Port scan heuristic triggers notice | Added (S2) | FR-10 | **PASS** |
| `test_summary_statistics` | Summary statistics | Added (S2) | FR-6 | **PASS** |
| `test_traffic_flood_detection_triggers_notice` | Traffic flood detection triggers notice | Added (S2) | FR-10 | **PASS** |

### `AnalysisExporterTest` (`tests/test_export.py`) - 5 tests

| Test Method | Verifies | Test Plan Ref | SRS / SADS Req | Result |
| :--- | :--- | :--- | :--- | :---: |
| `test_export_csv_empty_returns_empty_string` | Export csv empty returns empty string | TC-FUNC-05 | FR-9, FR-10 | **PASS** |
| `test_export_csv_headers_and_nested_serialization` | Export csv headers and nested serialization | TC-FUNC-05 | FR-9, FR-10 | **PASS** |
| `test_export_html_report_contains_required_sections` | Export html report contains required sections | TC-FUNC-05 | FR-9, FR-10 | **PASS** |
| `test_export_json_valid_formatting` | Export json valid formatting | TC-FUNC-05 | FR-9, FR-10 | **PASS** |
| `test_export_pcap_structure_and_magic_header` | Export pcap structure and magic header | TC-FUNC-05 | FR-8 | **PASS** |


## 3. Reproduction

```bash
python -m unittest discover -s tests -v
python -m unittest tests.test_capture tests.test_processing tests.test_storage   # selected modules
```
