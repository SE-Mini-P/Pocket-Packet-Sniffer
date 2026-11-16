# System Validation Report
**Project:** Pocket Packet Sniffer (PPS)  
**Document ID:** PPS-SVR-1.0  
**Associated Documents:** `PPS-SRS-1.0`, `PPS-SADS-1.0`, `PPS-TP-1.0`, [`PERFORMANCE_REPORT.md`](PERFORMANCE_REPORT.md)  
**Execution Date:** 16 November 2026  
**Runner:** `python -m unittest discover -s tests` against the Flask test client (no mocked HTTP layer)  

## 1. Summary

System validation tests drive the assembled application end to end through its REST API:
authentication and RBAC, capture control, filtering, statistics, alerts, Zeek analysis endpoints, exports,
error responses, and performance / resource telemetry.

```
System validation tests executed:  54   Passed: 54   Failed: 0   Errors: 0
Full suite (unit + system validation): 92 / 92 passing
```

| Area | Test class | Tests | Result |
| :--- | :--- | ---: | :---: |
| Capture, auth, RBAC, filters, stats, alerts, errors | `CaptureApiTest` | 35 | PASS |
| Zeek analysis API | `ZeekApiIntegrationTest` | 5 | PASS |
| Export and report API | `ExportApiIntegrationTest` | 11 | PASS |
| Performance and resources | `PerformanceAndResourceTest` | 3 | PASS |
| **Total** | | **54** | **PASS** |

## 2. Scope and Limits of Validation

- Validation runs against the simulated capture adapter (`backend/mock_capture.py`), as documented in
  `SPRINT2_FREEZE.md` §5. Tests that the Test Plan defines for real hardware (live WiFi channel capture,
  30-minute sustained load at 1,000 pkt/s, iperf3 at 5,000 pkt/s, Wireshark opening an exported PCAP,
  encryption at rest `TC-SEC-01`, alert acknowledgment `TC-FUNC-07`) were **not** executed as written (no automated test exists for `TC-SEC-01` / `TC-FUNC-07`; the storage mode is labelled `mock_encrypted_sqlite`);
  the automated tests above are the software-level equivalents (e.g. the burst test pushes 2,500 frames through
  a 500-frame buffer). The manual demo videos in `docs/demos/` show the dashboard behaviour.
- The performance figures are in [`PERFORMANCE_REPORT.md`](PERFORMANCE_REPORT.md).

## 3. System Validation Test Cases

> **Test Plan Ref legend.** IDs `TC-FUNC-01..07`, `TC-PERF-08`, `TC-REL-09`, `TC-SEC-01..03` are the
> baseline cases defined in `TestPlan_Pocket_Packet_Sniffer.pdf` (PPS-TP-1.0). **Added (S2)** marks automated
> test cases written during Sprint 2 that have no baseline Test Plan ID (input validation, error handling,
> alerts, audit log, telemetry, Zeek and export internals). They are listed as deviations in
> `SPRINT2_FREEZE.md` §5. The reference mapping is by feature area; the authoritative list of what each test
> does is the test source itself.

### `CaptureApiTest` (`tests/test_app.py`) - 35 tests

| Test Method | Verifies | Test Plan Ref | SRS / SADS Req | Result |
| :--- | :--- | :--- | :--- | :---: |
| `test_404_error_handler_returns_json` | 404 error handler returns json | Added (S2) | SADS 3.4 | **PASS** |
| `test_account_lockout_after_five_failed_attempts` | Account lockout after five failed attempts | TC-SEC-02 | SEC-REQ-6 | **PASS** |
| `test_capture_history_contains_analysis_results` | Capture history contains analysis results | Added (S2) | FR-8 | **PASS** |
| `test_get_alerts_endpoint` | Get alerts endpoint | Added (S2) | FR-08 | **PASS** |
| `test_get_alerts_filtered_by_severity` | Get alerts filtered by severity | Added (S2) | FR-08 | **PASS** |
| `test_get_alerts_oversized_filter_returns_400` | Get alerts oversized filter returns 400 | Added (S2) | FR-11 | **PASS** |
| `test_get_alerts_search_filter` | Get alerts search filter | Added (S2) | FR-08 | **PASS** |
| `test_get_capture_statistics` | Get capture statistics | Added (S2) | FR-05, FR-6 | **PASS** |
| `test_get_capture_stats_returns_metrics` | Get capture stats returns metrics | Added (S2) | FR-05, FR-6 | **PASS** |
| `test_get_interfaces_endpoint` | Get interfaces endpoint | TC-FUNC-01 | FR-02 | **PASS** |
| `test_get_interfaces_returns_supported_list` | Get interfaces returns supported list | TC-FUNC-01 | FR-02 | **PASS** |
| `test_login_short_password_rejected` | Login short password rejected | TC-SEC-02 | SEC-REQ-2 | **PASS** |
| `test_login_success_and_logout` | Login success and logout | TC-SEC-02 | SEC-REQ-2 | **PASS** |
| `test_packet_filters_match_supported_fields` | Packet filters match supported fields | TC-FUNC-02 | FR-06 | **PASS** |
| `test_post_alert_success` | Post alert success | Added (S2) | FR-08 | **PASS** |
| `test_post_alert_validation_errors` | Post alert validation errors | Added (S2) | FR-11 | **PASS** |
| `test_process_packet_with_dictionary` | Process packet with dictionary | Added (S2) | FR-04, FR-5 | **PASS** |
| `test_process_packet_with_malformed_hex_returns_400` | Process packet with malformed hex returns 400 | Added (S2) | FR-11 / SADS 3.4 | **PASS** |
| `test_process_packet_with_raw_hex` | Process packet with raw hex | Added (S2) | FR-04, FR-5 | **PASS** |
| `test_query_filter_length_validation` | Query filter length validation | Added (S2) | FR-11 | **PASS** |
| `test_rbac_admin_enforcement` | Rbac admin enforcement | TC-SEC-03 | SEC-REQ-3 | **PASS** |
| `test_select_interface_during_active_capture_returns_409` | Select interface during active capture returns 409 | TC-FUNC-01 | FR-02 | **PASS** |
| `test_select_interface_missing_payload_returns_400` | Select interface missing payload returns 400 | Added (S2) | FR-11 | **PASS** |
| `test_select_invalid_interface_returns_400` | Select invalid interface returns 400 | Added (S2) | FR-11 | **PASS** |
| `test_select_valid_interface` | Select valid interface | TC-FUNC-01 | FR-02 | **PASS** |
| `test_start_and_stop_capture` | Start and stop capture | TC-FUNC-01 | FR-03, FR-7 | **PASS** |
| `test_start_capture_with_disallowed_filter_chars_returns_400` | Start capture with disallowed filter chars returns 400 | TC-SEC-03 | SEC-REQ-3 | **PASS** |
| `test_start_capture_with_invalid_interface_returns_400` | Start capture with invalid interface returns 400 | Added (S2) | FR-11 | **PASS** |
| `test_start_capture_with_oversized_filter_returns_400` | Start capture with oversized filter returns 400 | Added (S2) | FR-11 | **PASS** |
| `test_start_capture_with_valid_interface` | Start capture with valid interface | TC-FUNC-01 | FR-02 | **PASS** |
| `test_stats_protocol_distribution_accurate` | Stats protocol distribution accurate | Added (S2) | FR-05, FR-6 | **PASS** |
| `test_stats_top_talkers_aggregated` | Stats top talkers aggregated | Added (S2) | FR-05, FR-6 | **PASS** |
| `test_stop_without_capture_returns_error` | Stop without capture returns error | TC-FUNC-01 | FR-03, FR-7 | **PASS** |
| `test_system_performance_endpoint` | System performance endpoint | Added (S2) | NFR-01, NFR-07 | **PASS** |
| `test_unknown_capture_session_returns_not_found` | Unknown capture session returns not found | Added (S2) | SADS 3.4 | **PASS** |

### `ZeekApiIntegrationTest` (`tests/test_zeek.py`) - 5 tests

| Test Method | Verifies | Test Plan Ref | SRS / SADS Req | Result |
| :--- | :--- | :--- | :--- | :---: |
| `test_api_zeek_analyze_packet` | Api zeek analyze packet | TC-FUNC-04 | FR-5 | **PASS** |
| `test_api_zeek_logs_all` | Api zeek logs all | TC-FUNC-04 | FR-5 | **PASS** |
| `test_api_zeek_logs_by_type` | Api zeek logs by type | TC-FUNC-04 | FR-5 | **PASS** |
| `test_api_zeek_logs_invalid_type_returns_400` | Api zeek logs invalid type returns 400 | Added (S2) | FR-11 | **PASS** |
| `test_api_zeek_stats` | Api zeek stats | TC-FUNC-04 | FR-5 | **PASS** |

### `ExportApiIntegrationTest` (`tests/test_export.py`) - 11 tests

| Test Method | Verifies | Test Plan Ref | SRS / SADS Req | Result |
| :--- | :--- | :--- | :--- | :---: |
| `test_api_export_csv_packets` | Api export csv packets | TC-FUNC-05 | FR-9, FR-10 | **PASS** |
| `test_api_export_html_report` | Api export html report | TC-FUNC-05 | FR-9, FR-10 | **PASS** |
| `test_api_export_invalid_data_type_returns_400` | Api export invalid data type returns 400 | Added (S2) | FR-11 | **PASS** |
| `test_api_export_invalid_format_returns_400` | Api export invalid format returns 400 | Added (S2) | FR-11 | **PASS** |
| `test_api_export_json_packets` | Api export json packets | TC-FUNC-05 | FR-9, FR-10 | **PASS** |
| `test_api_export_pcap` | Api export pcap | TC-FUNC-05 | FR-8 | **PASS** |
| `test_api_session_export_json` | Api session export json | TC-FUNC-05 | FR-9, FR-10 | **PASS** |
| `test_api_session_export_missing_returns_404` | Api session export missing returns 404 | Added (S2) | FR-11 | **PASS** |
| `test_api_session_export_pcap` | Api session export pcap | TC-FUNC-05 | FR-8 | **PASS** |
| `test_api_session_report_html` | Api session report html | TC-FUNC-05 | FR-9 | **PASS** |
| `test_api_session_report_missing_returns_404` | Api session report missing returns 404 | Added (S2) | FR-11 | **PASS** |

### `PerformanceAndResourceTest` (`tests/test_performance.py`) - 3 tests

| Test Method | Verifies | Test Plan Ref | SRS / SADS Req | Result |
| :--- | :--- | :--- | :--- | :---: |
| `test_dashboard_response_times_under_threshold` | Dashboard response times under threshold | TC-PERF-08 | NFR-02 | **PASS** |
| `test_memory_boundedness_under_burst_load` | Memory boundedness under burst load | TC-REL-09 | NFR-REL-1, NFR-01 | **PASS** |
| `test_resource_observation_telemetry` | Resource observation telemetry | Added (S2) | NFR-07 | **PASS** |


## 4. Reproduction

```bash
python -m unittest tests.test_app tests.test_export tests.test_zeek tests.test_performance -v
python -m coverage run --branch -m unittest discover -s tests && python -m coverage report
```
