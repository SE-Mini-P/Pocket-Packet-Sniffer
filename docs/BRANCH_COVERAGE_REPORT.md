# Branch Coverage Report
**Project:** Pocket Packet Sniffer (PPS)  
**Document ID:** PPS-BCR-1.0  
**Associated Documents:** `PPS-SRS-1.0`, `PPS-SADS-1.0`, `PPS-TP-1.0`, `PPS-TR-1.0` ([`TEST_RESULTS.md`](TEST_RESULTS.md))  
**Execution Date:** 16 November 2026  
**Tool:** Coverage.py 7.17.3 (`--branch` mode), Python `unittest` runner  
**Requirement Traceability:** NFR-MAINT-1, NFR-06 (automated test coverage >= 70%)  

> This report was added after the Sprint 2 freeze as a documentation-only addendum
> (see `SPRINT2_FREEZE.md` §6). No production code was changed to produce it. Every
> number below was measured by running the existing 92-test suite against the `main`
> branch at commit `5256a1e`.

---

## 1. Executive Summary

```
======================================================================
Branch Coverage Summary (production + test modules):
- Tests Executed:           92 / 92 passing
- Total Statements:         2,270   -> Statement Coverage: 91.9%
- Total Branches:           466     -> Branch Coverage:    71.9%
- Partially Covered Branches: 83   (missed branch arcs: 131)
- Combined (stmt+branch):   88.5%   (the figure `coverage report` gates on)
- Quality Gate (>= 70%):    PASSED
----------------------------------------------------------------------
Production code only (excluding tests/):
- Statements: 1,425 -> 87.6%   Branches: 430 -> 71.4%   Combined: 83.9%
======================================================================
```

**Branch coverage** counts each outcome of every decision point (`if`/`elif`/`else`,
loops, `try/except`, boolean short-circuits) separately. It is a stricter measure than
statement coverage: a line can be executed while one of its two outcomes is never
exercised. This is why branch coverage (71.9%) is lower than statement coverage (91.9%).

Result against the target in NFR-MAINT-1 / NFR-06 (>= 70%): **met**, both on the
combined metric used by the CI gate (88.5%) and on the pure branch metric (71.9%).
Margin on the pure branch metric is thin, and two modules sit below 70% (see §3).

---

## 2. Per-Module Results

| Module | Stmts | Branches | Partial Br. | Missed Br. | Stmt Cov | Branch Cov | Combined |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `backend/app.py` | 361 | 114 | 16 | 38 | 85.3% | 66.7% | 80.8% |
| `backend/auth.py` | 69 | 24 | 6 | 6 | 87.0% | 75.0% | 83.9% |
| `backend/mock_capture.py` | 208 | 54 | 6 | 8 | 88.0% | 85.2% | 87.4% |
| `capture/__init__.py` | 4 | 0 | 0 | 0 | 100.0% | n/a | 100.0% |
| `capture/buffer.py` | 47 | 8 | 1 | 1 | 93.6% | 87.5% | 92.7% |
| `capture/interfaces.py` | 17 | 0 | 0 | 0 | 100.0% | n/a | 100.0% |
| `capture/service.py` | 48 | 14 | 3 | 3 | 91.7% | 78.6% | 88.7% |
| `processing/__init__.py` | 5 | 0 | 0 | 0 | 100.0% | n/a | 100.0% |
| `processing/error_handling.py` | 26 | 2 | 1 | 1 | 96.2% | 50.0% | 92.9% |
| `processing/metadata.py` | 43 | 6 | 2 | 2 | 95.3% | 66.7% | 91.8% |
| `processing/parser.py` | 195 | 86 | 20 | 44 | 73.3% | 48.8% | 65.8% |
| `processing/zeek_engine.py` | 182 | 70 | 12 | 12 | 95.1% | 82.9% | 91.7% |
| `storage/__init__.py` | 4 | 0 | 0 | 0 | 100.0% | n/a | 100.0% |
| `storage/database.py` | 54 | 8 | 1 | 1 | 94.4% | 87.5% | 93.5% |
| `storage/exporter.py` | 144 | 42 | 7 | 7 | 89.6% | 83.3% | 88.2% |
| `storage/pcap_store.py` | 18 | 2 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| `tests/test_app.py` | 307 | 8 | 1 | 1 | 99.7% | 87.5% | 99.4% |
| `tests/test_capture.py` | 72 | 6 | 1 | 1 | 98.6% | 83.3% | 97.4% |
| `tests/test_export.py` | 103 | 2 | 1 | 1 | 99.0% | 50.0% | 98.1% |
| `tests/test_performance.py` | 58 | 8 | 1 | 1 | 98.3% | 87.5% | 97.0% |
| `tests/test_processing.py` | 107 | 2 | 1 | 1 | 99.1% | 50.0% | 98.2% |
| `tests/test_storage.py` | 59 | 4 | 2 | 2 | 98.3% | 50.0% | 95.2% |
| `tests/test_zeek.py` | 139 | 6 | 1 | 1 | 99.3% | 83.3% | 98.6% |
| **TOTAL** | **2,270** | **466** | **83** | **131** | **91.9%** | **71.9%** | **88.5%** |

Column notes: *Partial Br.* = decision points where only one outcome was exercised;
*Missed Br.* = individual untaken branch arcs; *Combined* = Coverage.py's
`(covered statements + covered branches) / (statements + branches)`.

---

## 3. Gap Analysis (Modules Below Target)

| Module | Branch Cov | Main uncovered areas (from `coverage report --show-missing`) | Risk |
| :--- | ---: | :--- | :--- |
| `processing/parser.py` | 48.8% | IPv6 dissection (lines 217-234), ICMP dissection and type decoding (381-393), unknown-EtherType / unknown-IP-protocol fallbacks (124-127, 199-202) and the generic unexpected-exception handler (94-96) | Medium. Truncated/malformed Ethernet and IPv4 handling is covered by `TC-ERR-01` tests; the gap is IPv6/ICMP decoding and fallback paths. |
| `backend/app.py` | 66.7% | Batch-packet input handling for Zeek analyze (495-509), non-default CSV export data types such as `alerts` / `zeek` / summary (608-624, 636-651) and the JSON session-report variant (725-732) | Low-Medium. Main request paths and all validation 400/409 paths are covered. |

Per-module combined coverage for both still exceeds 65%, and the project-level gate is met.
These two modules are the first candidates if further tests are added; no decision to
change scope has been taken since the development freeze.

Full line/branch-level detail for every module (including the exact untaken branches,
shown as `line->line` arcs) is produced by:

```bash
python -m coverage run --branch -m unittest discover -s tests
python -m coverage report --show-missing
```

---

## 4. Methodology and Reproduction

```bash
pip install -r requirements.txt coverage
python -m coverage erase
python -m coverage run --branch -m unittest discover -s tests   # 92 tests
python -m coverage report --show-missing --fail-under=70        # gate
python -m coverage html -d coverage-report/html                 # browsable report
```

- **CI integration:** `.github/workflows/ci.yml` now runs the suite with `--branch`,
  enforces the >= 70% gate, and uploads the HTML / XML / JSON reports as the
  `coverage-report` build artifact on every push and pull request.
- **Environment of this measurement:** local run, Python 3.14.7 and Coverage.py 7.17.3.
  CI uses Python 3.10; percentages should be identical or within rounding because no
  version-specific code is involved. Check the latest CI artifact for the authoritative
  CI figure.
- **Scope:** both production packages (`backend`, `capture`, `processing`, `storage`) and
  `tests/` are included, matching how `TEST_RESULTS.md` reports coverage. The
  production-only figures are given in §1 for reference.

---

## 5. Relation to Previous Reports

`TEST_RESULTS.md` reports **statement** coverage (92%). That figure is unchanged
(91.9% rounds to 92%; total statements are 2,270, not the 2,279 quoted earlier, which
predates the final test edits). This report adds the **branch** dimension required for
the final evaluation.
