# PrivWatch 3.0 — Automated Testing Guide

PrivWatch 3.0 maintains a comprehensive test suite powered by `pytest`.

---

## 1. Running the Test Suite

Execute the entire test suite with verbose output:

```bash
python3 -m pytest -v
```

Execute a specific test category:
```bash
# Unit tests for scanners
python3 -m pytest -v tests/test_scanners.py

# Forensic correlation logic
python3 -m pytest -v tests/test_correlation.py

# API integration tests
python3 -m pytest -v tests/test_api_integration.py

# Security and path traversal validation
python3 -m pytest -v tests/test_security_validation.py
```

---

## 2. Test Architecture & Structure

All tests run in isolated temporary directories (`temp_dir` fixture) with dedicated SQLite in-memory or temporary databases. Synthetic test data is strictly labeled with `is_test_fixture=True`.

| Test File | Category | Coverage |
|-----------|----------|----------|
| `tests/test_event_normalization.py` | Unit | Data models (`SecurityEvent`, `Finding`, `Incident`, `TelemetryHealth`), evidence hashing, mathematical posture calculation. |
| `tests/test_scanners.py` | Unit | Red Team audit scanners: SUID, Sudo, Capabilities, Cron, Passwd, Kernel version parsing, PATH hijacking. |
| `tests/test_log_parsers.py` | Unit | Multi-format timestamp parsing (RFC3164, ISO-8601, Auditd), auth.log collector normalization. |
| `tests/test_correlation.py` | Unit | Multi-factor correlation: user matching, chronological validation, web shell to privesc, burst detection. |
| `tests/test_remediation.py` | Unit | Controlled remediation plan generation, dry-run default safety, confirmation enforcement. |
| `tests/test_exporters.py` | Unit | JSON serialization, ReportLab PDF generation, CSV exports. |
| `tests/test_api_integration.py` | Integration | FastAPI endpoints: dashboard, overview, findings, system info, monitoring lifecycle, report generation. |
| `tests/test_security_validation.py` | Security | Path traversal rejection, credential redaction (hashes and private keys), command execution safety. |

---

## 3. Bytecode Compilation Check

Before every release, verify that all Python files compile without syntax errors:

```bash
python3 -m compileall .
```

