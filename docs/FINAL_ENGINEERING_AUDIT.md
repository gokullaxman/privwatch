# UATU Linux Edition — Final Engineering Repository Audit

**Date**: 2026-11-04  
**Target Platform**: Linux (Debian 12 / Kali Linux 2024.x)  
**Architecture**: Linux-Native Privilege Escalation Detection, Prevention & Attack-Path Disruption  
**Repository**: `https://github.com/gokullaxman/privwatch`  
**Classification**: Engineering Audit & Architecture Analysis  

---

## 1. Executive Summary

This comprehensive audit inventories the code repository, evaluating architectural compliance against the Master Engineering Directive for UATU Linux Edition. All cross-platform/Windows legacy artifacts have been systematically analyzed, POSIX security boundaries verified, deterministic detection pathways audited, and containment mechanisms scoped.

---

## 2. Subsystem Inventory & Component Analysis

### 2.1 Core Subsystem (`core/`)

| Module | Primary Class / Component | Responsibilities | Security Assumptions | Gaps & Rectifications |
| :--- | :--- | :--- | :--- | :--- |
| `platform.py` | `LinuxPlatform` | Enforces strictly Linux runtime; rejects Windows/Darwin with exit code 1. | System calls must target POSIX APIs. | Hardened: Windows completely removed from execution path. |
| `command_runner.py` | `CommandRunner` | Non-shell command execution (`shell=False`), argv lists, environment scrubbing. | Subprocesses must not execute through `/bin/sh` or `/bin/bash -c`. | Complete: zero `shell=True` or shell injection vectors across codebase. |
| `event_schema.py` | `UatuEvent`, enums | Standardized event contract, provenance tagging, SHA-256 integrity hashing. | Synthetic events must never masquerade as live telemetry. | Enforced: Provenance invariants reject synthetic events with live origins. |
| `storage.py` | `StorageEngine` | SQLite WAL-mode persistence, 22 tables, immutability triggers, SHA-256 hash chaining. | SQLite DB file must be 0600; directory 0700. | Hardened: Pragma foreign keys, WAL mode, audit trail hash chain verified. |
| `health.py` | `TelemetryHealthMonitor` | Telemetry health state tracking with recovery hysteresis (threshold=3). | Telemetry sources report true state (HEALTHY, DEGRADED, UNAVAILABLE). | Hardened: Recovery hysteresis prevents state flapping. |
| `identity.py` | `PrivilegedIdentityVerifier` | Verifies caller real/effective UID, group memberships, and sudoers permissions. | Non-root users must possess verified sudoers entry for sensitive operations. | Implemented: Enforces verification and records cryptographic audit logs. |

### 2.2 Telemetry Subsystem (`telemetry/`)

| Module | Primary Class | Ingestion Mechanism | Provenance Classification |
| :--- | :--- | :--- | :--- |
| `reader.py` | `AuditLogReader` | Linux Audit Netlink / `ausearch -i` parsing | `LIVE_AUDITD` (`LIVE_TELEMETRY`) |
| `reader.py` | `AuthLogReader` | `/var/log/auth.log` / `/var/log/secure` regex parser | `LIVE_AUTH_LOG` (`LIVE_TELEMETRY`) |
| `reader.py` | `TelemetryEngine` | Event bus coordination, source aggregation | Unified event stream dispatcher |

### 2.3 Detection Subsystem (`detection/`)

| Rule ID | Detection Pattern | Target Vector | Severity | Correlation Window |
| :--- | :--- | :--- | :--- | :--- |
| `RULE_REPEATED_AUTH_FAILURES` | >=3 authentication failures within temporal window | SSH / Sudo | HIGH | 300 seconds |
| `RULE_SUDO_BRUTE_FORCE_SUCCESS` | Authentication failures followed by successful sudo command | Sudo brute force | CRITICAL | 300 seconds |
| `RULE_SUID_EXECUTION` | SUID binary execution where `euid != uid` | SUID elevation | HIGH / CRITICAL | Immediate |
| `RULE_WATCHED_FILE_EDIT` | Tampering with `/etc/sudoers`, `/etc/passwd`, `/etc/shadow` | Auth database modification | CRITICAL | Immediate |
| `RULE_WORLD_WRITABLE_EXECUTION` | Execution of elevated binary from `/tmp`, `/var/tmp`, `/dev/shm` | Trojan binary execution | CRITICAL | Immediate |
| `RULE_UNEXPECTED_PRIVILEGE_TRANSITION` | Direct `setuid` family syscall transitioning to UID 0 | Privilege escalation syscall | CRITICAL | Immediate |
| `RULE_MULTI_STAGE_ESCALATION_SEQUENCE` | Auth failures followed by SUID execution or watched file modification | Multi-stage attack chain | CRITICAL | 300 seconds |

### 2.4 Attack Path Intelligence Subsystem (`attack_path/`)

| Module | Class | Graph Library | Classification Guarantee |
| :--- | :--- | :--- | :--- |
| `graph_builder.py` | `AttackPathEngine` | `networkx.DiGraph` | Every path strictly labeled `CONFIGURATION_ONLY` |

Nodes modeled: `USER`, `GROUP`, `PROCESS`, `FILE`, `DIRECTORY`, `SERVICE`, `SYSTEMD_UNIT`, `CRON_JOB`, `SUDO_RULE`, `CAPABILITY`, `HOST`, `CONTAINER`.  
Edges modeled: `MEMBER_OF`, `OWNS`, `CAN_WRITE`, `CAN_EXECUTE`, `EXECUTED_BY`, `RUNS_AS`, `CAN_MODIFY`, `HAS_CAPABILITY`, `ESCALATES_TO`.

### 2.5 Response Subsystem (`modules/response/`)

| Module | Primary Class | Actions | Safety Guards |
| :--- | :--- | :--- | :--- |
| `containment_engine.py` | `ContainmentEngine` | Process termination, cgroups v2 / SIGSTOP freeze, nftables network containment | PID <= 2 protected, kernel threads protected, `/proc/<pid>/stat` starttime PID-reuse check, loopback/gateway protected |
| `remediation_engine.py` | `RemediationEngine` | Least-privilege chmod/chown, SUID strip, backup, rollback | Canonical path resolution, symlink bypass prevention, atomic pre-state capture, dry-run default |

### 2.6 Machine Learning Governance (`models/`, `ml/`)

| Component | Class | Security Controls |
| :--- | :--- | :--- |
| `model_registry.py` | `ModelRegistry` | Trust states (`UNVERIFIED`, `VALIDATED`, `APPROVED`, `REVOKED`), SHA-256 check against `models/manifest.json` |
| `model_runner.py` | `ModelRunner` | Graceful fallback to deterministic rule engine upon model corruption or revocation |

### 2.7 API & Dashboard Subsystem (`web/`)

| Component | Framework | Security Architecture |
| :--- | :--- | :--- |
| `app.py` | `FastAPI` | Localhost binding (127.0.0.1), token auth (0600 file), `secrets.compare_digest`, RBAC roles (`ADMIN`, `OPERATOR`, `ANALYST`, `AUDITOR`, `READ_ONLY`), CSP / security headers, rate limiting |
