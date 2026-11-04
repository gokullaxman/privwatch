# UATU Linux Edition - Requirements Traceability Matrix

This matrix maps every functional, architectural, security, and verification requirement from the Master Implementation Directive to its corresponding subsystem, implementation files, API endpoints, dashboard interfaces, automated tests, operational evidence, and current implementation status.

---

## 1. Master Traceability Matrix

| Requirement Identifier | Directive Description | Subsystem | Implementation Files | API Endpoint | Dashboard Interface | Automated Verification Test | Implementation Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **REQ-01** | Continuous Linux monitoring directly from kernel and system sources | Telemetry Engine | `telemetry/`, `modules/blue_mode/telemetry/` | `GET /api/v1/events` | *Live Monitoring* | `test_log_parsers.py`, `test_network_telemetry.py` | IN PROGRESS |
| **REQ-02** | Comprehensive privilege escalation detection (SUID, sudoers, caps, cron, CVEs) | Detection Engine | `detection/`, `modules/red_mode/`, `core/scanner.py` | `POST /api/v1/scan/red`, `GET /api/v1/findings` | *Threat Detection*, *Security Posture* | `test_scanners.py`, `test_detection_engine.py` | IN PROGRESS |
| **REQ-03** | Multi-layer behavioural intelligence & explainable anomaly scoring | ML & Behavioural Engine | `ml/`, `models/` | `GET /api/v1/ml/status`, `POST /api/v1/ml/evaluate` | *ML Intelligence* | `test_feature_engineering.py`, `test_inference.py`, `test_model_drift.py` | IN PROGRESS |
| **REQ-04** | Multi-event chronological sequence correlation & process ancestry | Correlation Engine | `correlation/engine.py`, `modules/timeline/` | `GET /api/v1/incidents`, `GET /api/v1/timeline` | *Incident Investigation* | `test_correlation.py`, `test_correlation_engine.py` | PLANNED (Phase 6) |
| **REQ-05** | Attack-path discovery, transitive graph modeling, and choke-point prioritization | Attack-Path Engine | `attack_path/graph.py`, `traversal.py`, `prioritization.py` | `GET /api/v1/attack-paths`, `GET /api/v1/attack-graph` | *Attack-Path Explorer* | `test_attack_path_engine.py` | PLANNED (Phase 4) |
| **REQ-06** | Transparent explainable detection with feature attribution | Explainability Engine | `ml/explainability/attribution.py`, `explanation.py` | `POST /api/v1/ml/evaluate` | *Threat Detection*, *Incident Investigation* | `test_inference.py` | IN PROGRESS |
| **REQ-07** | Policy-driven prevention with declarative rules and safe rollout modes | Prevention Engine | `prevention/policy.py`, `evaluator.py`, `enforcement/` | `GET /api/v1/policies`, `POST /api/v1/policies/enforce` | *Prevention Center* | `test_prevention_engine.py` | PLANNED (Phase 8) |
| **REQ-08** | Suspicious privilege-transition disruption & runtime operation restriction | Prevention Engine | `prevention/enforcement/` (capabilities, systemd, ACLs) | `POST /api/v1/policies/evaluate` | *Prevention Center* | `test_prevention_engine.py` | PLANNED (Phase 8) |
| **REQ-09** | Safe, allowlisted least-privilege remediation with atomic rollback | Remediation Engine | `modules/response/remediation_engine.py` | `POST /api/v1/remediation/plan`, `POST /api/v1/remediation/execute` | *Security Posture* | `test_remediation.py` | IN PROGRESS |
| **REQ-10** | Multi-dimensional risk assessment (Impact, Exploitability, Path, Reliability) | Risk Engine | `risk/scoring.py`, `risk/prioritization.py` | `GET /api/v1/risk/posture` | *Security Overview* | `test_risk_engine.py` | PLANNED (Phase 7) |
| **REQ-11** | Centralized UATU Security Operations Dashboard with 11 functional views | Web Dashboard | `web/app.py`, `dashboard/` | `GET /dashboard`, `GET /api/v1/overview` | *All 11 Dashboard Pages* | `test_api_integration.py` | IN PROGRESS |
| **REQ-12** | Measured low-latency event processing and real-time alert generation | Real-Time Engine | `core/event_bus.py`, `ml/inference/model_runner.py` | `GET /api/v1/ml/status` | *Live Monitoring* | `test_inference.py`, `test_model_evaluation.py` | IN PROGRESS |
| **REQ-13** | Forensic incident timelines with cryptographic evidence hashes | Forensic Engine | `forensics/timeline.py`, `core/evidence.py`, `reports/` | `POST /api/v1/reports/generate`, `GET /api/v1/reports/download` | *Forensics & Reports* | `test_exporters.py`, `test_forensics.py` | IN PROGRESS |
| **REQ-14** | Controlled attack disruption & active containment (kill, stop, isolate, net-drop) | Containment Engine | `response/containment.py`, `privileged_service/` | `POST /api/v1/containment/execute`, `POST /api/v1/containment/verify` | *Containment Center* | `test_containment_engine.py` | PLANNED (Phase 9) |
| **REQ-15** | Strict Linux-native platform verification and capability detection | Platform Engine | `core/platform_validator.py` | `GET /api/v1/system` | *System Settings*, *Security Overview* | `test_security_validation.py` | IN PROGRESS |
| **REQ-16** | Explicit Windows rejection; Windows unsupported | Platform Engine | `core/platform_validator.py`, `privwatch.py`, `uatu.py` | N/A (Halt at startup) | N/A (Platform gate) | `test_security_validation.py` | VERIFIED |

---

## 2. Status Progression Criteria

Each requirement progresses through four strictly verified stages:
1. **PLANNED**: Architecturally defined in `docs/UATU_MIGRATION_PLAN.md`; data contracts and interfaces specified.
2. **IN PROGRESS**: Implementation files created or undergoing enhancement; initial unit tests written.
3. **IMPLEMENTED**: Fully implemented in codebase, integrated into application workflow and API/Dashboard.
4. **VERIFIED**: Passes automated unit tests, integration tests, security failure-mode tests, and independent operational verification.
