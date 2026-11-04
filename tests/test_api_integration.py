"""
PrivWatch / UATU 3.0 - Integration Tests for REST API Endpoints & Security
"""

from fastapi.testclient import TestClient
import pytest

from web.app import app, API_KEY, storage
from core.models import Finding, Severity


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_headers():
    return {"X-API-Key": API_KEY}


def test_dashboard_endpoint_returns_html(client):
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "UATU LINUX" in response.text


def test_public_health_endpoints(client):
    res1 = client.get("/health")
    assert res1.status_code == 200
    res2 = client.get("/api/v1/health")
    assert res2.status_code == 200
    assert "hostname" in res2.json()


def test_overview_api_returns_posture_and_health(client, admin_headers):
    response = client.get("/api/v1/overview", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert 'posture' in data
    assert 'score' in data['posture']
    assert 'telemetry_health' in data
    assert 'monitoring' in data


def test_system_info_api_endpoint(client, admin_headers):
    response = client.get("/api/v1/system", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert 'hostname' in data
    assert 'kernel' in data
    assert 'os_info' in data


def test_unauthenticated_protected_endpoints_return_401(client):
    """Verify that unauthenticated callers to protected endpoints receive 401 Unauthorized."""
    endpoints = [
        "/api/v1/overview",
        "/api/v1/findings",
        "/api/v1/events",
        "/api/v1/incidents",
        "/api/v1/attack-paths",
        "/api/v1/system",
        "/api/v1/timeline"
    ]
    for ep in endpoints:
        res = client.get(ep)
        assert res.status_code == 401, f"Expected 401 for unauthenticated GET {ep}, got {res.status_code}"


def test_unauthenticated_mutation_rejected_with_401(client):
    """Verify that unauthenticated callers are rejected with 401 Unauthorized."""
    res = client.post("/api/v1/monitoring/start")
    assert res.status_code == 401
    assert "Unauthorized" in res.json()["detail"]


def test_invalid_api_key_rejected_with_401(client):
    """Verify that invalid API key is rejected."""
    res = client.post("/api/v1/monitoring/start", headers={"X-API-Key": "invalid-bogus-token"})
    assert res.status_code == 401


def test_monitoring_lifecycle_endpoints(client, admin_headers):
    # 1. Start monitoring with admin authentication
    res_start = client.post("/api/v1/monitoring/start", headers=admin_headers)
    assert res_start.status_code == 200
    assert res_start.json()['monitoring'] is True

    # 2. Check status
    res_status = client.get("/api/v1/monitoring/status", headers=admin_headers)
    assert res_status.status_code == 200
    assert res_status.json()['monitoring'] is True

    # 3. Stop monitoring with admin authentication
    res_stop = client.post("/api/v1/monitoring/stop", headers=admin_headers)
    assert res_stop.status_code == 200
    assert res_stop.json()['monitoring'] is False


def test_report_generation_api(client, admin_headers):
    response = client.post("/api/v1/reports/generate", json={"format": "json", "mode": "red"}, headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert data['status'] == "SUCCESS"
    assert "privwatch_report" in data['output_file']


def test_attack_paths_api_endpoint(client, admin_headers):
    res = client.get("/api/v1/attack-paths", headers=admin_headers)
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_export_item_routes(client, admin_headers):
    # Create test finding
    fnd = Finding(
        finding_id="fnd_test_export_item",
        vector="CRON",
        severity=Severity.HIGH.value,
        title="Test Cron Finding",
        affected_resource="/etc/cron.d/test",
        evidence={"owner": "root", "mode": "0777"}
    )
    storage.save_finding(fnd)

    # Export JSON
    res_json = client.get("/api/v1/reports/export/json?item_type=finding&item_id=fnd_test_export_item", headers=admin_headers)
    assert res_json.status_code == 200
    assert "attachment" in res_json.headers.get("content-disposition", "") or "filename" in res_json.headers.get("content-disposition", "")

    # Export PDF
    res_pdf = client.get("/api/v1/reports/export/pdf?item_type=finding&item_id=fnd_test_export_item", headers=admin_headers)
    assert res_pdf.status_code == 200


def test_ml_status_api_endpoint(client, admin_headers):
    response = client.get("/api/v1/ml/status", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "OPERATIONAL"
    assert "registered_models" in data
    assert "drift_monitor" in data


def test_ml_evaluate_api_endpoint(client, admin_headers):
    payload = {
        "event_type": "SUID_EXECUTION",
        "uid": 1000,
        "euid": 0,
        "pid": 4321,
        "ppid": 1000,
        "process": "bash",
        "command": "/tmp/root_bash",
        "evidence": {"exe": "/tmp/root_bash"}
    }
    response = client.post("/api/v1/ml/evaluate", json=payload, headers=admin_headers)
    assert response.status_code == 200
    res = response.json()
    assert res["predicted_class"] in ["CONFIRMED_MALICIOUS", "PRIVILEGE_TRANSITION_ANOMALY"]
    assert "anomaly_score" in res
    assert "confidence" in res
    assert "composite_risk_score" in res
    assert len(res["contributing_features"]) > 0


def test_load_api_token_generates_random_token_and_sets_0600(temp_dir, monkeypatch):
    """Verify that load_api_token generates a secure random token and stores it in the token file."""
    from web.app import load_api_token
    token_file = temp_dir / "test_token"
    monkeypatch.setenv("UATU_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("UATU_API_KEY", raising=False)
    monkeypatch.delenv("PRIVWATCH_API_KEY", raising=False)
    monkeypatch.delenv("PRIVWATCH_API_TOKEN", raising=False)

    token = load_api_token()
    assert token
    assert token != "privwatch-secure-local-admin-token"
    assert len(token) >= 32
    assert token_file.exists()
    assert token_file.read_text().strip() == token


def test_security_headers_injected_on_responses(client):
    """Verify strict security headers are injected on HTTP responses."""
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert "Content-Security-Policy" in resp.headers
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_rbac_privilege_enforcement(client):
    """Verify role-based access control blocks lower-privileged tokens from admin actions."""
    ro_headers = {"X-API-Key": "readonly-token"}

    # Read-only token can access health
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200

    # Read-only token blocked from administrative suppression endpoint with 403 Forbidden
    payload = {"vector": "SUID", "pattern": "/test", "reason": "test"}
    resp = client.post("/api/v1/suppression", json=payload, headers=ro_headers)
    assert resp.status_code == 403
    assert "Insufficient privileges" in resp.json()["detail"] or "Forbidden" in resp.json()["detail"]

    # Read-only token blocked from admin network isolation
    net_payload = {"ip": "198.51.100.5", "reason": "c2"}
    resp = client.post("/api/v1/containment/isolate-network", json=net_payload, headers=ro_headers)
    assert resp.status_code == 403


def test_containment_api_routes(client, admin_headers):
    """Verify containment endpoints accept valid requests and enforce validation."""
    # List actions
    resp = client.get("/api/v1/containment/actions", headers=admin_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # Process termination rejected for protected PID 1
    resp = client.post(
        "/api/v1/containment/terminate-process",
        json={"pid": 1, "reason": "test"},
        headers=admin_headers
    )
    assert resp.status_code == 400
    assert "protected PID 1" in resp.json()["detail"]

