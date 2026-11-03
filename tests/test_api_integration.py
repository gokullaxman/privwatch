"""
PrivWatch 3.0 - Integration Tests for REST API Endpoints
"""

from fastapi.testclient import TestClient
import pytest

from web.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_dashboard_endpoint_returns_html(client):
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "PRIVWATCH 3.0" in response.text


def test_overview_api_returns_posture_and_health(client):
    response = client.get("/api/v1/overview")
    assert response.status_code == 200
    data = response.json()
    assert 'posture' in data
    assert 'score' in data['posture']
    assert 'telemetry_health' in data
    assert 'monitoring' in data


def test_system_info_api_endpoint(client):
    response = client.get("/api/v1/system")
    assert response.status_code == 200
    data = response.json()
    assert 'hostname' in data
    assert 'kernel' in data
    assert 'os_info' in data


def test_monitoring_lifecycle_endpoints(client):
    # 1. Start monitoring
    res_start = client.post("/api/v1/monitoring/start")
    assert res_start.status_code == 200
    assert res_start.json()['monitoring'] is True

    # 2. Check status
    res_status = client.get("/api/v1/monitoring/status")
    assert res_status.status_code == 200
    assert res_status.json()['monitoring'] is True

    # 3. Stop monitoring
    res_stop = client.post("/api/v1/monitoring/stop")
    assert res_stop.status_code == 200
    assert res_stop.json()['monitoring'] is False


def test_report_generation_api(client):
    response = client.post("/api/v1/reports/generate", json={"format": "json", "mode": "red"})
    assert response.status_code == 200
    data = response.json()
    assert data['status'] == "SUCCESS"
    assert "privwatch_report" in data['output_file']

