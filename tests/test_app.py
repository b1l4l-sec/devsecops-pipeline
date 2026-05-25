import pytest
from app.app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_home(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"VulnScan" in res.data

def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.get_json()["status"] == "healthy"

def test_scan_missing_target(client):
    res = client.post("/api/scan",
        json={},
        content_type="application/json"
    )
    assert res.status_code == 400

def test_scan_invalid_target(client):
    res = client.post("/api/scan",
        json={"target": "thisdoesnotexist.invalid"},
        content_type="application/json"
    )
    data = res.get_json()
    assert "error" in data
