"""
Tests for FastAPI Application Endpoints
======================================
"""


def test_health_endpoint(client):
    """Verify /health returns 200 OK with service details."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "AI Memory Firewall" in data["service"]


def test_health_db_endpoint(client):
    """Verify /health/db returns response structure."""
    response = client.get("/health/db")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "database" in data
