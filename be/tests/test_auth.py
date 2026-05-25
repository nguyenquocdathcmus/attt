from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_login():
    response = client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "admin123"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "access_token" in payload
    assert payload.get("token_type") == "bearer"
