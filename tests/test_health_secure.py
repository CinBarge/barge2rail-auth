from unittest.mock import patch


def test_health_ok(client):
    r = client.get("/health/")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@patch("common.auth.requests.get")
def test_secure_ok(mock_get, client):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "status": "ok",
        "user": {"id": "u", "roles": ["user"]},
    }
    r = client.get("/secure/", HTTP_AUTHORIZATION="Bearer test")
    assert r.status_code == 200
    assert r.json()["ok"] is True


@patch("common.auth.requests.get")
def test_secure_forbidden_without_role(mock_get, client):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "status": "ok",
        "user": {"id": "u", "roles": []},
    }
    r = client.get("/secure/", HTTP_AUTHORIZATION="Bearer test")
    assert r.status_code == 403
