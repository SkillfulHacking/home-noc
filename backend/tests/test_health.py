# backend/tests/test_health.py
from __future__ import annotations

from fastapi.testclient import TestClient


def test_health(monkeypatch):
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DB_URL", "sqlite:///:memory:")
    from app.main import app
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
