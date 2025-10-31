# backend/tests/test_health.py
from __future__ import annotations
from fastapi.testclient import TestClient
from app.main import app
import os
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DB_URL", "sqlite:///:memory:")

def test_health():
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
