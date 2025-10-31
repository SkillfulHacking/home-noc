# backend/tests/conftest.py
from __future__ import annotations

import os

import pytest

# Set test environment variables before any app imports
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DB_URL", "sqlite:///:memory:")


@pytest.fixture
def client():
    """Create a test client with isolated environment."""
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)
