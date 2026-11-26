"""The committed docs/openapi.json is the canonical API contract; it must not drift."""
from __future__ import annotations

import json
from pathlib import Path

from app.main import app

DOC = Path(__file__).resolve().parents[2] / "docs" / "openapi.json"


def test_committed_openapi_matches_the_application():
    assert DOC.exists(), "run scripts/export-openapi.py"
    committed = json.loads(DOC.read_text())
    assert committed == json.loads(json.dumps(app.openapi())), (
        "docs/openapi.json is stale: run `python ../scripts/export-openapi.py` from backend/")
