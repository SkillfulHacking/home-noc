#!/usr/bin/env python3
"""Write the canonical OpenAPI schema to docs/openapi.json (the live /docs is disabled in
production). Run from backend/:  python ../scripts/export-openapi.py [--check]

--check exits non-zero if the committed file differs from the current application schema."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("APP_ENV", "dev")
os.environ.setdefault("DB_URL", "sqlite://")

from app.main import app  # noqa: E402

TARGET = ROOT / "docs" / "openapi.json"


def render() -> str:
    return json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":
    text = render()
    if "--check" in sys.argv:
        if not TARGET.exists() or TARGET.read_text() != text:
            print("docs/openapi.json is out of date; run scripts/export-openapi.py", file=sys.stderr)
            raise SystemExit(1)
        print("docs/openapi.json is current")
    else:
        TARGET.write_text(text)
        print(f"wrote {TARGET.relative_to(ROOT)} ({len(text)} bytes)")
