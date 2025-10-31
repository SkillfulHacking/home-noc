# backend/scripts/export_openapi.py
from __future__ import annotations

import json
from pathlib import Path

from app.main import app

openapi = app.openapi()
Path("openapi.json").write_text(json.dumps(openapi, indent=2))
print("Wrote openapi.json")
