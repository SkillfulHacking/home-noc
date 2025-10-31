# backend/scripts/export_openapi.py
from app.main import app
import json
from pathlib import Path

openapi = app.openapi()
out = Path(__file__).resolve().parents[1] / "openapi.json"
out.write_text(json.dumps(openapi, indent=2))
print(f"Wrote {out}")
