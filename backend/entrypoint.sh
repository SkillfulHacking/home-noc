#!/usr/bin/env sh
set -e

# Ensure our package is importable when Alembic loads env.py
export PYTHONPATH="/app:${PYTHONPATH}"

# Use explicit config path just in case
alembic -c /app/alembic.ini upgrade head

exec python -m uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 1 \
  --proxy-headers
