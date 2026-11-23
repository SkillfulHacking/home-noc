#!/usr/bin/env sh
set -eu

# New database files (and SQLite journals) are private to the app user.
umask 077

# Ensure our package is importable when Alembic loads env.py
export PYTHONPATH="/app${PYTHONPATH:+:${PYTHONPATH}}"

# Runs exactly once per container start, before the server begins listening.
# `upgrade head` is idempotent, so restarts on an up-to-date database are no-ops.
echo "entrypoint: applying database migrations (alembic upgrade head)" >&2
if ! alembic -c /app/alembic.ini upgrade head; then
  echo "entrypoint: FATAL: database migration failed; the API will not start." >&2
  echo "entrypoint: see the alembic output above and docs/installation.md (Troubleshooting)." >&2
  exit 1
fi

# Tighten modes on a database created by an older release (best effort).
python -m app.dbtool harden || echo "entrypoint: warning: could not tighten database permissions" >&2

exec python -m uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 1 \
  --proxy-headers
