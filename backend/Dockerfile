# backend/Dockerfile  (patched: install via requirements.txt, not editable package)
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget tini && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps
COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install --no-cache-dir -r /app/requirements.txt

# Copy source and runtime assets
COPY app /app/app
COPY scripts /app/scripts
COPY entrypoint.sh /app/entrypoint.sh
COPY alembic.ini /app/alembic.ini
COPY alembic /app/alembic

# Runtime user & perms
RUN useradd -r -u 10001 appuser && \
    chmod +x /app/entrypoint.sh && \
    mkdir -p /data && chown -R appuser:appuser /data /app

USER appuser

EXPOSE 8000
VOLUME ["/data"]

CMD ["/usr/bin/tini","--","/app/entrypoint.sh"]
