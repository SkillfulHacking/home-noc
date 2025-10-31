# backend/Dockerfile
# Multi-stage, non-root, slim
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget tini && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Separate deps layer
COPY pyproject.toml /app/pyproject.toml
RUN pip install --upgrade pip && pip install --no-cache-dir -e .

# Copy source
COPY app /app/app
COPY scripts /app/scripts

# Create non-root user and data dir
RUN useradd -r -u 10001 appuser && \
    mkdir -p /data && chown -R appuser:appuser /data /app

USER appuser

EXPOSE 8000
VOLUME ["/data"]

# Gunicorn+Uvicorn workers is production-friendly; keep small footprint
CMD ["/usr/bin/tini","--","python","-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8000","--workers","1","--proxy-headers"]