# backend/Dockerfile  (patched: install via requirements.txt, not editable package)
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
      ca-certificates curl wget tini && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps
COPY requirements.txt requirements.lock /app/
RUN pip install --no-cache-dir --only-binary=:all: --upgrade \
      pip==26.3 setuptools==84.2.1 wheel==0.48.0 && \
    pip install --no-cache-dir --only-binary=:all: --require-hashes \
      -r /app/requirements.lock && \
    pip uninstall --yes pip setuptools wheel

# Copy source and runtime assets
COPY app /app/app
COPY scripts /app/scripts
COPY entrypoint.sh /app/entrypoint.sh
COPY alembic.ini /app/alembic.ini
COPY alembic /app/alembic

# Runtime user & perms
# Normalize source permissions independently of the host checkout's umask.
# Bootstrap runs under the operator's UID; application services use UID 10001.
RUN useradd -r -u 10001 appuser && \
    chmod -R a+rX /app && \
    chmod 755 /app/entrypoint.sh && \
    mkdir -p /data && chown -R appuser:appuser /data /app

USER appuser

# --- worker (M09): the only image that carries the scanner. ---------------
# Unprivileged (appuser, no capabilities in Compose): profiles use TCP connect
# scans and `-sn`, which need no raw sockets. No port is exposed.
FROM base AS worker
USER root
RUN apt-get update && apt-get install -y --no-install-recommends nmap && \
    rm -rf /var/lib/apt/lists/*
USER appuser
VOLUME ["/data"]
CMD ["/usr/bin/tini","--","python","-m","app.worker"]

# --- api: the last stage, so it stays the default build target. -----------
FROM base AS api
EXPOSE 8000
VOLUME ["/data"]

CMD ["/usr/bin/tini","--","/app/entrypoint.sh"]
