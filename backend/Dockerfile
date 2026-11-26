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

# Pinned, checksum-verified Nuclei binary and curated HTTP templates (M17, docs/nuclei.md).
# Checksums are the upstream-published sha256 values (release checksums files); bump the
# ARGs together and re-verify them when upgrading. Update checks are never run at runtime.
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_SHA256_AMD64=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_SHA256_ARM64=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07
ARG NUCLEI_TEMPLATES_VERSION=10.5.2
ARG NUCLEI_TEMPLATES_SHA256=016b7abbf931d4d1a851a5a568e44510dc61691dc8a5202e3b24e701515ec574
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) sum="$NUCLEI_SHA256_AMD64";; arm64) sum="$NUCLEI_SHA256_ARM64";; \
      *) echo "unsupported architecture $arch" >&2; exit 1;; esac; \
    mkdir -p /opt/nuclei /opt/nuclei-templates /tmp/nuclei-dl; \
    curl -fsSL -o /tmp/nuclei-dl/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${arch}.zip"; \
    echo "${sum}  /tmp/nuclei-dl/nuclei.zip" | sha256sum -c -; \
    python3 -c "import zipfile; zipfile.ZipFile('/tmp/nuclei-dl/nuclei.zip').extract('nuclei', '/opt/nuclei')"; \
    curl -fsSL -o /tmp/nuclei-dl/templates.tar.gz \
      "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz"; \
    echo "${NUCLEI_TEMPLATES_SHA256}  /tmp/nuclei-dl/templates.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/nuclei-dl/templates.tar.gz -C /opt/nuclei-templates --strip-components=1 \
      --no-same-owner --wildcards '*/http/*' '*/LICENSE.md'; \
    printf '{"nuclei": "%s", "templates": "%s"}\n' "$NUCLEI_VERSION" "$NUCLEI_TEMPLATES_VERSION" \
      > /opt/nuclei/versions.json; \
    chown -R root:root /opt/nuclei /opt/nuclei-templates; \
    chmod -R a+rX,go-w /opt/nuclei /opt/nuclei-templates; chmod 755 /opt/nuclei/nuclei; \
    rm -rf /tmp/nuclei-dl
USER appuser
VOLUME ["/data"]
CMD ["/usr/bin/tini","--","python","-m","app.worker"]

# --- api: the last stage, so it stays the default build target. -----------
FROM base AS api
EXPOSE 8000
VOLUME ["/data"]

CMD ["/usr/bin/tini","--","/app/entrypoint.sh"]
