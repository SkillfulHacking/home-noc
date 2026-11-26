# Release guide — 0.1.0-beta.1

## Version matrix (pinned)
| Component | Version | Pin |
|---|---|---|
| Backend runtime | Python 3.12 (`python:3.12-slim`) | image digest in `backend/Dockerfile` |
| Python dependencies | see `backend/requirements.lock` | hashes enforced (`--require-hashes`); `pip-audit` in CI |
| Frontend build | Node 24.22.3 (alpine 3.24) | digest in `frontend/Dockerfile` |
| Web tier | nginx 1.30.7 (alpine 3.24) | digest in `frontend/Dockerfile` |
| Frontend dependencies | `frontend/package-lock.json` | `npm ci`, `npm audit` in CI |
| Scanner | nmap (Debian package of the pinned base) | base image digest |
| Vulnerability scanner | Nuclei v3.11.1, nuclei-templates v10.5.2 (HTTP only) | sha256 in Dockerfile, mirrored by `app/nuclei.py::PINNED` |
| Database | SQLite (single file in the `api_data` volume) | Alembic migrations 0001–0013 |
| API contract | `docs/openapi.json` | drift test in the backend suite |

## Tagging images
Compose builds images tagged `<project>-<service>`. To publish reproducible tags (nothing is pushed by this repository's tooling):
```bash
V=0.1.0-beta.1
docker build --target api    -t home-noc-api:$V        backend
docker build --target worker -t home-noc-scanner:$V    backend
docker build                 -t home-noc-frontend:$V   frontend
# connector-worker uses the api image with: command python -m app.worker, WORKER_JOB_KINDS=snmp_poll,unifi_sync
```
Scan each image (`trivy image`) before publishing; CI does this for the backend and frontend images.

## Services and readiness
| Service | Role | Credential key | Readiness |
|---|---|---|---|
| `backend` | API, applies migrations | yes (secret file) | `GET /health` (503 until DB reachable and migrated) |
| `worker` | scanner (`WORKER_JOB_KINDS=scan`) | **no** | heartbeat file touched every poll |
| `connector-worker` | SNMP/UniFi jobs | yes (secret file) | heartbeat file |
| `frontend` | nginx SPA + `/api` proxy | no | HTTP 200 on `/` |

`docker compose up -d --wait` returns only when all four report healthy.

## Fresh install
Follow `docs/installation.md` ("First run": `bash scripts/bootstrap.sh`, then `docker compose up -d --build`). Verified on this stack: fresh volume → all four services healthy, administrator login works, wrong password → 401, unauthenticated API → 401, empty inventory.

## Upgrade
1. `bash scripts/backup.sh` (and keep `secrets/credential_key` backed up separately).
2. `git fetch && git checkout <release tag>`; `docker compose build`; `docker compose up -d --wait`.
3. Migrations run automatically; check `GET /api/health` and `docker compose logs backend | grep -i migrat`.
4. Add the new `connector-worker` service (it is part of the compose file) — it needs the same key secret as `backend`.

Verified on this stack: a database at revision 0008 (with a device) upgraded to head (0013) on start, the device was preserved, new APIs answered, and a scheduled SNMP-poll job ran through the connector-worker.

## Rollback
Schema changes are additive, but the supported rollback is **restore**, not downgrade:
1. `docker compose down` (never `-v`).
2. `git checkout <previous tag>`.
3. `bash scripts/restore.sh --replace <backup taken before the upgrade>` (the current database is moved aside, never deleted).
4. `docker compose up -d --build --wait`.
Alembic downgrades exist for the new tables (0009–0013) and are tested to preserve existing data, for emergencies only.

## Backup and restore
`scripts/backup.sh` (online SQLite backup, integrity-checked, mode 0600, **not encrypted**, no key) and `scripts/restore.sh` (guarded, no-clobber, key-checked). Verified end to end on this stack: backup of a populated database → `down` → volume removed → `restore.sh` → `up` → inventory and schedules intact, login works.

## Acceptance checklist (what was and was not verified)
| Item | Evidence |
|---|---|
| Fresh install and upgrade smoke | run on real containers (above) |
| Backup/restore | run on real containers (above) |
| Scheduled job through connector-worker, key isolation | run on real containers |
| Nuclei in the pinned worker image | real binary against a throw-away loopback server |
| Browser flows | Playwright against a mocked API in CI; CSP verified on the built image |
| `/24` + UniFi + SNMP lab demo | **not performed**: needs real hardware; use `docs/supported-devices.md` and `docs/snmp-connector.md` / `docs/unifi-connector.md` lab steps |
| Independent review / pentest | Gitar review of every PR; no external pentest |

## Known limitations
- Single administrator, no MFA; plain HTTP on loopback by default (put TLS in front for LAN use).
- IPv4 only; SNMPv3 authPriv only (no v1/v2c); UniFi requires Network 9+ and an IPv4 controller address.
- Scheduling is interval-based (no calendar windows); no notification delivery (fast-follow).
- Health windows are fixed defaults (`app/health.py::FRESH_SECONDS`).
- Fixtures, not hardware, back the SNMP/UniFi/Nuclei tests beyond the loopback agent and pinned-binary checks.
