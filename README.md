# home-noc
Home NOC is a self-hosted, local-first network operations center for homelab and small-infrastructure admins: authorized discovery and port scanning, a deduplicated device inventory, SNMPv3 and UniFi enrichment, health and events, and opt-in vulnerability findings — all in one Docker Compose stack with SQLite.

**Status:** 0.1.0-beta.1 (MVP beta). See [`CHANGELOG.md`](CHANGELOG.md), [`docs/release.md`](docs/release.md) (versions, upgrade, rollback, what is and is not verified) and [`docs/supported-devices.md`](docs/supported-devices.md).

## Quick start
```bash
bash scripts/bootstrap.sh --http      # creates backend/.env (admin verifier) and secrets/credential_key; use without --http behind TLS
docker compose up -d --build --wait   # backend, scanner worker, connector worker, frontend
```
Open http://127.0.0.1:3000 and sign in as the administrator you created. Full steps, TLS/reverse proxy, backups and troubleshooting: [`docs/installation.md`](docs/installation.md).

## Defaults (secure by default)
- Loopback-only web UI on port 3000; the API is not published. No default password; production auth fails closed.
- Scans: private (RFC1918) ranges only, bounded and rate-limited; public scanning, the `security` profile and the Nuclei `vuln` profile are **off**. Read [`docs/scan-safety.md`](docs/scan-safety.md) before scanning.
- Credentials (SNMPv3, UniFi token) are write-only, encrypted at rest, and usable only by the connector worker; the scanner worker never receives the key.
- Containers are unprivileged with all capabilities dropped (the scanner worker gets only a ping-socket sysctl).

## Using it
Overview (health, events, findings) → Inventory (sortable table, bulk scan hand-off) → Scans → Connectors (UniFi, SNMPv3, schedules) → Findings → Scan policy. UI guides: [`overview-ui`](docs/overview-ui.md), [`inventory-ui`](docs/inventory-ui.md), [`connectors-ui`](docs/connectors-ui.md), [`findings-ui`](docs/findings-ui.md). The API contract is [`docs/openapi.json`](docs/openapi.json).

## Operations
Backup/restore: `bash scripts/backup.sh`, `bash scripts/restore.sh` (see installation guide). Security model and runbook: [`docs/security.md`](docs/security.md).

## Troubleshooting
| Symptom | Check |
|---|---|
| Backend never healthy | `docker compose logs backend`: migration failure or invalid admin hash / key (production fails closed) |
| Credential endpoints return 503 | the key secret is missing or belongs to another database (`python -m app.dbtool check-key`) |
| Scheduled SNMP/UniFi jobs stay queued | `connector-worker` not running or `WORKER_JOB_KINDS` misspelled (the worker exits with code 2) |
| Scans rejected 403 | target outside the ceiling/policy or excluded: see the Scan policy page |
| Vulnerability scan says disabled | set `SCAN_VULN_PROFILE_ENABLED=true` for the API and scanner worker |
| Device shows "unknown" health | no recent observation yet; run a scan or poll (see [`docs/device-health.md`](docs/device-health.md)) |

## Development and testing
[`docs/testing.md`](docs/testing.md) lists the backend, frontend, browser, image, Compose and pipeline checks mirrored by CI. Engineering conventions: [`CLAUDE.md`](CLAUDE.md); autonomous-development ledger: [`docs/autonomous/`](docs/autonomous/).
