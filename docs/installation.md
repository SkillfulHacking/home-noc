# Installing Home-NOC with Docker Compose

Home-NOC runs as two containers: `frontend` (Nginx + React, published on `127.0.0.1:3000` -
this machine only, unless you opt in to more, see "Network exposure") and `backend` (FastAPI +
SQLite, **not** published on the host). Nginx proxies `/api/*` to the backend over the internal
Compose network, so the browser only ever talks to one origin.

The Compose project name is fixed to `home-noc` (`name:` in `docker-compose.yml`), so the data
volume is `home-noc_api_data` wherever the checkout lives. There are no fixed `container_name`s and
no shared `image:` tags: containers, networks, volumes and built images are all named after the
project. To run a second stack on the same host (development, test, staging) give it its own name:
`COMPOSE_PROJECT_NAME=home-noc-dev docker compose up -d` (or `docker compose -p home-noc-dev ...`).
The same variable must be used for every later command on that stack, including the scripts.

## Prerequisites
- Docker Engine with the Compose v2 plugin (`docker compose version`).
- `bash`, `base64`, `curl` on the host; a terminal (the admin password is typed at a prompt).
- Nothing else: no Python or Node is needed on the host.

## First run
From a clean checkout:

```bash
# HTTPS / behind a TLS reverse proxy (recommended; Secure session cookies):
bash scripts/bootstrap.sh
# OR, trusted loopback/LAN over plain HTTP only (explicitly disables Secure cookies):
bash scripts/bootstrap.sh --http

docker compose up -d --build
```

`bootstrap.sh` creates two **untracked** files and never overwrites existing ones:

| File | Purpose |
| --- | --- |
| `backend/.env` (mode 600) | Copy of `backend/.env.example` plus `ADMIN_PASSWORD_HASH` and `SESSION_COOKIE_SECURE`. |
| `secrets/credential_key` | Random 256-bit key protecting stored connector credentials. |

- The password (min. 12 characters, **no default**) is typed in a network-less throwaway
  container and only its PBKDF2-SHA256 verifier is stored. Nothing secret appears in command
  arguments, logs, images or Git.
- The key is generated once. Re-running the script keeps an existing key (it also tightens an
  existing key directory to mode 700, and refuses a key location directly in the checkout root,
  `/` or `$HOME`) and refuses to touch an existing `backend/.env`. **Copy `secrets/credential_key`
  to a password manager now** - it is not in database backups, and without it stored credentials
  are unrecoverable.
- The password step builds a throwaway image under a private, per-run tag
  (`home-noc-bootstrap:<pid>-<random>`) and removes that tag afterwards; it never uses or
  overwrites a tag that belongs to a Compose project.
- The generated verifier must match the exact format `pbkdf2_sha256$<iterations>$<salt>$<digest>`
  (single-quoted; at least 100000 iterations; base64 of a 16-byte salt and a 32-byte digest) on a
  single line; anything else aborts before any file is written.
- The verifier is written in single quotes (`ADMIN_PASSWORD_HASH='pbkdf2_sha256$...'`) because
  Compose interpolates `$` in env files. Keep the quotes if you edit the file by hand.
- The key file is mode 444 inside a 700 `secrets/` directory so the container user (UID 10001)
  can read the bind-mounted secret while other host users cannot traverse to it.

### `SESSION_COOKIE_SECURE`
Production defaults to Secure cookies, which browsers send only over HTTPS. The bootstrap writes
the value explicitly: `true` by default, `false` only with `--http`. If you log in over
`http://host:3000` with `true`, the login "succeeds" but the browser never returns the cookie
(current Chromium and Firefox do accept Secure cookies on `http://localhost`; Safari may not -
verify in your browser). Fix it by adding TLS (preferred) or, for a trusted LAN only, setting
`SESSION_COOKIE_SECURE=false` in `backend/.env` and restarting. The setting is never relaxed
automatically, and `false` should only ever accompany a loopback or trusted-LAN bind.

## Upgrading from M04 (inline `CREDENTIAL_ENCRYPTION_KEY`)
If your existing `backend/.env` sets `CREDENTIAL_ENCRYPTION_KEY=...` (the M04 way) and you have
stored credentials, **do not bootstrap a new key**: a different key cannot open them, and Home-NOC
refuses it. `scripts/bootstrap.sh` detects this and stops without changing anything. Move the
*same* key to the secret-file configuration instead. Compose sets
`CREDENTIAL_ENCRYPTION_KEY_FILE` itself, and having both variables set is rejected by design, so
the inline line must go. Nothing below prints the key.

```bash
bash scripts/backup.sh                       # 1. back up first
docker compose down                          #    (never -v)
umask 077
mkdir -p secrets && chmod 700 secrets
# 2. Paste the existing value when prompted (copy it from backend/.env; it is not echoed):
IFS= read -rsp 'Existing credential key: ' K; echo
printf '%s\n' "$K" > secrets/credential_key; unset K
chmod 444 secrets/credential_key             #    readable by the container user (UID 10001)
# 3. Edit backend/.env: delete the CREDENTIAL_ENCRYPTION_KEY=... line (keep a copy of the key in
#    your password manager first). Keep ADMIN_PASSWORD_HASH and the other settings as they are.
# 4. Prove the key is unchanged, read-only, before starting anything:
docker compose run --rm --no-deps -T backend python -m app.dbtool check-key
docker compose up -d --build
```
`check-key` exits 0 only if the key in `secrets/credential_key` opens this database (the key
verifier matches, or, for a database that predates the verifier, every stored credential
decrypts). A non-zero exit means the pasted value differs from the original: restore the original
key; nothing was modified. If you ever ran the old bootstrap, keep the existing key file; the new
one never overwrites it.

**Project name and data volume.** Older checkouts let Compose derive the project name from the
directory (e.g. `home-noc-m07`), so the volume is `<directory>_api_data`. The fixed name
`home-noc` would then point at a different, *empty* volume. Before the first `docker compose up`
after upgrading, find your volume (`docker volume ls | grep api_data`) and, if it is not
`home-noc_api_data`, keep using it by exporting the old name for every command:
`export COMPOSE_PROJECT_NAME=<directory-name-in-lowercase>` (put it in a root `.env` file next to
`docker-compose.yml` to make it permanent). Do not delete either volume.

## Scan policy: fresh install vs upgrade (M08A)
Routine scan authorization is managed in the browser (Settings → Security → Scan Policy), not
in `backend/.env`; no restart is needed for changes. Migration `0007_scan_policy` runs with the
backend's normal `alembic upgrade head` and seeds one policy row:

| Situation | Seeded policy |
| --- | --- |
| Fresh install | Private RFC1918 scanning **on** (targets still chosen explicitly), public **off**. |
| Upgrade, `SCAN_ALLOWED_CIDRS` set | Private on; that env list stays an **immutable ceiling** the UI cannot widen. |
| Upgrade, `SCAN_ALLOWED_CIDRS` empty | Private **off** (previous "refuse everything" is preserved); an administrator must enable it. |

`SCAN_ALLOW_PUBLIC=false` stays an immutable block on public scanning; `true` never authorizes
anything by itself. Back up first (`bash scripts/backup.sh`). Rollback: restore the backup, or
`docker compose run --rm --no-deps backend alembic downgrade 0006_scan_jobs` (drops only the
policy and its audit tables; the older release then authorizes from the environment alone).
If the policy cannot be read the backend and worker deny every scan. See `docs/scan-scope.md`.

## Access
Open <http://localhost:3000> (or `https://your-host` behind a proxy). Sign in as `admin`
(`ADMIN_USERNAME` in `backend/.env`) with the password you chose.

## Start, stop, status
```bash
docker compose up -d            # start (backend must be healthy before frontend starts)
docker compose ps               # both services should report "healthy"
docker compose logs -f backend
docker compose stop             # stop, keep data
docker compose down             # remove containers, KEEP the data volume
# docker compose down -v        # DANGER: also deletes the database volume
```
On every start the backend runs `alembic upgrade head` once, then launches the API. A failed
migration stops the container with a clear `FATAL: database migration failed` message. `/health`
returns 503 if the database is unreachable or its schema is incomplete.

## Network exposure
- Frontend: `HOME_NOC_FRONTEND_BIND` defaults to `127.0.0.1:3000`, i.e. **this machine only**.
  The bundled Nginx speaks plain HTTP, so reaching it from other machines is an explicit choice:
  - **HTTPS (recommended for anything beyond this machine):** keep the loopback default and put a
    TLS reverse proxy on the same host in front (next section).
  - **Trusted LAN over plain HTTP:** `HOME_NOC_FRONTEND_BIND=0.0.0.0:3000` (or one LAN address,
    e.g. `192.168.1.10:3000`) *and* bootstrap with `--http` (or set `SESSION_COOKIE_SECURE=false`).
    Anyone on that network can read the session and the admin password in transit; never expose
    this port to the internet. Set the variable in your shell or in a root `.env` file, not in
    `backend/.env` (Compose reads it for port publishing).
  - Check the result with `docker compose port frontend 80`.
- Backend: **not published**. For development only, opt in with the override file (loopback by
  default; override with `HOME_NOC_BACKEND_BIND`):
  `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d`
- Containers run without privilege, with all Linux capabilities dropped (the frontend keeps only
  `CHOWN`, `SETGID`, `SETUID`, `NET_BIND_SERVICE` for Nginx). The backend is UID 10001, read-only
  root filesystem. No scanner capabilities (`NET_RAW`, ...) are granted and active scanning is
  not enabled.

## TLS and reverse proxy
The bundled Nginx speaks plain HTTP. For anything beyond loopback, terminate TLS in front of it
(Caddy, Traefik, Nginx, ...) and forward to `127.0.0.1:3000` (the default bind). The proxy must send
`X-Forwarded-Proto: https` and `Host`, pass `/` unchanged (including `/api/`), and should not add
CORS headers. Keep `SESSION_COOKIE_SECURE=true`. Do not expose port 3000 directly to the internet.

## Updating
```bash
bash scripts/backup.sh                 # always back up first
git pull
docker compose build --pull
docker compose up -d                   # new backend runs pending migrations, then starts
```
Rolling back an image after a schema migration may need a database restore (below).

## Backups
```bash
bash scripts/backup.sh                 # writes backups/home-noc-<UTC>.sqlite3 (file 600, dir 700)
bash scripts/backup.sh /mnt/nas/noc    # alternative directory
```
- A relative destination (argument or `HOME_NOC_BACKUP_DIR`) is relative to the directory you run
  the command from, wherever the checkout is; with neither, backups go to `<checkout>/backups`.
- An existing backup file is never overwritten. If the destination name appears while a backup
  runs, the script fails (non-zero, no "Backup written" message) instead of silently skipping.
  The one-second-resolution name means two backups in the same second collide: wait and retry.
- **Backups are not encrypted.** Although credentials inside are encrypted and the key is not
  included, a backup file exposes the whole inventory (hostnames, IPs, MACs, notes, scan
  observations, session metadata) and every other non-credential table. Keep it in a private
  location (the script creates the file mode 600) and encrypt it yourself (e.g. `age`, `gpg`, an
  encrypted volume) before copying it to a NAS or cloud storage.
- The running backend takes the snapshot via SQLite's **online backup API** and verifies it with
  `PRAGMA integrity_check`; the live file is never copied directly. It contains devices,
  identities, observations, admin sessions (token digests only) and **encrypted** credentials.
- It does **not** contain `secrets/credential_key`. Store the key separately; pair every backup
  with the key that was active when it was taken.
- Never copy `/data/home_noc.db` out of the volume by hand while the stack is running.

## Restore and recovery
The restore is deliberately guarded and non-destructive:

```bash
docker compose down                                   # never add -v
bash scripts/restore.sh backups/home-noc-<time>.sqlite3
docker compose run --rm --no-deps -T backend python -m app.dbtool check-key
docker compose up -d
```
- `BACKUP_FILE` can be anywhere (a relative path is relative to where you run the command).
- **No service container may exist, in any state.** The script asks Compose for the backend and
  frontend containers with `ps -a` and refuses if any is running, restarting, paused, stopped or
  merely created, or if Compose cannot answer. Run `docker compose down` first - **without `-v`**,
  which would delete the database volume. The script never stops, removes or recreates anything
  itself.
- Works without `--replace` only into an **empty** data volume. If any database file, journal or
  even a dangling symlink occupies the name it refuses. The final install is a no-clobber
  hard-link, so a database that appears *while* the restore runs is also never overwritten.
- To replace an existing database: `bash scripts/restore.sh --replace <backup>` (type `REPLACE`,
  or set `HOME_NOC_RESTORE_CONFIRM=REPLACE`). The database and its `-journal`/`-wal`/`-shm` files
  are moved (never deleted) to `home_noc.db.pre-restore-<UTC>[-n]*` inside the volume. If any step
  fails, every move is rolled back; if a rollback cannot complete, the error lists where the
  original files are preserved. Delete the `pre-restore` files yourself once you are satisfied.
- A refused or failed restore never modifies the backup file or the existing database.
- Before anything is installed the backup is checked (SQLite header, integrity, schema) and the
  configured key must match it; a mismatch aborts with nothing changed. A backup taken **before**
  the key-verifier table existed (schema older than `0005`) has no verifier, so it is accepted only
  if every stored credential decrypts under the configured key; otherwise it is refused. If the
  key binding cannot be verified at all the restore is refused, not deferred.

Full disaster recovery on a new host:
1. Check out the repo, run `bash scripts/bootstrap.sh`, then **replace** the generated
   `secrets/credential_key` with your saved key (`chmod 444`; keep `secrets/` at 700).
   The bootstrap-created key is brand new and would not match the backup.
2. `docker compose build`, then `bash scripts/restore.sh <backup>` (volume is empty).
3. `docker compose up -d`. Sign in with the admin password in your new `backend/.env`.

If the key is lost, the database is still restorable with `--skip-key-check` run manually
(`docker compose run --rm --no-deps -T backend python -m app.dbtool restore --skip-key-check < backup`),
but stored credentials stay unusable; see "Master key mismatch and recovery" in
`docs/connector-credentials.md`.

## Troubleshooting
| Symptom | Likely cause / fix |
| --- | --- |
| `env file backend/.env not found` | Run `bash scripts/bootstrap.sh` first. |
| `bind source path ... credential_key does not exist` | Bootstrap not run, or `HOME_NOC_CREDENTIAL_KEY_FILE` wrong. |
| Backend exits with `ADMIN_PASSWORD_HASH is required` / `not usable` | Env file lacks a valid verifier; check it is single-quoted and unbroken. |
| `FATAL: database migration failed` | Read the alembic output (`docker compose logs backend`); restore the last backup if needed. |
| Backend `unhealthy`; `/health` 503 | Database missing/unmigrated/unreadable; check logs and the volume. |
| Login works but you are logged out immediately | Secure cookie over HTTP; use HTTPS or see `SESSION_COOKIE_SECURE`. |
| Credential endpoints return 503 | Key missing, unreadable (needs mode 444), or not the database's key (`python -m app.dbtool check-key`). |
| Backend refuses to start; "Set only one of CREDENTIAL_ENCRYPTION_KEY and ..._FILE" | Old inline key still in `backend/.env`; follow "Upgrading from M04". |
| Restore: "containers exist" | `docker compose down` (no `-v`), then retry. |
| Restore: "a database already exists" | Intended. Use `--replace` only if you mean it. |
| New empty install after upgrading | Project name changed; set `COMPOSE_PROJECT_NAME` to the old one (see "Upgrading from M04"). |
| Web UI unreachable from another machine | Loopback is the default; see "Network exposure". |
| Bootstrap password step fails to write | Rootless Docker/userns remapping: run it as a user whose UID maps into the container. |
| `permission denied` on `/data` after upgrading from an older release | `docker compose run --rm --user root --no-deps --entrypoint chown backend -R 10001 /data` |

## Verification
Backend (no Docker needed; run without `ANTHROPIC_API_KEY` in your environment):
```bash
cd backend && ruff check . && pytest -q
pytest -q tests/test_m07_deployment.py tests/test_m07_scripts.py   # this feature only
```
Compose and scripts:
```bash
docker compose -f docker-compose.yml config -q   # needs backend/.env and secrets/credential_key
bash -n scripts/bootstrap.sh scripts/backup.sh scripts/restore.sh scripts/ci-restore-integration.sh
shellcheck --shell=bash scripts/bootstrap.sh scripts/backup.sh scripts/restore.sh scripts/ci-restore-integration.sh
cd frontend && npm ci && npm run build
docker compose build && docker compose up -d && docker compose ps
./scripts/compose-smoke-test.sh                  # proxy/auth smoke test on :3000
docker compose exec backend id -u                # 10001
curl -sS --max-time 3 http://127.0.0.1:8000/health || echo "backend correctly not published"
docker compose port frontend 80                  # 127.0.0.1:3000 unless you opted in to more
bash scripts/backup.sh
```
CI runs the full backup -> stop (volume kept) -> refused/wrong-key/real restore -> restart cycle
against a disposable project with `scripts/ci-restore-integration.sh`. That script refuses to run
unless `COMPOSE_PROJECT_NAME` starts with `home-noc-ci-`; never point it at a real stack.
