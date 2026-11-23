#!/usr/bin/env bash
# CI-only integration test for M07: real API write -> real SQLite online backup ->
# stack down (volume kept) -> guarded restores -> restart -> data verified, plus
# container hardening checks. Run with `bash`, against a stack that is ALREADY UP
# and healthy in a DISPOSABLE Compose project:
#
#   COMPOSE_PROJECT_NAME=home-noc-ci-<id>  HOME_NOC_BASE_URL=http://127.0.0.1:<port> \
#   HOME_NOC_ADMIN_PASSWORD=<disposable>   HOME_NOC_BACKUP_DIR=<scratch dir> \
#   bash scripts/ci-restore-integration.sh
#
# It creates devices, stores a connector credential, restores with --replace and
# swaps key files, so it refuses to run unless the project name starts with
# "home-noc-ci-". It never runs `down -v` (the workflow's teardown owns that).
#
# Secrets: the admin password, session/CSRF tokens, the connector token and the
# wrong-key file contents are only ever passed through environment variables,
# stdin or private files. Nothing secret is echoed, and `set -x` is never used.
set -euo pipefail
set +x
umask 077

fail() { echo "ERROR: $*" >&2; exit 1; }
step() { echo "== $*"; }

case "${COMPOSE_PROJECT_NAME:-}" in
  home-noc-ci-*) ;;
  *) fail "refusing to run: COMPOSE_PROJECT_NAME must start with 'home-noc-ci-' (disposable stacks only)" ;;
esac
: "${HOME_NOC_BASE_URL:?set HOME_NOC_BASE_URL}"
: "${HOME_NOC_ADMIN_PASSWORD:?set HOME_NOC_ADMIN_PASSWORD}"
: "${HOME_NOC_BACKUP_DIR:?set HOME_NOC_BACKUP_DIR}"
command -v curl >/dev/null || fail "curl is required"
command -v python3 >/dev/null || fail "python3 is required"

cd "$(dirname "${BASH_SOURCE[0]}")/.."
BASE="$HOME_NOC_BASE_URL"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
JAR="$WORK/jar.txt"
CSRF=""

# --- API helpers (secrets via env/stdin only) --------------------------------

login() {
  : > "$JAR"
  HN_P="$HOME_NOC_ADMIN_PASSWORD" HN_U="${HOME_NOC_ADMIN_USERNAME:-admin}" python3 -c \
    'import json,os;print(json.dumps({"username":os.environ["HN_U"],"password":os.environ["HN_P"]}))' \
    | curl -fsS --max-time 15 -o /dev/null -c "$JAR" -X POST \
        -H 'Content-Type: application/json' --data-binary @- "$BASE/api/v1/auth/login"
  # The $6/$7 below are awk field references, not shell expansions.
  # shellcheck disable=SC2016
  CSRF="$(awk '$6=="home_noc_csrf"{print $7}' "$JAR")"
  [ -n "$CSRF" ] || fail "login did not yield a CSRF cookie"
}

create_device() {  # $1=hostname -> prints the new device id
  HN_H="$1" python3 -c \
    'import json,os;print(json.dumps({"hostname":os.environ["HN_H"],"ip":["192.0.2.50"],"discovery_method":"manual"}))' \
    | curl -fsS --max-time 15 -b "$JAR" -X POST -H 'Content-Type: application/json' \
        -H "X-CSRF-Token: $CSRF" --data-binary @- "$BASE/api/v1/devices" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])'
}

store_connector_credential() {
  # The random token is generated and sent inside Python; the shell never sees it.
  python3 -c 'import json,secrets;print(json.dumps({"secret":{"token":secrets.token_urlsafe(32)},"metadata":{"label":"ci-restore"}}))' \
    | curl -fsS --max-time 15 -o /dev/null -b "$JAR" -X PUT -H 'Content-Type: application/json' \
        -H "X-CSRF-Token: $CSRF" --data-binary @- \
        "$BASE/api/v1/credentials/connectors/unifi/unifi_api_token"
}

device_ids() {  # prints one device id per line
  curl -fsS --max-time 15 -b "$JAR" "$BASE/api/v1/devices" | python3 -c '
import json, sys
data = json.load(sys.stdin)
if isinstance(data, dict):
    data = next((v for v in data.values() if isinstance(v, list)), [])
for item in data:
    print(item["id"])'
}

# Capture first, then grep: `cmd | grep -q` under pipefail reports failure
# (SIGPIPE upstream) even when grep matched.
has_device() {
  local ids
  ids="$(device_ids)"
  grep -qx -- "$1" <<< "$ids"
}

wait_healthy() {
  local svc="$1" cid status
  for _ in $(seq 1 36); do
    cid="$(docker compose ps -q "$svc")"
    status="$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null || echo starting)"
    [ "$status" = healthy ] && return 0
    sleep 5
  done
  fail "$svc did not become healthy in time"
}

# --- data-volume probes (one-off container: no entrypoint, no migration) ------

# Run python in the backend image with the stack's /data volume mounted.
data_python() { docker compose run --rm --no-deps -T backend python -c "$1"; }
db_digest() {
  data_python "import hashlib;print(hashlib.sha256(open('/data/home_noc.db','rb').read()).hexdigest())"
}
data_listing() { data_python "import os;print(sorted(os.listdir('/data')))"; }

# Run a restore expecting a refusal: $1=expected stderr fragment, rest=command.
expect_refused() {
  local fragment="$1" rc=0
  shift
  "$@" > /dev/null 2> "$WORK/restore.err" || rc=$?
  if [ "$rc" -eq 0 ]; then
    fail "restore unexpectedly succeeded (expected a refusal)"
  fi
  grep -q -- "$fragment" "$WORK/restore.err" \
    || { cat "$WORK/restore.err" >&2; fail "refusal did not mention '$fragment' (exit $rc)"; }
  echo "OK  refused (exit $rc): $fragment"
}

# ============================================================================
step "write real data through the authenticated API"
login
ORIGINAL_ID="$(create_device ci-restore-original)"
store_connector_credential   # creates the key verifier row; wrong-key restore needs it
echo "OK  created original device and a connector credential"

step "take a real SQLite online backup"
mkdir -p -- "$HOME_NOC_BACKUP_DIR"
chmod 700 -- "$HOME_NOC_BACKUP_DIR"
bash scripts/backup.sh "$HOME_NOC_BACKUP_DIR"
BACKUPS=("$HOME_NOC_BACKUP_DIR"/home-noc-*.sqlite3)
if [ "${#BACKUPS[@]}" -ne 1 ] || [ ! -f "${BACKUPS[0]}" ]; then
  fail "expected exactly one backup file"
fi
BACKUP="${BACKUPS[0]}"
HN_BACKUP="$BACKUP" HN_ID="$ORIGINAL_ID" python3 - <<'PY'
import os, sqlite3
conn = sqlite3.connect("file:" + os.environ["HN_BACKUP"] + "?mode=ro", uri=True)
assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",), "integrity_check"
assert conn.execute("SELECT count(*) FROM devices WHERE id = ?", (os.environ["HN_ID"],)).fetchone()[0] == 1
assert conn.execute("SELECT count(*) FROM credential_key_verifier").fetchone()[0] == 1
print("OK  backup passes integrity_check and holds the original device")
PY

step "add data AFTER the backup (a correct restore must remove it)"
LATER_ID="$(create_device ci-restore-after-backup)"
has_device "$ORIGINAL_ID" || fail "original device missing before restore"
has_device "$LATER_ID" || fail "later device missing before restore"

step "container hardening: UID 10001, read-only root filesystem, backend not published"
[ "$(docker compose exec -T backend id -u)" = 10001 ] || fail "backend is not UID 10001"
BACKEND_CID="$(docker compose ps -q backend)"
[ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$BACKEND_CID")" = true ] \
  || fail "backend root filesystem is not read-only"
if docker compose exec -T backend sh -c ': > /rootfs-write-probe' 2>/dev/null; then
  fail "backend root filesystem accepted a write"
fi
docker inspect -f '{{json .NetworkSettings.Ports}}' "$BACKEND_CID" | python3 -c '
import json, sys
ports = json.load(sys.stdin) or {}
if ports.get("8000/tcp"):
    sys.exit("backend port 8000 is published on the host")'
if docker compose port backend 8000 > "$WORK/port.out" 2>/dev/null && [ -s "$WORK/port.out" ]; then
  fail "docker compose reports a published backend port"
fi
if curl -sS --max-time 3 -o /dev/null "http://127.0.0.1:8000/health" 2>/dev/null; then
  fail "backend answered on host port 8000"
fi
FRONTEND_BIND="$(docker compose port frontend 80)"
case "$FRONTEND_BIND" in
  127.0.0.1:*) ;;
  *) fail "frontend is not bound to loopback by default: $FRONTEND_BIND" ;;
esac
echo "OK  UID 10001, read-only rootfs, backend unpublished, frontend on loopback"

step "stop the stack WITHOUT deleting its volume"
docker compose down
docker volume inspect "${COMPOSE_PROJECT_NAME}_api_data" > /dev/null \
  || fail "data volume is gone after 'docker compose down'"
[ -z "$(docker compose ps -a -q)" ] || fail "containers remain after down"
DIGEST_BEFORE="$(db_digest)"
LISTING_BEFORE="$(data_listing)"

step "restore without --replace must refuse a populated database"
expect_refused "already exists" bash scripts/restore.sh "$BACKUP"
[ "$(db_digest)" = "$DIGEST_BEFORE" ] || fail "database changed by a refused restore"
[ "$(data_listing)" = "$LISTING_BEFORE" ] || fail "data volume changed by a refused restore"

step "restore with the WRONG key must fail without changing anything"
mkdir -m 700 "$WORK/wrongkey"
python3 -c 'import base64,secrets;print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())' \
  > "$WORK/wrongkey/credential_key"
chmod 444 "$WORK/wrongkey/credential_key"
expect_refused "does not match" env HOME_NOC_CREDENTIAL_KEY_FILE="$WORK/wrongkey/credential_key" \
  HOME_NOC_RESTORE_CONFIRM=REPLACE bash scripts/restore.sh --replace "$BACKUP"
[ "$(db_digest)" = "$DIGEST_BEFORE" ] || fail "database changed by a wrong-key restore"
[ "$(data_listing)" = "$LISTING_BEFORE" ] || fail "data volume changed by a wrong-key restore"

step "restore the backup with --replace and the correct key"
HOME_NOC_RESTORE_CONFIRM=REPLACE bash scripts/restore.sh --replace "$BACKUP"
[ "$(db_digest)" != "$DIGEST_BEFORE" ] || fail "restore did not change the database"
LISTING_AFTER="$(data_listing)"
grep -q "home_noc.db.pre-restore-" <<< "$LISTING_AFTER" || fail "the previous database was not kept aside"
docker compose run --rm --no-deps -T backend python -m app.dbtool check-key

step "restart and verify the original device is back (and the later one is gone)"
docker compose up -d
wait_healthy backend
wait_healthy frontend
login
has_device "$ORIGINAL_ID" || fail "original device missing after restore"
if has_device "$LATER_ID"; then
  fail "post-backup device survived the restore"
fi
echo "OK  restore verified"
