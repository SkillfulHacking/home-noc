#!/usr/bin/env bash
# Guarded restore of a Home-NOC SQLite backup (M07).
#
#   bash scripts/restore.sh BACKUP_FILE             # only into an EMPTY data volume
#   bash scripts/restore.sh --replace BACKUP_FILE   # move the existing DB aside first
#
# BACKUP_FILE may be anywhere; a relative path is relative to the directory you
# run the command from (it is made absolute before the script changes directory).
#
# Safety rules:
#   * No backend, worker, connector-worker or frontend container may exist in ANY state (running, restarting,
#     paused, stopped, created). Run `docker compose down` first -- never with
#     -v, which deletes the database volume. This script never stops or removes
#     containers, and never removes or recreates a volume.
#   * An existing database is never overwritten, even if one appears while the
#     restore runs (no-clobber install). --replace moves the database and its
#     journal files to home_noc.db.pre-restore-<UTC time>* inside the volume,
#     rolling back if any step fails; nothing is deleted. Typing REPLACE (or
#     HOME_NOC_RESTORE_CONFIRM=REPLACE) is required.
#   * The backup is validated (integrity_check, schema) and must match the
#     configured credential encryption key before anything is changed. For
#     backups from before the key-verifier table, every stored credential must
#     decrypt under that key.
set -euo pipefail
umask 077

fail() { echo "ERROR: $*" >&2; exit 1; }

CALLER_PWD="$PWD"
# Absolute form of a path given relative to the caller's directory (resolved
# before the cd below, so the backup is found wherever it lives).
abspath() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$CALLER_PWD" "$1" ;;
  esac
}

REPLACE=()
if [ "${1:-}" = "--replace" ]; then
  REPLACE=(--replace)
  shift
fi
[ $# -eq 1 ] || fail "usage: restore.sh [--replace] BACKUP_FILE"
BACKUP="$(abspath "$1")"
[ -f "$BACKUP" ] || fail "backup file not found: $BACKUP"
[ "$(head -c 15 "$BACKUP")" = "SQLite format 3" ] || fail "not a SQLite backup: $BACKUP"

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
command -v docker >/dev/null || fail "docker is required"
# `ps -a` lists containers in every state. If Compose cannot answer, refuse:
# an unknown state must never be treated as "no containers".
if ! containers="$(docker compose ps -a -q backend worker connector-worker frontend 2>/dev/null)"; then
  fail "could not determine whether the stack's containers exist; refusing to restore"
fi
[ -z "$containers" ] \
  || fail "backend/worker/connector-worker/frontend containers exist (running, restarting, paused or stopped). Remove them first with: docker compose down   (do NOT add -v: that deletes the database volume)"

if [ ${#REPLACE[@]} -gt 0 ] && [ "${HOME_NOC_RESTORE_CONFIRM:-}" != "REPLACE" ]; then
  [ -t 0 ] || fail "--replace needs a terminal confirmation or HOME_NOC_RESTORE_CONFIRM=REPLACE"
  read -r -p "This moves the existing database aside and installs $BACKUP. Type REPLACE to continue: " answer
  [ "$answer" = "REPLACE" ] || fail "confirmation not given; nothing changed"
fi

# One-off container with the same volume, env file and key secret as the stack.
# --no-deps: nothing else starts. The backup arrives on stdin.
docker compose run --rm --no-deps -T backend \
  python -m app.dbtool restore ${REPLACE[@]+"${REPLACE[@]}"} < "$BACKUP"

echo
echo "Restored. Verify the key, then start the stack:"
echo "  docker compose run --rm --no-deps -T backend python -m app.dbtool check-key"
echo "  docker compose up -d"
echo "The key in secrets/credential_key must be the one that was active for this backup."
