#!/usr/bin/env bash
# Consistent online backup of the Home-NOC SQLite database (M07).
#
#   bash scripts/backup.sh [DEST_DIR]        # default: <checkout>/backups (or $HOME_NOC_BACKUP_DIR)
#
# A DEST_DIR (argument or $HOME_NOC_BACKUP_DIR) given as a relative path is
# relative to the directory you run the command from, not to the checkout; it
# is made absolute before the script changes directory.
#
# The running backend container takes the snapshot with SQLite's online backup
# API and streams it here; the live database file is never copied directly.
# The snapshot is integrity-checked, then stored mode 0600.
#
# The backup is NOT encrypted: it exposes the whole inventory (hosts, IPs, MACs,
# notes, observations) and other non-credential database metadata. Protect or
# encrypt the destination yourself. The credential encryption key is NOT
# included; back it up separately (secrets/credential_key).
set -euo pipefail
umask 077

fail() { echo "ERROR: $*" >&2; exit 1; }

CALLER_PWD="$PWD"
# Absolute form of a path given relative to the caller's directory. Resolved
# BEFORE the cd below, so paths outside the checkout behave as typed.
abspath() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$CALLER_PWD" "$1" ;;
  esac
}

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -n "${1:-}" ]; then
  DEST="$(abspath "$1")"
elif [ -n "${HOME_NOC_BACKUP_DIR:-}" ]; then
  DEST="$(abspath "$HOME_NOC_BACKUP_DIR")"
else
  DEST="$REPO_ROOT/backups"
fi
cd "$REPO_ROOT"

command -v docker >/dev/null || fail "docker is required"
[ -n "$(docker compose ps --status running -q backend 2>/dev/null)" ] \
  || fail "the backend container is not running (start it with: docker compose up -d)"

mkdir -p -- "$DEST"
chmod 700 -- "$DEST"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FINAL="$DEST/home-noc-$STAMP.sqlite3"
# -L: a dangling symlink occupies the name too (-e alone would miss it).
if [ -e "$FINAL" ] || [ -L "$FINAL" ]; then
  fail "$FINAL already exists; it was not touched. Wait a second and retry"
fi
PARTIAL="$(mktemp "$DEST/.home-noc-$STAMP.XXXXXX.partial")"
trap 'rm -f "$PARTIAL"' EXIT

docker compose exec -T backend python -m app.dbtool backup > "$PARTIAL" \
  || fail "backup failed; no file was kept"
[ -s "$PARTIAL" ] || fail "backup was empty; no file was kept"
[ "$(head -c 15 "$PARTIAL")" = "SQLite format 3" ] || fail "backup is not a SQLite database"

chmod 600 "$PARTIAL"
# Publish without ever replacing: ln (no -f) fails if the name exists, even if it
# appeared after the check above. Success is only reported once this succeeds.
if ln -- "$PARTIAL" "$FINAL" 2>/dev/null; then
  rm -f -- "$PARTIAL"
elif [ -e "$FINAL" ] || [ -L "$FINAL" ]; then
  fail "$FINAL appeared while the backup ran; it was NOT overwritten and this backup was not stored. Retry."
else
  # Filesystem without hard links (some network shares): mv -n skips silently
  # when the destination exists, so prove the move actually happened.
  mv -n -- "$PARTIAL" "$FINAL" 2>/dev/null || true
  [ ! -e "$PARTIAL" ] || fail "could not store the backup at $FINAL (nothing was overwritten)"
fi
[ -f "$FINAL" ] || fail "could not store the backup at $FINAL"

echo "Backup written: $FINAL"
echo "Reminder: it is not encrypted and exposes inventory data; protect or encrypt it."
echo "Reminder: it does not contain the credential encryption key; keep that backed up separately."
