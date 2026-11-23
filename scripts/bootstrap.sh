#!/usr/bin/env bash
# First-run bootstrap for Home-NOC (M07).
#
#   bash scripts/bootstrap.sh            # HTTPS / reverse-proxy deployment (Secure cookies)
#   bash scripts/bootstrap.sh --http     # plain-HTTP trusted LAN/loopback testing only
#
# Creates, from a clean checkout and WITHOUT overwriting anything:
#   backend/.env             untracked env file (copy of backend/.env.example + admin verifier)
#   secrets/credential_key   random 256-bit credential encryption key (outside the DB volume)
#
# Secrets handling: the admin password is typed at a TTY prompt inside a
# throwaway, network-less container and only its PBKDF2 verifier is written
# out. The encryption key is generated straight into a private file. No
# secret is ever passed as a command argument, printed, or baked into an image.
#
# Upgrading from M04 with an inline CREDENTIAL_ENCRYPTION_KEY in backend/.env?
# Do NOT bootstrap a new key: move the SAME key (docs/installation.md).
set -euo pipefail
umask 077

fail() { echo "ERROR: $*" >&2; exit 1; }

COOKIE_SECURE=true
case "${1:-}" in
  "" | --https) ;;
  --http) COOKIE_SECURE=false ;;
  -h | --help)
    # Print the leading comment block of this file.
    awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
    exit 0 ;;
  *) fail "unknown option '$1' (use --https, --http or --help)" ;;
esac

cd "$(dirname "${BASH_SOURCE[0]}")/.."
ENV_FILE="${HOME_NOC_ENV_FILE:-backend/.env}"
KEY_FILE="${HOME_NOC_CREDENTIAL_KEY_FILE:-secrets/credential_key}"
# A private, per-run tag. A shared tag such as home-noc-api:latest could clobber
# (or be clobbered by) an image belonging to another Compose project.
IMAGE="home-noc-bootstrap:$$-${RANDOM}${RANDOM}"

# Exact shape written by app.admin_password / app.auth.hash_password:
#   ADMIN_PASSWORD_HASH='pbkdf2_sha256$<iterations>$<salt>$<digest>'
# iterations: 6-9 digits, no leading zero (>= 100000, the production floor);
# salt: base64 of 16 bytes (22 chars + "=="); digest: base64 of 32 bytes (43 + "=").
# The regex lives in single quotes, so the shell never expands the '$' or the
# bracket expressions (a double-quoted "$[...]" is Bash arithmetic expansion).
# The literal single quotes come from $SQ and are matched exactly, not with '.'.
SQ="'"
# The dollar signs below are literal regex escapes, not expansions (SC2016).
# shellcheck disable=SC2016
VERIFIER_RE="^ADMIN_PASSWORD_HASH=${SQ}pbkdf2_sha256"'\$[1-9][0-9]{5,8}\$[A-Za-z0-9+/]{22}==\$[A-Za-z0-9+/]{43}='"${SQ}"'$'

WORK=""
KEY_TMP=""
ENV_TMP=""
cleanup() {
  [ -z "$WORK" ] || rm -rf "$WORK"
  [ -z "$KEY_TMP" ] || rm -f "$KEY_TMP"
  [ -z "$ENV_TMP" ] || rm -f "$ENV_TMP"
  docker rmi "$IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Mode of a directory as octal digits (GNU stat, then BSD/macOS stat).
dir_mode() { stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' -- "$1"; }

# The key directory must be a dedicated, owner-only directory.
ensure_private_key_dir() {
  local dir="$1" mode
  case "$dir" in
    . | / | "${HOME:-/nonexistent}" | "$PWD")
      fail "$KEY_FILE would live directly in '$dir'; use a dedicated directory (default: secrets/)" ;;
  esac
  [ -d "$dir" ] || mkdir -p "$dir"
  mode="$(dir_mode "$dir")"
  if [ "$mode" != 700 ]; then
    chmod 700 "$dir" 2>/dev/null \
      || fail "$dir has mode $mode and could not be tightened to 700; fix it (chmod 700 '$dir') and retry"
    echo "Tightened $dir from mode $mode to 700 (it holds the credential encryption key)."
  fi
}

command -v docker >/dev/null || fail "docker is required"
docker compose version >/dev/null 2>&1 || fail "the Docker Compose v2 plugin is required"
command -v base64 >/dev/null || fail "base64 is required"
[ -f backend/.env.example ] || fail "run this script from a Home-NOC checkout"
[ -t 0 ] || fail "run interactively: the admin password is read from a terminal, never a pipe"

if [ -e "$ENV_FILE" ] || [ -L "$ENV_FILE" ]; then
  # Only tests for the variable's presence; the value is never read or printed.
  if grep -Eq -e '^[[:space:]]*(export[[:space:]]+)?CREDENTIAL_ENCRYPTION_KEY[[:space:]]*=' -- "$ENV_FILE" 2>/dev/null; then
    fail "$ENV_FILE already holds an inline CREDENTIAL_ENCRYPTION_KEY (M04). Do NOT generate a new key: it would not open your stored credentials. Move the SAME key into $KEY_FILE as described in docs/installation.md (\"Upgrading from M04\"). Nothing was changed."
  fi
  fail "$ENV_FILE already exists; refusing to overwrite it. Move it aside deliberately if you really want to re-bootstrap (never delete the encryption key while credentials are stored)."
fi

WORK="$(mktemp -d)"

echo "Building the backend image (used only to hash your password)..."
docker build --quiet -t "$IMAGE" ./backend >/dev/null

# --- administrator password verifier ---------------------------------------
echo "Choose the administrator password (minimum 12 characters; no default exists)."
docker run --rm -it --network none --cap-drop ALL --security-opt no-new-privileges:true \
  --user "$(id -u):$(id -g)" -v "$WORK:/out" --entrypoint python "$IMAGE" \
  -m app.admin_password --output /out/admin_hash \
  || fail "password setup failed or was cancelled; nothing was written"
[ -s "$WORK/admin_hash" ] || fail "no verifier was produced"
# Exactly one line, matching the exact format (see VERIFIER_RE above). The line
# is only compared, never evaluated, and is not echoed on failure.
[ "$(wc -l < "$WORK/admin_hash")" -eq 1 ] || fail "unexpected verifier format"
verifier_line=""
IFS= read -r verifier_line < "$WORK/admin_hash" || true
[[ "$verifier_line" =~ $VERIFIER_RE ]] || fail "unexpected verifier format"

# --- credential encryption key (generated once, never replaced) -------------
KEY_DIR="$(dirname "$KEY_FILE")"
if [ -e "$KEY_FILE" ] || [ -L "$KEY_FILE" ]; then
  [ -f "$KEY_FILE" ] || fail "$KEY_FILE exists but is not a regular file"
  [ -s "$KEY_FILE" ] || fail "$KEY_FILE exists but is empty; restore your saved key there (nothing was changed)"
  ensure_private_key_dir "$KEY_DIR"
  chmod go-w "$KEY_FILE" 2>/dev/null || true   # the content is never touched
  echo "Keeping the existing credential encryption key at $KEY_FILE (never regenerated)."
else
  ensure_private_key_dir "$KEY_DIR"
  # Created inside the (private, same-filesystem) key directory, so the final
  # no-clobber hard link below is atomic and the key is never visible half-written.
  KEY_TMP="$(mktemp "$KEY_DIR/.credential_key.XXXXXX")"
  # 32 random bytes, urlsafe base64 (the format app.crypto expects).
  head -c 32 /dev/urandom | base64 | tr -d '\n' | tr '+/' '-_' > "$KEY_TMP"
  [ "$(wc -c < "$KEY_TMP")" -eq 44 ] || fail "key generation failed"
  echo >> "$KEY_TMP"
  # Readable by the container's UID 10001; the 0700 directory keeps other host
  # users out. ln (no -f) refuses to replace a key created concurrently.
  chmod 444 "$KEY_TMP"
  ln -- "$KEY_TMP" "$KEY_FILE" 2>/dev/null \
    || fail "$KEY_FILE appeared concurrently (or hard links are unavailable); not overwritten"
  rm -f "$KEY_TMP"
  KEY_TMP=""
  echo "Created credential encryption key: $KEY_FILE"
fi

# --- env file --------------------------------------------------------------
ENV_TMP="$(mktemp "${ENV_FILE}.XXXXXX")"
{
  cat backend/.env.example
  printf '\n# --- generated by scripts/bootstrap.sh ---\n'
  cat "$WORK/admin_hash"
  printf 'SESSION_COOKIE_SECURE=%s\n' "$COOKIE_SECURE"
} > "$ENV_TMP"
chmod 600 "$ENV_TMP"
# mv -n silently skips when the destination exists, so success is proven by the
# temp file being gone, never assumed.
mv -n "$ENV_TMP" "$ENV_FILE"
[ ! -e "$ENV_TMP" ] || fail "$ENV_FILE appeared concurrently; not overwritten"
ENV_TMP=""

echo
echo "Created $ENV_FILE (mode 600). Neither file is tracked by Git."
if [ "$COOKIE_SECURE" = false ]; then
  echo "WARNING: SESSION_COOKIE_SECURE=false. Session cookies will travel over plain HTTP."
  echo "         Keep the frontend on loopback (the default) or a trusted LAN; use HTTPS beyond that."
else
  echo "SESSION_COOKIE_SECURE=true: browsers only send the session over HTTPS (current Chromium and"
  echo "Firefox also accept it on http://localhost). For another host name put a TLS reverse proxy"
  echo "in front (docs/installation.md)."
fi
echo
echo "IMPORTANT: copy $KEY_FILE to a password manager or other offline store NOW."
echo "Database backups do not contain it; losing it makes stored credentials unrecoverable."
echo
echo "Next: docker compose up -d --build    then open http://localhost:3000"
echo "The web UI is bound to 127.0.0.1 by default. LAN or HTTPS access is an explicit opt-in via"
echo "HOME_NOC_FRONTEND_BIND (docs/installation.md, \"Network exposure\")."
