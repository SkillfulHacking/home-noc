#!/usr/bin/env bash
# Manual routing smoke test for M02 (#5): confirms the frontend's Nginx proxy
# reaches the backend through a single origin on port 3000, with /api/v1/*
# path preserved and no CORS headers exposed.
#
# Run against a stack started with: docker compose up -d --build
#
# Usage:
#   ./scripts/compose-smoke-test.sh
#   HOME_NOC_ADMIN_PASSWORD=... ./scripts/compose-smoke-test.sh   # also runs session/CSRF auth checks
#     (optional HOME_NOC_ADMIN_USERNAME, default "admin"; the stack needs
#      SESSION_COOKIE_SECURE=false when tested over plain HTTP)
#   HOME_NOC_BASE_URL=http://localhost:3000 ./scripts/compose-smoke-test.sh
set -euo pipefail
fail() { echo "ERROR: $*" >&2; exit 1; }

BASE="${HOME_NOC_BASE_URL:-http://localhost:3000}"
command -v curl >/dev/null || fail "curl is required"
CURL_RETRY=(--retry 15 --retry-connrefused --retry-delay 1 --max-time 5)

# Asserts the HTTP status is one of the space-separated $allowed values.
check_in() {
  local path="$1" allowed="$2"; shift 2
  local status
  status="$(curl -s "${CURL_RETRY[@]}" -o /dev/null -w '%{http_code}' "$@" "$BASE$path")"
  for ok in $allowed; do
    if [[ "$status" == "$ok" ]]; then
      echo "OK  $path -> $status"
      return 0
    fi
  done
  fail "$path: expected one of [$allowed], got $status"
}

echo "Smoke-testing Home-NOC Compose stack at $BASE"

# /health and /version live outside the backend's /api/v1 prefix; Nginx must
# proxy them explicitly.
check_in "/api/health" "200"
check_in "/api/version" "200"

# Regression guard: a trailing slash on the Nginx proxy_pass strips the
# /api/ prefix, so /api/v1/devices would 404 instead of reaching the
# backend's /api/v1/devices route. 401 or 200 proves the path reached the
# backend; 404 means the prefix was stripped again.
check_in "/api/v1/devices" "200 401"

if [[ -n "${HOME_NOC_ADMIN_PASSWORD:-}" ]]; then
  ADMIN_USER="${HOME_NOC_ADMIN_USERNAME:-admin}"
  command -v python3 >/dev/null || fail "python3 is required for the auth checks"
  umask 077
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
  JAR="$WORK/jar.txt"
  HDRS="$WORK/login.hdrs"
  # 192.0.2.0/24 is documentation-only (RFC 5737); dry_run=true never scans.
  SCAN="/api/v1/scans/ping-sweep?targets=192.0.2.1&dry_run=true"

  # Builds the login JSON on stdin->stdout; credentials never appear in argv.
  login_body() {
    HN_U="$1" HN_P="$2" python3 -c \
      'import json,os;print(json.dumps({"username":os.environ["HN_U"],"password":os.environ["HN_P"]}))'
  }
  login() {  # $1=username $2=password, remaining args passed to curl
    local u="$1" p="$2"; shift 2
    login_body "$u" "$p" | curl -s "${CURL_RETRY[@]}" -o /dev/null -w '%{http_code}' \
      -X POST -H 'Content-Type: application/json' --data-binary @- "$@" \
      "$BASE/api/v1/auth/login"
  }
  expect() {  # $1=label $2=expected $3=actual
    [[ "$3" == "$2" ]] || fail "$1: expected $2, got $3"
    echo "OK  $1 -> $3"
  }

  # 1. Anonymous inventory read is rejected.
  check_in "/api/v1/devices" "401"

  # 2. Invalid login is rejected and sets no cookies.
  s="$(login "$ADMIN_USER" "not-the-password-$$" -c "$WORK/bad.jar")"
  expect "invalid login" 401 "$s"
  ! grep -q 'home_noc_session' "$WORK/bad.jar" 2>/dev/null \
    || fail "invalid login set a session cookie"

  # 3. Valid login succeeds and sets the session + CSRF cookies.
  s="$(login "$ADMIN_USER" "$HOME_NOC_ADMIN_PASSWORD" -c "$JAR" -D "$HDRS")"
  expect "valid login" 200 "$s"
  grep -qi '^set-cookie: home_noc_session=' "$HDRS" || fail "login did not set session cookie"
  grep -qi '^set-cookie: home_noc_csrf=' "$HDRS" || fail "login did not set CSRF cookie"
  echo "OK  login set session and CSRF cookies"
  CSRF="$(awk '$6=="home_noc_csrf"{print $7}' "$JAR")"
  [[ -n "$CSRF" ]] || fail "CSRF cookie missing from cookie jar"
  cp "$JAR" "$WORK/pre-logout.jar"

  # 4. Authenticated inventory read.
  check_in "/api/v1/devices" "200" -b "$JAR"

  # 5. Mutation without CSRF is forbidden; with CSRF it succeeds (dry run).
  check_in "$SCAN" "403" -X POST -b "$JAR"
  check_in "$SCAN" "403" -X POST -b "$JAR" -H "X-CSRF-Token: wrong-token"
  check_in "$SCAN" "200" -X POST -b "$JAR" -H "X-CSRF-Token: ${CSRF}"

  # 6. Legacy X-API-Key must not bypass authentication (value is a dummy).
  check_in "/api/v1/devices" "401" -H "X-API-Key: legacy-key-must-not-work"
  check_in "$SCAN" "401" -X POST -H "X-API-Key: legacy-key-must-not-work"

  # 7. Logout returns 204 and genuinely revokes the server-side session.
  check_in "/api/v1/auth/logout" "204" -X POST -b "$JAR" -H "X-CSRF-Token: ${CSRF}"
  check_in "/api/v1/devices" "401" -b "$WORK/pre-logout.jar"
else
  echo "Skipping session-auth checks (set HOME_NOC_ADMIN_PASSWORD to enable)"
fi

# Single-origin deployment: a cross-origin Origin header must never be
# echoed back, since that would signal (now-removed) cross-origin CORS
# configuration leaking into production.
cors_header="$(curl -s "${CURL_RETRY[@]}" -D - -o /dev/null \
  -H 'Origin: https://evil.example.com' "$BASE/api/health" \
  | tr -d '\r' | grep -i '^access-control-allow-origin:' || true)"
[[ -z "$cors_header" ]] || fail "Unexpected CORS header on /api/health: $cors_header"
echo "OK  /api/health has no Access-Control-Allow-Origin header"

echo "All routing smoke checks passed."
