#!/usr/bin/env bash
# Manual routing smoke test for M02 (#5): confirms the frontend's Nginx proxy
# reaches the backend through a single origin on port 3000, with /api/v1/*
# path preserved and no CORS headers exposed.
#
# Run against a stack started with: docker compose up -d --build
#
# Usage:
#   ./scripts/compose-smoke-test.sh
#   HOME_NOC_API_KEY=... ./scripts/compose-smoke-test.sh   # also exercises a protected dry-run route
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

if [[ -n "${HOME_NOC_API_KEY:-}" ]]; then
  check_in "/api/v1/scans/ping-sweep?targets=192.0.2.1&dry_run=true" "200" \
    -X POST -H "X-API-Key: ${HOME_NOC_API_KEY}"
else
  echo "Skipping protected dry-run check (set HOME_NOC_API_KEY to enable)"
fi

# Single-origin deployment: a cross-origin Origin header must never be
# echoed back, since that would signal (now-removed) cross-origin CORS
# configuration leaking into production.
cors_header="$(curl -s "${CURL_RETRY[@]}" -D - -o /dev/null \
  -H 'Origin: http://evil.example.com' "$BASE/api/health" \
  | tr -d '\r' | grep -i '^access-control-allow-origin:' || true)"
[[ -z "$cors_header" ]] || fail "Unexpected CORS header on /api/health: $cors_header"
echo "OK  /api/health has no Access-Control-Allow-Origin header"

echo "All routing smoke checks passed."
