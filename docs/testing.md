# Local test commands (M06)

Mirrors what `.github/workflows/ci.yml` runs. Run these from a clean checkout
before opening a PR.

## Backend

```
cd backend
python -m venv .venv && source .venv/bin/activate
python -m pip install --only-binary=:all: --upgrade pip==26.3
pip install --only-binary=:all: --require-hashes -r requirements.lock
pip install --only-binary=:all: pytest==9.2.0 pytest-cov==7.1.0 ruff==0.17.6
ruff check .
rm -f test.db
PYTHONPATH=. APP_ENV=test DB_URL=sqlite:///./test.db pytest -q
pip install --only-binary=:all: pip-audit==2.10.1
pip-audit -r requirements.lock
docker build --pull -t home-noc-api:dev .
```

## Frontend

Use Node.js 24 LTS (CI currently pins 24.22.3).

```
cd frontend
npm ci --ignore-scripts
npm run lint
npm run typecheck
npm run test
npm run build
npm audit --audit-level=high
docker build --pull -t home-noc-frontend:dev .
```

> If you added/updated a frontend dependency, run `npm install` (not `npm
> ci`) once to refresh `package-lock.json`, then commit the lockfile so CI's
> `npm ci` step stays reproducible.

## Full-stack smoke test (Compose + Nginx proxy)

This is what the `e2e-smoke` CI job automates. It exercises the same-origin
Nginx proxy (M02) and both denied/allowed sides of an API-key-protected scanner
dry-run against the real containers, not mocks. M03 will extend fail-closed
authentication to inventory reads.

```
test_env="$(mktemp)"
cp backend/.env.example "$test_env"
test_key="ci-$(openssl rand -hex 16)"
sed -i "s#^API_KEY=.*#API_KEY=${test_key}#" "$test_env"
export HOME_NOC_ENV_FILE="$test_env"

docker compose build
docker compose up -d
docker compose ps   # wait for both services to report "healthy"

curl -fsS http://localhost:3000/api/health
curl -fsS http://localhost:3000/api/version

HOME_NOC_API_KEY="$test_key" ./scripts/compose-smoke-test.sh

docker compose down -v
rm -f "$test_env"
unset HOME_NOC_ENV_FILE test_env test_key
```

## Docker Compose config validation

```
docker compose config
```

## End-to-end pipeline test (M26)
`backend/tests/test_e2e_pipeline.py` drives the real queue, worker, reconciliation, health, events and findings code over a synthetic fixture network (no packets leave the process):

1. ICMP discovery (executor fixture) creates two devices; port scans (TCP fixture) add open ports only (refused is not open) and a re-run duplicates nothing.
2. SNMPv3 poll through a fake agent derives the `switch` role and captures interfaces without touching the device MAC.
3. UniFi sync (mocked controller) merges into the **same** switch by IP and binds MAC/vendor, adds the AP: three devices, no duplicates; curated/derived fields are not overwritten.
4. An approved Nuclei run (scripted binary) yields one finding on the known HTTP service.
5. Health is online for all, events show one discovery per device, and none of the stored secrets (SNMP passphrases, UniFi token) appears in job results, observations, findings or events.

Fault cases: cancellation of a running job (inventory untouched), non-retryable timeout, crashing executor retried then failed with no raw exception text stored, restart recovery of a job abandoned mid-run, and a scheduler failure that must not stop job processing.

Browser coverage: the Playwright suite (mocked API, run by the `frontend` CI job) covers sign-in, inventory, scans, overview, connectors and findings flows, including secret masking. Fixtures are synthetic: real TCP/SNMP/UniFi/Nuclei behaviour is covered by the per-component tests (loopback SNMPv3 agent, real pinned Nuclei) and still needs hardware validation.
