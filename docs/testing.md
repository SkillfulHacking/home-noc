# Local test commands (M06)

Mirrors what `.github/workflows/ci.yml` runs. Run these from a clean checkout
before opening a PR.

## Backend

```
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
ruff check .
rm -f test.db
APP_ENV=test DB_URL=sqlite:///./test.db pytest -q
pip install pip-audit==2.10.1
pip-audit -r requirements.txt
docker build --pull -t home-noc-api:dev .
```

## Frontend

Use Node.js 24 LTS (CI currently pins 24.22.3).

```
cd frontend
npm ci
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
