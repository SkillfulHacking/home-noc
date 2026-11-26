# Security review, threat model and runbook (M27)

Scope: the code and Compose deployment on the `feat/home-noc-issue-*` stack at the time of this review. It is an engineering review with automated tests, **not** an independent penetration test.

## Assets and trust boundaries
| Asset | Where | Boundary |
|---|---|---|
| Admin session / CSRF token | API + SQLite | Browser ⇄ nginx ⇄ API (same origin) |
| Connector credentials (SNMPv3, UniFi token) | SQLite, AES-256-GCM | Key lives only in a read-only secret mounted into `backend` and `connector-worker` |
| Credential encryption key | `secrets/credential_key` | Never in the scanner worker, DB, image or env file |
| Scan authorization policy | SQLite (+ immutable env ceiling) | Enforced by API, scheduler, and again by workers |
| Inventory / findings | SQLite | Sanitized, redacted fields only |
| Untrusted input | Network responses (nmap, Nuclei, SNMP, UniFi), issue/PR text | Parsed defensively; scanner processes are separated from the key |

## Abuse cases and controls
| Abuse case | Control | Test |
|---|---|---|
| Unauthenticated access / forged state change | Session cookie (HttpOnly, SameSite), double-submit CSRF on every unsafe method, fail-closed prod auth, login throttle | `test_auth.py`, per-feature CSRF tests |
| Scan target bypass (CIDR widening, public IPs, special ranges, encodings, flag/shell injection, hostnames) | Strict IPv4/CIDR parsing, deployment ceiling, runtime policy, exclusions, per-profile host caps, no hostname resolution, argv never built from input | `test_security_hardening.py` (≈90 attempts × 2 profiles), `test_scan_scope.py` |
| Scope revoked mid-scan | Re-authorization before every dispatch; partial results never mark devices down | `test_worker.py`, `test_health.py` |
| SSRF through connectors | UniFi base URL must be `https://<IPv4>` inside the scan policy (checked on save and use, redirects refused, 10 s timeout, 5 MiB streamed cap); SNMP only to a device's own address, UDP/161 fixed; Nuclei only to known HTTP ports on authorized hosts, `-ni`, no redirects | `test_unifi_*`, `test_snmp_*`, `test_nuclei.py` |
| Malicious templates / scanner output | Explicit template allowlist from pinned, checksum-verified archive; dangerous tags/protocols excluded; out-of-scope hosts discarded; output, line and finding caps; raw request/response dropped; redaction | `test_nuclei.py`, `test_findings.py` |
| Credential theft from the scanner process | Scanner worker has no key and runs scanners with a scrubbed environment; connector worker holds the key but has no scanner binary; both unprivileged, read-only root, all capabilities dropped | Compose boundary test, verified on real containers |
| Secrets in logs / responses / DB | `SecretStr` everywhere, masked credential API, sanitized validation errors, canary tests over logs, job results, observations, findings, events | `test_security_hardening.py`, `test_e2e_pipeline.py` |
| XSS | React escaping (no `dangerouslySetInnerHTML`), CSP `script-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`, nosniff, no-referrer | `src/nginx.test.ts`, verified on the built image (page renders with no CSP violations) |
| Information disclosure via API docs | `/docs`, `/redoc`, `/openapi.json` disabled when `APP_ENV` is not dev/test | `test_security_hardening.py` |
| Resource exhaustion | Bounded page sizes/cursors, scan sizes, rate/concurrency/time limits, queue cap, per-tick scheduler budget, nginx body cap (256 KiB), response size caps, pids/memory limits in Compose | feature tests |
| Supply chain | Hash-locked Python deps (`pip-audit` in CI), `npm audit`, Trivy image scan, pinned base image digest, checksum-verified Nuclei, HTTPS-only downloads | CI |
| Build-context leaks | `.dockerignore` for frontend and backend (no `.env`, `.venv`, DBs, `node_modules`) | review |

## Findings register of this review
| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | High | Scheduled SNMP/UniFi jobs ran in the scanner worker, which must never hold the credential key | **Fixed** (connector-worker, #77), verified on real containers |
| 2 | Medium | Interactive API docs/schema reachable without authentication in production | **Fixed** |
| 3 | Medium | No browser hardening headers/CSP on the web tier | **Fixed** |
| 4 | Low | No `.dockerignore`: local `.env`/`node_modules` could enter build contexts | **Fixed** |
| 5 | Info | Compose serves plain HTTP on loopback by default | **Accepted**: terminate TLS in a reverse proxy before any LAN exposure (docs/installation.md) |
| 6 | Info | Nuclei template archive hash relies on GitHub tag archives | **Accepted**: hash mismatch fails the build; investigate before changing |
| 7 | Info | No credential-key rotation tooling | **Accepted for MVP** (documented in connector-credentials.md) |
| 8 | Info | Single local administrator account, no MFA | **Accepted for MVP**; keep the UI on loopback or behind an authenticating proxy |

No critical findings were identified. Dependency and image scans run in CI; their latest results are on the PR.

## Runbook
- **Suspected credential exposure:** rotate the exposed secret at the device/controller, overwrite it via the credentials API (`PUT` replaces in place), then check job results/logs; if the *encryption key* leaked, delete all stored credentials and re-enter them with a new key (see connector-credentials.md "Master key mismatch and recovery").
- **Unwanted scan activity:** disable the schedule (`PATCH /schedules/{id} {"enabled": false}`) and/or revoke the range in the scan policy; workers stop at the next check and fail closed. Audit lines `scan_authorization` show who authorized what.
- **Enabling vulnerability scanning:** set `SCAN_VULN_PROFILE_ENABLED=true` only for the scanner worker and API, review the plan for every run, and only against systems you own.
- **Upgrading Nuclei/templates:** change the Dockerfile `NUCLEI_*` ARGs and `app/nuclei.py::PINNED` together (a test enforces this), verify the new upstream checksums, rebuild, re-run the pipeline tests.
- **After any dependency or base-image update:** run `pip-audit -r backend/requirements.lock --require-hashes`, `npm audit`, and the Trivy job; do not merge with high/critical findings unless recorded here as accepted.
