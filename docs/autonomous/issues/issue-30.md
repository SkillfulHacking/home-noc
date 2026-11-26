# Issue #30 (M27) — security hardening and abuse-case review

**Implemented:** docs/security.md (threat model, abuse-case/control/test table, findings register, runbook); fixes: production API docs/schema disabled, nginx CSP + hardening headers + body cap, `.dockerignore` for both images; tests: ~180 scan-target bypass cases, prod-docs exposure (fresh interpreter in prod mode), log/response redaction canaries, nginx header tests. The key-isolation fix (#77) is registered as finding #1. Stacked on #86.
**Verified:** backend 887 passed/2 skipped; nginx headers and CSP verified on the real built frontend image (login page renders with no CSP violations in Chromium); worker/connector isolation verified earlier on real containers.
**Not done / limits:** not an independent pentest; dependency/image scan results are those of CI (not re-run locally here beyond earlier pip-audit); no MFA/key-rotation (accepted, documented); CSP keeps `style-src 'unsafe-inline'` because of React inline styles.
