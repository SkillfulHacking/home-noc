# Issue #21 (M18) — persisted findings with dedupe and redaction

**Implemented:** `findings`/`finding_events` (migration 0013, round trip tested), `app/findings.py` (fingerprint dedupe, lifecycle, audit trail, redaction), worker persistence hook in `persist_scan_result`, Nuclei results now carry scanned `urls`, `finding_opened` event, `/api/v1/findings` API + suppress/unsuppress. Stacked on #20.
**Decisions:** resolve only after complete runs that covered URL+template; suppression sticky; device match by unique IP; alert events only for medium+; DB-level severity-then-recency ordering (a page-local sort I first wrote was wrong — caught by my own pagination test).
**Tests:** 14 findings tests (dedupe, lifecycle, partial runs, suppression, redaction, ambiguity, events, API) + migration; backend 764 passed/2 skipped; ruff clean.
**Limits:** Nuclei only; no UI (#27).
