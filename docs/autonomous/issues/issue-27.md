# Issue #27 (M24) — vulnerability findings and scan results UI

**Implemented:** `src/pages/Findings.tsx`, `src/lib/findings.ts`, route `/findings`, nav link, mock API extensions, docs/findings-ui.md. Stacked on #26 (#83).
**Decisions:** vuln scanning is a separate approval-gated panel (the generic Scans page keeps hiding intrusive profiles); status defaults to open; suppression needs a reason; digest-based approval surfaced to the operator as an explicit review+checkbox step.
**Verified:** vitest 126 passed; tsc/eslint clean; Playwright: full suite 41 passed on the first run except one new findings test whose assertion I had written wrongly (detail stays expanded after suppression); fixed, findings spec 3/3 passing. The other specs were not re-run after that test-only change.
**Limits:** not exercised against the real backend; results are shown via findings (job progress is on Scans); no bulk suppress.
