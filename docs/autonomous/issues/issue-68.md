# Issue #68 — inventory and scan workflow polish from the UI spike

**Implemented:** table/cards inventory with numeric IP sort and selection; local+UTC timestamps; honest service labels; bulk and per-device scan hand-off as prefill-only; auth-aware navigation; docs. Stacked on #27 (#84).
**Decisions:** prefill-only hand-off (all authorization stays on the Scans page/server); table is the default view; unknown address devices sort last in both directions.
**Verified:** vitest 141 passed, tsc/eslint clean; Playwright: full suite run before the last test-only edits (40 passed, 2 pre-existing inventory tests needed table selectors), inventory spec re-run 16/16 after adapting them and adding 2 tests. Full suite not re-run on the final tip.
**Not done / limits:** no formal accessibility audit (roles, labels and aria-sort only); friendly-name editing is unchanged (already preserved by reconciliation); no UI test against the real backend.
