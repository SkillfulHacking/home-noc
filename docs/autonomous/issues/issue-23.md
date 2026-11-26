# Issue #23 (M20) — inventory changes and operational events

**Implemented:** `events` table (migration 0012, round trip tested), `app/events.py` (emit with cooldown dedupe, adapters, prune), hooks in reconcile (new device, new IP, new port), TCP persist (new open port), health transitions, UniFi import (managed device missing), worker retention, API `/events` (filter/search/keyset pagination/ack). Stacked on #22.
**Decisions:** transition-based events (not per-scan); per-value dedupe for address/port; 1 h flap cooldown folded into `count`; offline=critical; silent aging; ports tracked as (proto, port).
**Defects found by tests and fixed:** `_open_ports` ignored ports whose state is null (reconcile stores null); health rule let a single source with confirmed failures stay "fresh" (fixed on #22 branch).
**Tests:** 18 event tests + migration; backend 725 passed/1 skipped on file-backed SQLite; ruff clean.
**Limits:** no notification delivery; severity mapping fixed.
