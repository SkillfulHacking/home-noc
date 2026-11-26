"""Validate a Claude --output-format json report; track incremental cost."""
import json
import sys
import time
from pathlib import Path

INCOMPLETE = {"error_max_turns", "error_max_budget_usd", "error_max_budget"}


def main() -> int:
    report, expected = Path(sys.argv[1]), sys.argv[2]
    ledger = Path(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else None
    try:
        data = json.loads(report.read_text())
        if not isinstance(data, dict):
            raise ValueError("expected an object")
        actual = data.get("session_id")
        if expected and actual != expected:
            raise ValueError(f"session ID mismatch: {actual!r}")
        subtype = data.get("subtype")
        cost = data.get("total_cost_usd")
        if subtype not in INCOMPLETE:
            if data.get("is_error") is True:
                raise ValueError("Claude indicated an error")
            if not isinstance(data.get("result"), str) or not data["result"].strip():
                raise ValueError("Claude returned no result text")
    except (OSError, ValueError) as exc:
        print(f"Claude report could not be validated: {exc}", file=sys.stderr)
        return 1

    if isinstance(cost, (int, float)) and not isinstance(cost, bool) and ledger:
        prev = 0.0
        sid = data.get("session_id") or ""
        if ledger.is_file():
            for line in ledger.read_text().splitlines():
                parts = line.split("\t")
                if len(parts) == 4 and parts[1] == sid:
                    try:
                        prev = float(parts[2])
                    except ValueError:
                        pass
        delta = cost - prev if cost >= prev else cost
        with ledger.open("a") as fh:
            fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\t{sid}\t{cost}\t{delta:.4f}\n")
        print(f"Session cumulative cost (client estimate): ${cost}; incremental this pass: ${delta:.4f}")
    else:
        print(f"Reported session cost (estimate): ${cost if cost is not None else 'not reported'}")

    if subtype in INCOMPLETE:
        print(f"INCOMPLETE: {subtype}. Work is preserved; rerun with --resume "
              "(consider raising MAX_TURNS / MAX_BUDGET_USD).", file=sys.stderr)
        print(f"Partial result: {data.get('result', '(none)')}")
        return 3
    print(f"Result: {data['result']}")
    return 0


raise SystemExit(main())
