"""Validate a Claude --output-format json report; track incremental cost.

Usage: validate_report.py [EXPECTED_SESSION] < report.json [3>>ledger.tsv]
Environment HN_LEDGER holds the previous ledger text. No file paths are taken
from the command line; the caller supplies stdin and an optional append fd 3.
"""
import json
import os
import sys
import time

INCOMPLETE = {"error_max_turns", "error_max_budget_usd", "error_max_budget"}


def main() -> int:
    expected = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        ledger = os.fdopen(3, "a")
    except OSError:
        ledger = None
    try:
        data = json.loads(sys.stdin.read())
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
    except ValueError as exc:
        print(f"Claude report could not be validated: {exc}", file=sys.stderr)
        return 1

    if isinstance(cost, (int, float)) and not isinstance(cost, bool) and ledger:
        prev = 0.0
        sid = data.get("session_id") or ""
        for line in os.environ.get("HN_LEDGER", "").splitlines():
            parts = line.split("\t")
            if len(parts) == 4 and parts[1] == sid:
                try:
                    prev = float(parts[2])
                except ValueError:
                    pass
        delta = cost - prev if cost >= prev else cost
        ledger.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\t{sid}\t{cost}\t{delta:.4f}\n")
        ledger.flush()
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
