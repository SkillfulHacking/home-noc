"""Format `gh issue view --json title,body,comments` output for prompts.

Usage: issue_context.py title|body|comments < issue.json
Comments are bounded (latest 10, 4000 chars each, 20000 total) and untrusted.
"""
import json
import sys

MAX_COMMENTS, MAX_EACH, MAX_TOTAL = 10, 4000, 20000

data = json.loads(sys.stdin.read())
what = sys.argv[1]
if what in ("title", "body"):
    value = data.get(what)
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"issue {what} missing")
    print(value)
elif what == "comments":
    out, total = [], 0
    # Newest first so the budget never drops the latest requirement changes.
    for c in reversed((data.get("comments") or [])[-MAX_COMMENTS:]):
        author = (c.get("author") or {}).get("login", "unknown")
        text = (c.get("body") or "")[:MAX_EACH]
        entry = f"--- comment by {author} at {c.get('createdAt', '?')} ---\n{text}\n"
        if total + len(entry) > MAX_TOTAL:
            break
        total += len(entry)
        out.append(entry)
    print("".join(reversed(out)), end="")
else:
    raise SystemExit("unknown selector")
