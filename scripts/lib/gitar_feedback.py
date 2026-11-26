"""Build bounded Gitar feedback from GitHub API JSON.

Usage: gitar_feedback.py 3<comments.json 4<reviews.json 5<threads.json > feedback.md
Inputs arrive on fds 3-5; no paths are taken from the command line. Markdown goes
to stdout. Exit 0 and "ACTIONABLE <n>" on stderr, or exit 10 and "NONE"; exit 1
on unreadable input or incomplete (unpaginated) review threads. Only unresolved Gitar review threads, or a
latest Gitar review in CHANGES_REQUESTED, count as actionable; resolved threads
are historical and excluded. Concatenated paginated arrays are accepted.
"""
import json
import os
import sys

GITAR = {"gitar-bot", "gitar-bot[bot]"}


def load(fd):
    with os.fdopen(fd, "r", closefd=False) as fh:
        text = fh.read()
    dec, pos, items = json.JSONDecoder(), 0, []
    while pos < len(text):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        obj, pos = dec.raw_decode(text, pos)
        items.extend(obj) if isinstance(obj, list) else items.append(obj)
    return items


def is_gitar(user):
    return bool(user) and user.get("login") in GITAR and user.get("type", "Bot") == "Bot"


try:
    comments = [c for c in load(3) if is_gitar(c.get("user"))]
    reviews = [r for r in load(4) if is_gitar(r.get("user"))]
    thread_docs = load(5)
except (OSError, ValueError) as exc:
    print(f"unreadable feedback input: {exc}", file=sys.stderr)
    raise SystemExit(1)
threads = []
for doc in thread_docs:
    conn = (((doc.get("data") or {}).get("repository") or {}).get("pullRequest") or {}) \
        .get("reviewThreads", {})
    if (conn.get("pageInfo") or {}).get("hasNextPage"):
        # Fail closed rather than silently ignoring later unresolved findings.
        print("review threads are incomplete (hasNextPage); refusing to report NONE", file=sys.stderr)
        raise SystemExit(1)
    threads.extend(conn.get("nodes", []))

parts, actionable = [], 0
for t in threads:
    cs = (t.get("comments") or {}).get("nodes") or []
    first = cs[0] if cs else {}
    author = (first.get("author") or {}).get("login")
    if t.get("isResolved") or author not in GITAR:
        continue
    actionable += 1
    state = "outdated (code changed)" if t.get("isOutdated") else "current"
    parts.append(f"### Unresolved inline finding — {first.get('path')}:{first.get('line') or first.get('originalLine')} [{state}]\n"
                 f"{(first.get('body') or '')[:6000]}\n")
if reviews and reviews[-1].get("state") == "CHANGES_REQUESTED":
    actionable += 1
    parts.append(f"### Latest Gitar review — CHANGES_REQUESTED\n{(reviews[-1].get('body') or '')[:9000]}\n")
if actionable:
    for c in comments[-3:]:
        parts.append(f"### Gitar summary comment (context)\n{(c.get('body') or '')[:9000]}\n")
    sys.stdout.write("\n".join(parts)[:60000])
    print(f"ACTIONABLE {actionable}", file=sys.stderr)
else:
    print("NONE", file=sys.stderr)
    raise SystemExit(10)
