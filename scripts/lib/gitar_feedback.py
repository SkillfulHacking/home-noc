"""Build bounded Gitar feedback from GitHub API JSON.

Usage: gitar_feedback.py OUT_MD ISSUE_COMMENTS.json REVIEWS.json THREADS.json
Prints "ACTIONABLE <n>" or "NONE". Only unresolved Gitar review threads, or a
latest Gitar review in CHANGES_REQUESTED, count as actionable; resolved threads
are historical and excluded. Concatenated paginated arrays are accepted.
"""
import json
import sys
from pathlib import Path

GITAR = {"gitar-bot", "gitar-bot[bot]"}


def load(path):
    text, dec, pos, items = Path(path).read_text(), json.JSONDecoder(), 0, []
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


out_md, comments_f, reviews_f, threads_f = sys.argv[1:5]
comments = [c for c in load(comments_f) if is_gitar(c.get("user"))]
reviews = [r for r in load(reviews_f) if is_gitar(r.get("user"))]
threads = []
for doc in load(threads_f):
    nodes = (((doc.get("data") or {}).get("repository") or {}).get("pullRequest") or {}) \
        .get("reviewThreads", {}).get("nodes", [])
    threads.extend(nodes)

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
    Path(out_md).write_text("\n".join(parts)[:60000])
    print(f"ACTIONABLE {actionable}")
else:
    print("NONE")
