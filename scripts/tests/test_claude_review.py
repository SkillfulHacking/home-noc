"""Offline tests for claude-review-pr.sh with mocked gh and Claude CLIs."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]


def run(*args, cwd=None, env=None):
    return subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, check=False, timeout=35)


GH = '''#!/usr/bin/env python3
import json,os,sys
a = sys.argv[1:]
def out(o): print(json.dumps(o))
if a[:2] == ['pr','view']:
    out({'headRefName': os.environ['FAKE_BRANCH'], 'headRefOid': os.environ['FAKE_OID']})
elif a[:2] == ['pr','diff']:
    print(os.environ.get('FAKE_DIFF','backend/x.py'))
elif a[:1] == ['api'] and 'graphql' in a:
    threads = json.loads(os.environ.get('FAKE_THREADS','[]'))
    out({'data':{'repository':{'pullRequest':{'reviewThreads':{'nodes':threads}}}}})
elif a[:1] == ['api'] and any(x.endswith('/reviews') for x in a):
    out(json.loads(os.environ.get('FAKE_REVIEWS','[]')))
elif a[:1] == ['api'] and any(x.endswith('/comments') for x in a):
    out(json.loads(os.environ.get('FAKE_COMMENTS','[]')))
else:
    sys.exit(9)
'''
CLAUDE = '''#!/usr/bin/env python3
import json,os,sys
with open(os.environ['FAKE_CLAUDE_LOG'],'a') as fh:
    fh.write(json.dumps({'args':sys.argv[1:]})+'\\n')
o = {'session_id':'s','result':'Reviewed.','total_cost_usd':0.1}
if os.environ.get('FAKE_CLAUDE_SUBTYPE'):
    o = {'session_id':'s','subtype':os.environ['FAKE_CLAUDE_SUBTYPE'],'total_cost_usd':0.1}
if os.environ.get('FAKE_CLAUDE_BAD') == '1':
    print('not json'); sys.exit(0)
print(json.dumps(o))
'''


def thread(resolved, body="Fix the bug", author="gitar-bot"):
    return {"isResolved": resolved, "isOutdated": False,
            "comments": {"nodes": [{"path": "a.py", "line": 3, "body": body, "author": {"login": author}}]}}


class ReviewRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="home-noc-review-")
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.repo = base / "repo"
        self.repo.mkdir()
        run("git", "init", "-q", "--initial-branch=main", cwd=self.repo)
        run("git", "config", "user.email", "t@example.com", cwd=self.repo)
        run("git", "config", "user.name", "T", cwd=self.repo)
        (self.repo / "scripts").mkdir()
        shutil.copyfile(SCRIPTS / "claude-review-pr.sh", self.repo / "scripts/claude-review-pr.sh")
        shutil.copytree(SCRIPTS / "lib", self.repo / "scripts/lib")
        (self.repo / "CLAUDE.md").write_text("x\n")
        (self.repo / ".gitignore").write_text("/.claude-issue/\n")
        run("git", "add", ".", cwd=self.repo)
        run("git", "commit", "-qm", "init", cwd=self.repo)
        run("git", "switch", "-qc", "feat/home-noc-issue-5", cwd=self.repo)
        self.oid = run("git", "rev-parse", "HEAD", cwd=self.repo).stdout.strip()
        bindir = base / "bin"
        bindir.mkdir()
        for name, body in (("gh", GH), ("claude", CLAUDE)):
            (bindir / name).write_text(body)
            (bindir / name).chmod(0o755)
        self.log = base / "claude.log"
        self.env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "FAKE_CLAUDE_LOG": str(self.log),
                    "FAKE_BRANCH": "feat/home-noc-issue-5", "FAKE_OID": self.oid, "ANTHROPIC_API_KEY": "k"}
        self.env.pop("ANTHROPIC_AUTH_TOKEN", None)
        self.env.pop("CLAUDE_BILLING", None)

    def go(self, **upd):
        env = {**self.env, **upd}
        env = {k: v for k, v in env.items() if v is not None}
        return run("bash", str(self.repo / "scripts/claude-review-pr.sh"), "7", cwd=self.repo, env=env)

    def calls(self):
        return [json.loads(x) for x in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_unresolved_finding_invokes_restricted_model(self) -> None:
        p = self.go(FAKE_THREADS=json.dumps([thread(False)]))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        argv = self.calls()[0]["args"]
        self.assertNotIn("--bare", argv)
        self.assertEqual(argv[argv.index("--disallowedTools") + 1], "Bash")
        self.assertEqual(argv[argv.index("--tools") + 1], "Read,Edit,Write,Glob,Grep")
        self.assertIn(self.oid, argv[argv.index("-p") + 1])

    def test_no_findings_means_no_model_call(self) -> None:
        p = self.go(FAKE_THREADS=json.dumps([thread(True)]))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("No model invoked", p.stdout)
        self.assertEqual(self.calls(), [])

    def test_non_gitar_threads_ignored(self) -> None:
        p = self.go(FAKE_THREADS=json.dumps([thread(False, author="mallory")]))
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_changes_requested_review_is_actionable(self) -> None:
        reviews = [{"user": {"login": "gitar-bot[bot]", "type": "Bot"}, "state": "CHANGES_REQUESTED", "body": "bad"}]
        p = self.go(FAKE_REVIEWS=json.dumps(reviews))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(self.calls()), 1)

    def test_head_mismatch_refused(self) -> None:
        p = self.go(FAKE_OID="0" * 40, FAKE_THREADS=json.dumps([thread(False)]))
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("does not match PR head", p.stderr)
        self.assertEqual(self.calls(), [])

    def test_wrong_branch_refused(self) -> None:
        p = self.go(FAKE_BRANCH="other")
        self.assertIn("Check out PR branch", p.stderr)
        self.assertEqual(self.calls(), [])

    def test_missing_key_in_default_api_mode(self) -> None:
        p = self.go(ANTHROPIC_API_KEY=None)
        self.assertIn("requires ANTHROPIC_API_KEY", p.stderr)

    def test_invalid_budget_and_turns(self) -> None:
        self.assertIn("greater than zero", self.go(MAX_BUDGET_USD="0").stderr)
        self.assertIn("MAX_TURNS", self.go(MAX_TURNS="abc").stderr)

    def test_claude_config_changes_refused(self) -> None:
        p = self.go(FAKE_DIFF=".claude/settings.json", FAKE_THREADS=json.dumps([thread(False)]))
        self.assertIn("Claude settings", p.stderr)
        self.assertEqual(self.calls(), [])

    def test_malformed_report_fails(self) -> None:
        p = self.go(FAKE_THREADS=json.dumps([thread(False)]), FAKE_CLAUDE_BAD="1")
        self.assertEqual(p.returncode, 1)
        self.assertIn("could not be validated", p.stderr)

    def test_turn_exhaustion_is_incomplete(self) -> None:
        p = self.go(FAKE_THREADS=json.dumps([thread(False)]), FAKE_CLAUDE_SUBTYPE="error_max_turns")
        self.assertEqual(p.returncode, 3, p.stderr)

    def test_shares_lock_with_implementation_pass(self) -> None:
        state = self.repo / ".claude-issue/issue-5"
        state.mkdir(parents=True)
        with (state / "run.lock").open("w") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            p = self.go(FAKE_THREADS=json.dumps([thread(False)]))
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("already running", p.stderr)
        self.assertEqual(self.calls(), [])

    def test_dirty_tree_refused(self) -> None:
        (self.repo / "dirty").write_text("x")
        self.assertIn("Commit or stash", self.go().stderr)

    def test_report_is_private(self) -> None:
        self.assertEqual(self.go(FAKE_THREADS=json.dumps([thread(False)])).returncode, 0)
        for f in (self.repo / ".claude-issue/issue-5").iterdir():
            self.assertEqual(f.stat().st_mode & 0o077, 0, f.name)


if __name__ == "__main__":
    unittest.main()
