"""Offline integration tests: real local Git worktrees, mocked gh and Claude CLIs.

Run: python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
Requires no external services, Claude login or network access.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "claude-issue.sh"


def run(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, check=False, timeout=35)


class ClaudeIssueRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="home-noc-runner-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.repo = self.base / "home-noc"
        self.remote = self.base / "origin.git"
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.log = self.base / "claude.log"
        self.assertEqual(run("git", "init", "--bare", "--initial-branch=main", str(self.remote)).returncode, 0)
        self.assertEqual(run("git", "clone", str(self.remote), str(self.repo)).returncode, 0)
        run("git", "config", "user.email", "test@example.com", cwd=self.repo)
        run("git", "config", "user.name", "Test", cwd=self.repo)
        (self.repo / "scripts").mkdir()
        shutil.copyfile(SCRIPT, self.repo / "scripts" / "claude-issue.sh")
        (self.repo / "CLAUDE.md").write_text("Test project instructions.\n")
        (self.repo / ".gitignore").write_text("/.claude-issue/\n")
        self.assertEqual(run("git", "add", ".", cwd=self.repo).returncode, 0)
        commit = run("git", "commit", "-m", "test", cwd=self.repo)
        self.assertEqual(commit.returncode, 0, commit.stderr)
        push = run("git", "push", "-u", "origin", "main", cwd=self.repo)
        self.assertEqual(push.returncode, 0, push.stderr)

        (self.bin / "gh").write_text('''#!/usr/bin/env python3
import os,sys
args = sys.argv[1:]
if args[:2] == ['auth','status']:
    sys.exit(0)
if args[:2] == ['issue','view']:
    if '.title' in args:
        print(os.environ.get('FAKE_GH_TITLE','[MVP][P0][M08] Authorized scan scopes'))
    elif '.body' in args:
        print('Only authorized CIDRs; reject out-of-scope targets; tests required.')
    else:
        sys.exit(7)
    sys.exit(0)
sys.exit(9)
''')
        (self.bin / "claude").write_text('''#!/usr/bin/env python3
import json,os,sys
args = sys.argv[1:]
with open(os.environ['FAKE_CLAUDE_LOG'],'a') as fh:
    fh.write(json.dumps({'args':args,'cwd':os.getcwd()})+'\\n')
if os.environ.get('FAKE_CLAUDE_FAIL') == '1':
    sys.exit(7)
flag = '--resume' if '--resume' in args else '--session-id'
session_id = args[args.index(flag)+1]
if os.environ.get('FAKE_CLAUDE_WRONG_SESSION') == '1':
    session_id = 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa'
print(json.dumps({'session_id':session_id, 'result':'Mock implementation completed.', 'total_cost_usd':0.25}))
''')
        for name in ("gh", "claude"):
            (self.bin / name).chmod(0o755)
        self.env = dict(os.environ)
        self.env["PATH"] = f"{self.bin}:{os.environ['PATH']}"
        self.env["FAKE_CLAUDE_LOG"] = str(self.log)
        self.env.pop("ANTHROPIC_API_KEY", None)
        self.env.pop("ANTHROPIC_AUTH_TOKEN", None)
        self.script = self.repo / "scripts" / "claude-issue.sh"

    def invoke(self, *args: str, **updates: str) -> subprocess.CompletedProcess[str]:
        return run("bash", str(self.script), *args, cwd=self.repo, env={**self.env, **updates})

    def calls(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def session(self) -> str:
        return (self.repo / ".claude-issue/issue-11/session-id").read_text().strip()

    def test_start_creates_worktree_and_private_session(self) -> None:
        p = self.invoke("11")
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        worktree = self.base / "home-noc-m08"
        self.assertTrue(worktree.is_dir())
        self.assertEqual(run("git", "branch", "--show-current", cwd=worktree).stdout.strip(), "feat/home-noc-issue-11")
        state = self.repo / ".claude-issue/issue-11"
        self.assertEqual(state.stat().st_mode & 0o777, 0o700)
        self.assertEqual(run("git", "status", "--porcelain", cwd=self.repo).stdout.strip(), "")
        self.assertEqual(len(self.calls()), 1)
        argv = self.calls()[0]["args"]
        self.assertEqual(self.calls()[0]["cwd"], str(worktree))
        self.assertEqual(argv[argv.index("--session-id") + 1], self.session())
        self.assertIn("--append-system-prompt-file", argv)
        self.assertIn("--max-turns", argv)
        self.assertIn("--max-budget-usd", argv)
        self.assertNotIn("Bash", argv)
        self.assertTrue(any(state.glob("pass-*.json")))

    def test_resume_uses_exact_id_even_with_dirty_worktree(self) -> None:
        self.assertEqual(self.invoke("11").returncode, 0)
        old = self.session()
        (self.base / "home-noc-m08" / "draft.txt").write_text("uncommitted work")
        p = self.invoke("11", "--resume")
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        self.assertEqual(old, self.session())
        self.assertEqual(len(self.calls()), 2)
        argv = self.calls()[1]["args"]
        self.assertEqual(argv[argv.index("--resume") + 1], old)
        self.assertNotIn("--continue", argv)
        self.assertNotIn("--session-id", argv)
        self.assertTrue((self.base / "home-noc-m08" / "draft.txt").exists())
        self.assertEqual(len(list((self.repo / ".claude-issue/issue-11").glob("pass-*.json"))), 2)

    def test_resume_after_failure_preserves_session(self) -> None:
        p = self.invoke("11", FAKE_CLAUDE_FAIL="1")
        self.assertEqual(p.returncode, 7, p.stdout + p.stderr)
        old = self.session()
        p2 = self.invoke("11", "--resume")
        self.assertEqual(p2.returncode, 0, p2.stdout + p2.stderr)
        self.assertEqual(self.session(), old)
        self.assertEqual(len(self.calls()), 2)
        self.assertEqual(self.calls()[1]["args"][self.calls()[1]["args"].index("--resume") + 1], old)

    def test_start_twice_refuses_without_changing_worktree(self) -> None:
        self.assertEqual(self.invoke("11").returncode, 0)
        p = self.invoke("11")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("State already exists", p.stderr)
        self.assertEqual(len(self.calls()), 1)

    def test_resume_without_state_refuses(self) -> None:
        p = self.invoke("11", "--resume")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("No issue state", p.stderr)
        self.assertFalse(self.log.exists())

    def test_resume_refuses_wrong_branch(self) -> None:
        self.assertEqual(self.invoke("11").returncode, 0)
        worktree = self.base / "home-noc-m08"
        self.assertEqual(run("git", "switch", "-c", "unrelated-branch", cwd=worktree).returncode, 0)
        p = self.invoke("11", "--resume")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("expected issue branch", p.stderr)
        self.assertEqual(len(self.calls()), 1)

    def test_resume_refuses_concurrent_pass(self) -> None:
        self.assertEqual(self.invoke("11").returncode, 0)
        lock = self.repo / ".claude-issue/issue-11/run.lock"
        with lock.open("w") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            p = self.invoke("11", "--resume")
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("already running", p.stderr)
        self.assertEqual(len(self.calls()), 1)

    def test_issue_without_tracking_id_uses_issue_number(self) -> None:
        p = self.invoke("11", FAKE_GH_TITLE="Issue without milestone label")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertTrue((self.base / "home-noc-issue-11").exists())

    def test_billing_mode_guard(self) -> None:
        p = self.invoke("11", ANTHROPIC_API_KEY="must-not-use")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("API credentials found", p.stderr)
        self.assertFalse(self.log.exists())

    def test_api_mode_uses_bare_and_budget(self) -> None:
        p = self.invoke("11", CLAUDE_BILLING="api", ANTHROPIC_API_KEY="test-key", MAX_BUDGET_USD="1.50", MAX_TURNS="7")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        argv = self.calls()[0]["args"]
        self.assertIn("--bare", argv)
        self.assertEqual(argv[argv.index("--max-budget-usd") + 1], "1.50")
        self.assertEqual(argv[argv.index("--max-turns") + 1], "7")

    def test_zero_budget_is_rejected(self) -> None:
        p = self.invoke("11", MAX_BUDGET_USD="0")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("greater than zero", p.stderr)
        self.assertFalse(self.log.exists())

    def test_bad_session_never_silently_starts_over(self) -> None:
        self.assertEqual(self.invoke("11").returncode, 0)
        (self.repo / ".claude-issue/issue-11/session-id").write_text("wrong-session\n")
        p = self.invoke("11", "--resume")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("Invalid stored Claude session UUID", p.stderr)
        self.assertEqual(len(self.calls()), 1)

    def test_json_session_mismatch_causes_failure(self) -> None:
        p = self.invoke("11", FAKE_CLAUDE_WRONG_SESSION="1")
        self.assertEqual(p.returncode, 1)
        self.assertIn("session ID mismatch", p.stderr)
        self.assertTrue((self.repo / ".claude-issue/issue-11/session-id").exists())

    def test_invalid_flags_are_rejected(self) -> None:
        p = self.invoke("11", "--restart")
        self.assertEqual(p.returncode, 2)
        self.assertFalse((self.base / "home-noc-m08").exists())


if __name__ == "__main__":
    unittest.main()
