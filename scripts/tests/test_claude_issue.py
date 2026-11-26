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
        shutil.copytree(SCRIPT.parent / "lib", self.repo / "scripts" / "lib")
        (self.repo / "CLAUDE.md").write_text("Test project instructions.\n")
        (self.repo / ".gitignore").write_text("/.claude-issue/\n")
        self.assertEqual(run("git", "add", ".", cwd=self.repo).returncode, 0)
        commit = run("git", "commit", "-m", "test", cwd=self.repo)
        self.assertEqual(commit.returncode, 0, commit.stderr)
        push = run("git", "push", "-u", "origin", "main", cwd=self.repo)
        self.assertEqual(push.returncode, 0, push.stderr)

        (self.bin / "gh").write_text('''#!/usr/bin/env python3
import json,os,sys
args = sys.argv[1:]
if args[:2] == ['auth','status']:
    sys.exit(0)
if args[:2] == ['issue','view']:
    comments = json.loads(os.environ.get('FAKE_GH_COMMENTS','[]'))
    print(json.dumps({'title': os.environ.get('FAKE_GH_TITLE','[MVP][P0][M08] Authorized scan scopes'),
        'body': os.environ.get('FAKE_GH_BODY','Only authorized CIDRs; reject out-of-scope targets; tests required.'),
        'comments': comments}))
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
out = {'session_id':session_id, 'result':'Mock implementation completed.', 'total_cost_usd':float(os.environ.get('FAKE_COST','0.25'))}
if os.environ.get('FAKE_CLAUDE_SUBTYPE'):
    out = {'session_id':session_id, 'subtype':os.environ['FAKE_CLAUDE_SUBTYPE'], 'is_error':False, 'total_cost_usd':0.4}
if os.environ.get('FAKE_CLAUDE_ERROR_JSON') == '1':
    out['is_error'] = True
if os.environ.get('FAKE_CLAUDE_EMPTY') == '1':
    out['result'] = '  '
print(json.dumps(out))
''')
        for name in ("gh", "claude"):
            (self.bin / name).chmod(0o755)
        self.env = dict(os.environ)
        self.env["PATH"] = f"{self.bin}:{os.environ['PATH']}"
        self.env["FAKE_CLAUDE_LOG"] = str(self.log)
        self.env.pop("ANTHROPIC_API_KEY", None)
        self.env.pop("ANTHROPIC_AUTH_TOKEN", None)
        self.env["CLAUDE_BILLING"] = "subscription"  # most tests use plan mode; defaults tested explicitly
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
        self.assertNotIn(
            "Bash",
            argv[argv.index("--tools") + 1].split(","),
        )
        allowed = argv[
            argv.index("--allowedTools") + 1:
            argv.index("--disallowedTools")
        ]
        self.assertEqual(
            set(allowed),
            {"Read", "Edit", "Write", "Glob", "Grep"},
        )
        self.assertEqual(
            argv[argv.index("--disallowedTools") + 1],
            "Bash",
        )
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

    def test_default_billing_is_api_and_requires_key(self) -> None:
        env = {k: v for k, v in self.env.items() if k != "CLAUDE_BILLING"}
        p = run("bash", str(self.script), "11", cwd=self.repo, env=env)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("requires ANTHROPIC_API_KEY", p.stderr)
        self.assertFalse(self.log.exists())
        self.assertFalse((self.base / "home-noc-m08").exists())

    def test_default_api_mode_strips_auth_token_and_never_bare(self) -> None:
        env = {k: v for k, v in self.env.items() if k != "CLAUDE_BILLING"}
        env["ANTHROPIC_API_KEY"] = "k"
        p = run("bash", str(self.script), "11", cwd=self.repo, env=env)
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        self.assertNotIn("--bare", self.calls()[0]["args"])

    def test_invalid_billing_mode(self) -> None:
        p = self.invoke("11", CLAUDE_BILLING="auto")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("must be api or subscription", p.stderr)

    def test_billing_mode_guard(self) -> None:
        p = self.invoke("11", ANTHROPIC_API_KEY="must-not-use")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("API credentials found", p.stderr)
        self.assertFalse(self.log.exists())

    def test_api_mode_uses_restricted_tools_and_budget(self) -> None:
        p = self.invoke("11", CLAUDE_BILLING="api", ANTHROPIC_API_KEY="test-key", MAX_BUDGET_USD="1.50", MAX_TURNS="7")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        argv = self.calls()[0]["args"]
        self.assertNotIn("--bare", argv)
        self.assertIn("--strict-mcp-config", argv)
        self.assertEqual(
            argv[argv.index("--mcp-config") + 1],
            '{"mcpServers":{}}',
        )
        self.assertEqual(
            argv[argv.index("--settings") + 1],
            '{"disableAllHooks":true}',
        )
        self.assertEqual(
            argv[argv.index("--disallowedTools") + 1],
            "Bash",
        )
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

    def test_resume_refetches_issue_and_comments(self) -> None:
        self.assertEqual(self.invoke("11").returncode, 0)
        comments = json.dumps([{"author": {"login": "someone"}, "createdAt": "2026-01-01", "body": "NEW-COMMENT-TEXT"}])
        p = self.invoke("11", "--resume", FAKE_GH_BODY="UPDATED-REQUIREMENTS", FAKE_GH_COMMENTS=comments)
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        argv = self.calls()[1]["args"]
        prompt = argv[argv.index("-p") + 1]
        self.assertIn("UPDATED-REQUIREMENTS", prompt)
        self.assertIn("NEW-COMMENT-TEXT", prompt)
        self.assertIn("untrusted", prompt)

    def test_comment_context_is_bounded(self) -> None:
        self.assertEqual(self.invoke("11").returncode, 0)
        comments = json.dumps([{"author": {"login": "u"}, "createdAt": "t", "body": f"C{i}" + "x" * 6000} for i in range(15)])
        p = self.invoke("11", "--resume", FAKE_GH_COMMENTS=comments)
        self.assertEqual(p.returncode, 0, p.stderr)
        argv = self.calls()[1]["args"]
        prompt = argv[argv.index("-p") + 1]
        self.assertLess(len(prompt), 40000)
        self.assertNotIn("C0x", prompt)
        self.assertIn("C14x", prompt)  # newest comment must survive the budget

    def test_recover_starts_fresh_session_preserving_work(self) -> None:
        self.assertEqual(self.invoke("11").returncode, 0)
        old = self.session()
        wt = self.base / "home-noc-m08"
        (wt / "draft.txt").write_text("uncommitted work")
        report_count = len(list((self.repo / ".claude-issue/issue-11").glob("pass-*.json")))
        p = self.invoke("11", "--recover")
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        new = self.session()
        self.assertNotEqual(old, new)
        argv = self.calls()[1]["args"]
        self.assertEqual(argv[argv.index("--session-id") + 1], new)
        self.assertNotIn("--resume", argv)
        self.assertIn("draft.txt", argv[argv.index("-p") + 1])
        self.assertEqual((wt / "draft.txt").read_text(), "uncommitted work")
        state = self.repo / ".claude-issue/issue-11"
        self.assertIn(old, (state / "retired-sessions").read_text())
        self.assertEqual(len(list(state.glob("pass-*.json"))), report_count + 1)

    def test_recover_while_running_does_not_rotate_session(self) -> None:
        self.assertEqual(self.invoke("11").returncode, 0)
        old = self.session()
        with (self.repo / ".claude-issue/issue-11/run.lock").open("w") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            p = self.invoke("11", "--recover")
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("already running", p.stderr)
        self.assertEqual(self.session(), old)
        self.assertFalse((self.repo / ".claude-issue/issue-11/retired-sessions").exists())
        self.assertEqual(len(self.calls()), 1)

    def test_recover_without_state_refuses(self) -> None:
        p = self.invoke("11", "--recover")
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse(self.log.exists())

    def test_turn_exhaustion_is_incomplete_and_resumable(self) -> None:
        p = self.invoke("11", FAKE_CLAUDE_SUBTYPE="error_max_turns")
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
        self.assertIn("INCOMPLETE", p.stderr)
        old = self.session()
        p2 = self.invoke("11", "--resume")
        self.assertEqual(p2.returncode, 0, p2.stdout + p2.stderr)
        self.assertEqual(self.session(), old)

    def test_budget_exhaustion_is_incomplete(self) -> None:
        p = self.invoke("11", FAKE_CLAUDE_SUBTYPE="error_max_budget_usd")
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)

    def test_malformed_reports_fail(self) -> None:
        for var in ("FAKE_CLAUDE_ERROR_JSON", "FAKE_CLAUDE_EMPTY"):
            with self.subTest(var=var):
                self.tearDown_issue()
                p = self.invoke("11", **{var: "1"})
                self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
                self.assertIn("could not be validated", p.stderr)

    def tearDown_issue(self) -> None:
        wt = self.base / "home-noc-m08"
        if wt.exists():
            run("git", "worktree", "remove", "--force", str(wt), cwd=self.repo)
            run("git", "branch", "-D", "feat/home-noc-issue-11", cwd=self.repo)
        shutil.rmtree(self.repo / ".claude-issue", ignore_errors=True)

    def test_cost_ledger_records_incremental_cost(self) -> None:
        self.assertEqual(self.invoke("11", FAKE_COST="0.25").returncode, 0)
        p = self.invoke("11", "--resume", FAKE_COST="0.60")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("incremental this pass: $0.3500", p.stdout)
        rows = (self.repo / ".claude-issue/issue-11/costs.tsv").read_text().splitlines()
        self.assertEqual([r.split("\t")[3] for r in rows], ["0.2500", "0.3500"])

    def test_feedback_file_included_and_limited(self) -> None:
        fb = self.base / "fb.txt"
        fb.write_text("OPERATOR-FINDING")
        p = self.invoke("11", CLAUDE_FEEDBACK_FILE=str(fb))
        self.assertEqual(p.returncode, 0, p.stderr)
        argv = self.calls()[0]["args"]
        self.assertIn("OPERATOR-FINDING", argv[argv.index("-p") + 1])

    def test_feedback_file_oversize_and_symlink_rejected(self) -> None:
        big = self.base / "big.txt"
        big.write_bytes(b"x" * 65537)
        p = self.invoke("11", CLAUDE_FEEDBACK_FILE=str(big))
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("64 KiB", p.stderr)
        self.tearDown_issue()
        real = self.base / "real.txt"
        real.write_text("a")
        link = self.base / "link.txt"
        link.symlink_to(real)
        p = self.invoke("11", CLAUDE_FEEDBACK_FILE=str(link))
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("Invalid operator feedback file", p.stderr)

    def test_worktree_source_readable_state_private(self) -> None:
        self.assertEqual(self.invoke("11").returncode, 0)
        wt = self.base / "home-noc-m08"
        self.assertEqual((wt / "CLAUDE.md").stat().st_mode & 0o044, 0o044)
        self.assertEqual(wt.stat().st_mode & 0o055, 0o055)
        state = self.repo / ".claude-issue/issue-11"
        for f in state.iterdir():
            self.assertEqual(f.stat().st_mode & 0o077, 0, f.name)

    def test_invalid_flags_are_rejected(self) -> None:
        p = self.invoke("11", "--restart")
        self.assertEqual(p.returncode, 2)
        self.assertFalse((self.base / "home-noc-m08").exists())


if __name__ == "__main__":
    unittest.main()
