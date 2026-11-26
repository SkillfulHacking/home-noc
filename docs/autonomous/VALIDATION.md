# Validation evidence

## #71 runner (2026-11-26, local, API vars unset)
- `python3 -m unittest discover -s scripts/tests -p 'test_*.py'`: 42 tests, OK (28 issue-runner, 14 review-runner; all offline with mocked gh/claude).
- `shellcheck -x -P SCRIPTDIR scripts/*.sh scripts/lib/*.sh`: clean. `bash -n`: OK.
- Gitar review of PR #72 (3 findings, all independently verified as valid and fixed with regression tests):
  1. `--recover` rotated the session before taking the lock -> lock now taken first (test_recover_while_running_does_not_rotate_session).
  2. Comment bounding dropped newest comments -> newest-first selection (test asserts newest comment kept).
  3. Review-thread query unpaginated -> `gh api graphql --paginate` plus fail-closed on `hasNextPage`.
- SonarCloud `pythonsecurity:S8707` (6x path traversal via argv) -> helpers no longer take file paths from argv; inputs arrive via stdin/fds.
- After remediation: 44 offline tests OK, ShellCheck clean.
- Gaps: no live Claude invocation tested (by design); GraphQL thread query verified only against mocks.

## #67 (PR #73): backend 569 passed/1 skipped, ruff clean; CI all green, Gitar approved (no findings).
## #16 (PR #74): backend 587 passed/1 skipped, ruff clean; pip-audit on requirements.lock: no known vulnerabilities; `--require-hashes` install verified.
