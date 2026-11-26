# Validation evidence

## #71 runner (2026-11-26, local, API vars unset)
- `python3 -m unittest discover -s scripts/tests -p 'test_*.py'`: 42 tests, OK (28 issue-runner, 14 review-runner; all offline with mocked gh/claude).
- `shellcheck -x -P SCRIPTDIR scripts/*.sh scripts/lib/*.sh`: clean. `bash -n`: OK.
- CI / Gitar: pending PR.
- Gaps: no live Claude invocation tested (by design); GraphQL thread query verified only against mocks.
