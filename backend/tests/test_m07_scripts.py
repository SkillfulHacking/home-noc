"""M07 (#10): behavioural tests for the operator shell scripts.

Every test runs a *copy* of the scripts inside a temporary "checkout" with a fake
``docker`` (and, for backups, a fake ``date``) first on ``PATH``. Nothing here
touches a real ``.env``, a real Docker daemon, a real database or the network,
and the environment handed to the scripts is built from scratch (no inherited
``HOME_NOC_*`` settings, no API keys).
"""
from __future__ import annotations

import os
import pty
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from dotenv import dotenv_values

from app import admin_password, auth, crypto

REPO = Path(__file__).resolve().parents[2]
SCRIPTS = REPO / "scripts"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or BASH is None, reason="needs Linux and bash (GNU coreutils)"
)

FAKE_STAMP = "20260101T000000Z"

# A scripted stand-in for the docker CLI. Behaviour is selected by environment
# variables; every invocation is appended to calls.log so tests can assert on
# exactly what the scripts asked Docker to do.
FAKE_DOCKER = r'''#!@PYTHON@
import os
import sys

args = sys.argv[1:]
state_dir = os.environ["FAKE_DOCKER_DIR"]
with open(os.path.join(state_dir, "calls.log"), "a", encoding="utf-8") as fh:
    fh.write(" ".join(args) + "\n")

if args[:2] == ["compose", "version"]:
    print("Docker Compose version v2.fake")
    sys.exit(0)

if args[:1] in (["build"], ["rmi"]):
    sys.exit(0)

if args[:1] == ["run"]:
    # bootstrap.sh's password step: write the scripted verifier into the mount.
    if "--output" in args and "/out/admin_hash" in args:
        host = args[args.index("-v") + 1].rsplit(":/out", 1)[0]
        with open(os.path.join(host, "admin_hash"), "wb") as fh:
            fh.write(os.environ["FAKE_VERIFIER_RAW"].encode("utf-8"))
    sys.exit(0)

if args[:2] == ["compose", "ps"]:
    if os.environ.get("FAKE_DOCKER_PS_FAIL"):
        sys.stderr.write("cannot connect to the docker daemon\n")
        sys.exit(1)
    state = os.environ.get("FAKE_DOCKER_STATE", "none")
    rest = args[2:]
    status = rest[rest.index("--status") + 1] if "--status" in rest else None
    show_all = "-a" in rest or "--all" in rest
    if state == "none":
        listed = False
    elif status is not None:  # an explicit --status filter only matches that state
        listed = state == status
    elif show_all:  # -a lists every state
        listed = True
    else:  # the default listing hides stopped/created containers
        listed = state in ("running", "restarting", "paused")
    if listed and ("-q" in rest or "--quiet" in rest):
        skip = False
        services = []
        for token in rest:
            if skip:
                skip = False
            elif token == "--status":
                skip = True
            elif not token.startswith("-"):
                services.append(token)
        for service in services or ["all"]:
            print("fake-container-" + service)
    sys.exit(0)

if args[:2] == ["compose", "run"]:
    data = sys.stdin.buffer.read()
    with open(os.path.join(state_dir, "restore_stdin.bin"), "wb") as fh:
        fh.write(data)
    sys.exit(int(os.environ.get("FAKE_DOCKER_RUN_RC", "0")))

if args[:2] == ["compose", "exec"]:
    race = os.environ.get("FAKE_RACE_DEST")
    if race:  # somebody else creates the destination while the backup runs
        with open(race, "wb") as fh:
            fh.write(b"raced-content")
    sys.stdout.buffer.write(b"SQLite format 3\x00" + b"\x00" * 64)
    sys.exit(0)

sys.exit(0)
'''

DESTRUCTIVE = (
    "compose down", "compose stop", "compose rm", "compose kill", "compose restart",
    "compose pause", "volume", "rm ", "stop ", "kill ",
)


class _Sandbox:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.root = tmp_path / "checkout"
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "backend").mkdir()
        for name in ("bootstrap.sh", "backup.sh", "restore.sh"):
            shutil.copy2(SCRIPTS / name, self.root / "scripts" / name)
        shutil.copy2(REPO / "backend" / ".env.example", self.root / "backend" / ".env.example")
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.state = tmp_path / "fake-docker-state"
        self.state.mkdir()
        docker = self.bin / "docker"
        docker.write_text(FAKE_DOCKER.replace("@PYTHON@", sys.executable))
        docker.chmod(0o755)

    def fix_date(self) -> None:
        shim = self.bin / "date"
        shim.write_text(f"#!/bin/sh\necho {FAKE_STAMP}\n")
        shim.chmod(0o755)

    def env(self, **extra: str) -> dict[str, str]:
        return {
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "HOME": str(self.home),
            "LC_ALL": "C",
            "FAKE_DOCKER_DIR": str(self.state),
            **{key: str(value) for key, value in extra.items()},
        }

    def calls(self) -> list[str]:
        log = self.state / "calls.log"
        return log.read_text().splitlines() if log.exists() else []

    def script(self, name: str) -> str:
        return str(self.root / "scripts" / name)


@pytest.fixture
def sandbox(tmp_path: Path) -> _Sandbox:
    return _Sandbox(tmp_path)


def _run(box: _Sandbox, script: str, args: list[str], *, cwd: Path, **env: str):
    return subprocess.run(  # noqa: S603 - fixed argv, no shell, scripted fake docker
        [BASH, box.script(script), *args],
        cwd=cwd, env=box.env(**env), stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=60, check=False,
    )


def _run_pty(box: _Sandbox, script: str, args: list[str], *, cwd: Path, **env: str):
    """Run with a real pseudo-terminal on stdin, as an operator's shell would."""
    master, slave = pty.openpty()
    try:
        proc = subprocess.Popen(  # noqa: S603
            [BASH, box.script(script), *args],
            cwd=cwd, env=box.env(**env), stdin=slave,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
        )
    finally:
        os.close(slave)
    try:
        out, err = proc.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise
    finally:
        os.close(master)
    return subprocess.CompletedProcess(proc.args, proc.returncode, out.decode(), err.decode())


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# --------------------------------------------------------------------------
# B1: bootstrap quoting and exact verifier validation
# --------------------------------------------------------------------------

PASSWORD = "a-long-enough-password"  # noqa: S105 - throwaway test value


def _verifier_line() -> str:
    return admin_password.format_env_line(auth.hash_password(PASSWORD, iterations=100_000))


def test_bootstrap_succeeds_through_a_pty_with_a_fake_docker(sandbox, tmp_path):
    line = _verifier_line()
    result = _run_pty(
        sandbox, "bootstrap.sh", [], cwd=tmp_path, FAKE_VERIFIER_RAW=line + "\n"
    )
    assert result.returncode == 0, result.stderr + result.stdout

    env_file = sandbox.root / "backend" / ".env"
    assert _mode(env_file) == 0o600
    assert line in env_file.read_text().splitlines()
    assert "SESSION_COOKIE_SECURE=true" in env_file.read_text().splitlines()
    verifier = dotenv_values(env_file)["ADMIN_PASSWORD_HASH"]
    assert auth.verify_password(PASSWORD, verifier)

    key_file = sandbox.root / "secrets" / "credential_key"
    assert _mode(key_file) == 0o444 and _mode(key_file.parent) == 0o700
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}=\n", key_file.read_text())
    assert len(crypto._decode_key(key_file.read_text())) == 32

    # No temp files left behind.
    assert {p.name for p in key_file.parent.iterdir()} == {"credential_key"}
    assert {p.name for p in env_file.parent.iterdir()} == {".env", ".env.example"}

    calls = sandbox.calls()
    builds = [c for c in calls if c.startswith("build ")]
    assert len(builds) == 1
    tag = re.search(r"-t (\S+)", builds[0]).group(1)
    assert tag.startswith("home-noc-bootstrap:") and "latest" not in tag  # private, unshared tag
    assert f"rmi {tag}" in calls  # and cleaned up
    run_call = next(c for c in calls if c.startswith("run "))
    assert "--network none" in run_call and "--cap-drop ALL" in run_call
    assert line not in "\n".join(calls) and PASSWORD not in "\n".join(calls)
    assert line not in result.stdout + result.stderr


def test_bootstrap_http_flag_is_the_only_way_to_relax_secure_cookies(sandbox, tmp_path):
    result = _run_pty(
        sandbox, "bootstrap.sh", ["--http"], cwd=tmp_path,
        FAKE_VERIFIER_RAW=_verifier_line() + "\n",
    )
    assert result.returncode == 0, result.stderr
    env_text = (sandbox.root / "backend" / ".env").read_text()
    assert "SESSION_COOKIE_SECURE=false" in env_text.splitlines()
    assert "127.0.0.1" in result.stdout  # tells the operator the UI is loopback-bound


def _malformed_verifiers(canary: Path) -> dict[str, str]:
    good = _verifier_line()
    _, iterations, salt, digest = good[len("ADMIN_PASSWORD_HASH='"):-1].split("$")

    def build(*, algo="pbkdf2_sha256", it=iterations, s=salt, d=digest, q="'",
              prefix="ADMIN_PASSWORD_HASH=", suffix="") -> str:
        return f"{prefix}{q}{algo}${it}${s}${d}{q}{suffix}"

    return {
        "no quotes": build(q=""),
        "double quotes": build(q='"'),
        # A '.'-style wildcard in place of the literal quote would accept this.
        "wildcard-dot quotes": build(q="x"),
        "arithmetic in iterations": build(it="$[1+1]"),
        "arithmetic in salt": build(s="$[1+1]"),
        "command substitution": build(s=f"$(touch {canary})"),
        "backticks": build(s=f"`touch {canary}`"),
        "low iterations": build(it="1000"),
        "leading-zero iterations": build(it="0600000"),
        "absurd iterations": build(it="9" * 12),
        "wrong algorithm": build(algo="pbkdf2_sha1"),
        "short salt": build(s=salt[:10]),
        "unpadded digest": build(d=digest.rstrip("=")),
        "foreign alphabet": build(d="-" + digest[1:]),
        "leading space": build(prefix=" ADMIN_PASSWORD_HASH="),
        "wrong variable name": build(prefix="admin_password_hash="),
        "trailing text": build(suffix=" # x"),
        "carriage return": build(suffix="\r"),
        "second line": good + "\nSESSION_COOKIE_SECURE=false",
    }


def test_bootstrap_rejects_every_malformed_verifier_without_side_effects(sandbox, tmp_path):
    canary = tmp_path / "pwned"
    for label, raw in _malformed_verifiers(canary).items():
        # Fresh state per case: the previous run must have created nothing.
        result = _run_pty(sandbox, "bootstrap.sh", [], cwd=tmp_path, FAKE_VERIFIER_RAW=raw + "\n")
        diagnostics = f"[{label}] rc={result.returncode}\n{result.stderr}"
        assert result.returncode != 0, diagnostics
        assert "unexpected verifier format" in result.stderr, diagnostics
        lowered = result.stderr.lower()
        assert "syntax error" not in lowered and "arithmetic" not in lowered, diagnostics
        assert not canary.exists(), f"[{label}] verifier text was executed"
        assert not (sandbox.root / "backend" / ".env").exists(), diagnostics
        assert not (sandbox.root / "secrets").exists(), diagnostics


def test_bootstrap_rejects_an_empty_verifier_file(sandbox, tmp_path):
    result = _run_pty(sandbox, "bootstrap.sh", [], cwd=tmp_path, FAKE_VERIFIER_RAW="")
    assert result.returncode != 0 and "no verifier was produced" in result.stderr
    assert not (sandbox.root / "backend" / ".env").exists()
    assert not (sandbox.root / "secrets").exists()


def test_bootstrap_requires_a_terminal(sandbox, tmp_path):
    result = _run(sandbox, "bootstrap.sh", [], cwd=tmp_path, FAKE_VERIFIER_RAW="x")
    assert result.returncode != 0 and "interactively" in result.stderr
    assert not any(c.startswith("build ") for c in sandbox.calls())


def test_bootstrap_never_replaces_an_existing_env_file(sandbox, tmp_path):
    env_file = sandbox.root / "backend" / ".env"
    env_file.write_text("EXISTING=1\n")
    result = _run_pty(sandbox, "bootstrap.sh", [], cwd=tmp_path, FAKE_VERIFIER_RAW="x")
    assert result.returncode != 0 and "already exists" in result.stderr
    assert env_file.read_text() == "EXISTING=1\n"
    assert not (sandbox.root / "secrets").exists()


def test_bootstrap_points_m04_upgraders_at_their_existing_key(sandbox, tmp_path):
    """An inline M04 key must be moved, never replaced by a freshly generated one."""
    env_file = sandbox.root / "backend" / ".env"
    content = "ADMIN_USERNAME=admin\nCREDENTIAL_ENCRYPTION_KEY=canary-inline-key-value\n"
    env_file.write_text(content)
    result = _run_pty(sandbox, "bootstrap.sh", [], cwd=tmp_path, FAKE_VERIFIER_RAW="x")
    assert result.returncode != 0
    assert "inline CREDENTIAL_ENCRYPTION_KEY" in result.stderr
    assert "docs/installation.md" in result.stderr
    assert "canary-inline-key-value" not in result.stdout + result.stderr  # never echoed
    assert env_file.read_text() == content
    assert not (sandbox.root / "secrets").exists()  # no new key was minted
    assert not any(c.startswith("build ") for c in sandbox.calls())


def test_bootstrap_preserves_an_existing_key_and_tightens_its_directory(sandbox, tmp_path):
    key_dir = sandbox.root / "secrets"
    key_dir.mkdir()
    key_file = key_dir / "credential_key"
    original = "Zm9yLXRlc3RzLW9ubHktbm90LWEtcmVhbC1rZXktMTIzNDU=\n"
    key_file.write_text(original)
    key_file.chmod(0o666)
    key_dir.chmod(0o755)

    result = _run_pty(
        sandbox, "bootstrap.sh", [], cwd=tmp_path,
        FAKE_VERIFIER_RAW=_verifier_line() + "\n",
    )
    assert result.returncode == 0, result.stderr
    assert key_file.read_text() == original  # byte-for-byte unchanged
    assert _mode(key_dir) == 0o700  # loose directory permissions were tightened
    assert not _mode(key_file) & 0o022  # and the key is no longer group/world-writable
    assert "Keeping the existing credential encryption key" in result.stdout
    assert (sandbox.root / "backend" / ".env").exists()


def test_bootstrap_refuses_to_use_the_checkout_root_as_the_key_directory(sandbox, tmp_path):
    root_mode = _mode(sandbox.root)
    result = _run_pty(
        sandbox, "bootstrap.sh", [], cwd=tmp_path,
        FAKE_VERIFIER_RAW=_verifier_line() + "\n",
        HOME_NOC_CREDENTIAL_KEY_FILE="credential_key",
    )
    assert result.returncode != 0 and "dedicated directory" in result.stderr
    assert not (sandbox.root / "credential_key").exists()
    assert not (sandbox.root / "backend" / ".env").exists()
    assert _mode(sandbox.root) == root_mode  # the checkout directory is never chmod'ed


def test_bootstrap_script_has_no_unsafe_verifier_check():
    text = (SCRIPTS / "bootstrap.sh").read_text()
    assert "VERIFIER_RE=" in text and "{22}==" in text and "{43}=" in text
    assert '[[ "$verifier_line" =~ $VERIFIER_RE ]]' in text
    # The old check put "$[0-9]" in double quotes, i.e. Bash arithmetic expansion.
    assert not re.search(r"grep[^\n]*pbkdf2", text)


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
@pytest.mark.parametrize(
    "script", ["bootstrap.sh", "backup.sh", "restore.sh", "ci-restore-integration.sh"]
)
def test_operator_scripts_pass_shellcheck(script):
    result = subprocess.run(  # noqa: S603, S607 - fixed argv, tool resolved from PATH
        ["shellcheck", "--shell=bash", "--external-sources", str(SCRIPTS / script)],  # noqa: S607
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# --------------------------------------------------------------------------
# B3 + B4: restore.sh path resolution and container-state protection
# --------------------------------------------------------------------------

BACKUP_BYTES = b"SQLite format 3\x00" + b"home-noc-backup-payload" * 8


def _backup_file(directory: Path, name: str = "b.sqlite3") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(BACKUP_BYTES)
    return path


@pytest.mark.parametrize("style", ["absolute", "relative-sibling", "relative-nested"])
def test_restore_resolves_the_backup_relative_to_the_callers_directory(sandbox, tmp_path, style):
    backup = _backup_file(tmp_path / "outside-the-checkout")
    caller = tmp_path / "callers" / "deep" / "dir"
    caller.mkdir(parents=True)
    argument = str(backup) if style == "absolute" else os.path.relpath(backup, caller)
    if style == "relative-sibling":
        caller = tmp_path / "callers"
        argument = os.path.relpath(backup, caller)

    result = _run(sandbox, "restore.sh", [argument], cwd=caller)

    assert result.returncode == 0, result.stderr
    assert (sandbox.state / "restore_stdin.bin").read_bytes() == BACKUP_BYTES
    run_call = next(c for c in sandbox.calls() if c.startswith("compose run "))
    assert run_call.endswith("python -m app.dbtool restore")  # no --replace implied


def test_restore_finds_a_backup_inside_the_checkout_from_another_directory(sandbox):
    backup = _backup_file(sandbox.root / "backups")
    caller = sandbox.root / "scripts"
    result = _run(sandbox, "restore.sh", [os.path.relpath(backup, caller)], cwd=caller)
    assert result.returncode == 0, result.stderr
    assert (sandbox.state / "restore_stdin.bin").read_bytes() == BACKUP_BYTES


def test_restore_rejects_missing_or_non_sqlite_input_before_touching_docker(sandbox, tmp_path):
    result = _run(sandbox, "restore.sh", ["nope.sqlite3"], cwd=tmp_path)
    assert result.returncode != 0 and "not found" in result.stderr
    junk = tmp_path / "junk.sqlite3"
    junk.write_bytes(b"not a database")
    result = _run(sandbox, "restore.sh", [str(junk)], cwd=tmp_path)
    assert result.returncode != 0 and "not a SQLite backup" in result.stderr
    assert junk.read_bytes() == b"not a database"
    assert sandbox.calls() == []


@pytest.mark.parametrize("state", ["running", "restarting", "paused", "exited", "created"])
def test_restore_refuses_when_any_service_container_exists(sandbox, tmp_path, state):
    backup = _backup_file(tmp_path)
    result = _run(sandbox, "restore.sh", [str(backup)], cwd=tmp_path, FAKE_DOCKER_STATE=state)

    assert result.returncode != 0, state
    assert "docker compose down" in result.stderr
    assert "do NOT add -v" in result.stderr
    calls = sandbox.calls()
    assert not any(c.startswith("compose run") for c in calls)  # nothing was restored
    assert not (sandbox.state / "restore_stdin.bin").exists()
    # The script never stops, removes or deletes anything on the operator's behalf.
    assert not [c for c in calls if any(c.startswith(d) for d in DESTRUCTIVE)]
    assert backup.read_bytes() == BACKUP_BYTES  # the backup is preserved on every refusal


def test_restore_lists_containers_in_every_state(sandbox, tmp_path):
    backup = _backup_file(tmp_path)
    result = _run(sandbox, "restore.sh", [str(backup)], cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "compose ps -a -q backend worker connector-worker frontend" in sandbox.calls()
    assert not any("--status" in c for c in sandbox.calls())  # no state-filtered check


def test_restore_fails_closed_when_docker_cannot_report_container_state(sandbox, tmp_path):
    backup = _backup_file(tmp_path)
    result = _run(sandbox, "restore.sh", [str(backup)], cwd=tmp_path, FAKE_DOCKER_PS_FAIL="1")
    assert result.returncode != 0 and "could not determine" in result.stderr
    assert not any(c.startswith("compose run") for c in sandbox.calls())
    assert backup.read_bytes() == BACKUP_BYTES


def test_restore_replace_requires_explicit_confirmation(sandbox, tmp_path):
    backup = _backup_file(tmp_path)
    for confirm in ({}, {"HOME_NOC_RESTORE_CONFIRM": "yes"}):
        result = _run(sandbox, "restore.sh", ["--replace", str(backup)], cwd=tmp_path, **confirm)
        assert result.returncode != 0 and "terminal confirmation" in result.stderr
    assert not any(c.startswith("compose run") for c in sandbox.calls())

    result = _run(
        sandbox, "restore.sh", ["--replace", str(backup)], cwd=tmp_path,
        HOME_NOC_RESTORE_CONFIRM="REPLACE",
    )
    assert result.returncode == 0, result.stderr
    run_call = next(c for c in sandbox.calls() if c.startswith("compose run "))
    assert run_call.endswith("restore --replace")


def test_restore_reports_a_refusal_from_the_database_tool_and_keeps_the_backup(sandbox, tmp_path):
    backup = _backup_file(tmp_path)
    result = _run(sandbox, "restore.sh", [str(backup)], cwd=tmp_path, FAKE_DOCKER_RUN_RC="3")
    assert result.returncode == 3
    assert "Restored." not in result.stdout
    assert backup.read_bytes() == BACKUP_BYTES


def test_restore_script_never_deletes_or_stops_anything():
    text = (SCRIPTS / "restore.sh").read_text()
    executable = "\n".join(
        ln for ln in text.splitlines() if not ln.lstrip().startswith(("#", "echo", "fail"))
    )
    assert not re.search(
        r"(?m)^[ \\t]*(?:exec[ \\t]+)?docker[ \\t]+compose[ \\t]+"
        r"(?:down|stop|rm|kill|restart)\\b",
        executable,
    )
    assert not re.search(r"(?m)^\s*(?:command\s+)?(?:rm|rmdir)\s+", executable)
    assert "--status" not in text  # the check must not be limited to running containers
    # Paths are made absolute before the working directory changes.
    assert text.index('BACKUP="$(abspath "$1")"') < text.index("cd -- ")


# --------------------------------------------------------------------------
# B3 + ADDITIONAL 4: backup.sh path resolution and destination races
# --------------------------------------------------------------------------


def _backups_in(directory: Path) -> list[Path]:
    return sorted(directory.glob("home-noc-*.sqlite3"))


def test_backup_destination_is_relative_to_the_callers_directory(sandbox, tmp_path):
    caller = tmp_path / "caller"
    caller.mkdir()
    result = _run(
        sandbox, "backup.sh", ["rel-out/backups"], cwd=caller, FAKE_DOCKER_STATE="running"
    )

    assert result.returncode == 0, result.stderr
    dest = caller / "rel-out" / "backups"
    (written,) = _backups_in(dest)
    assert f"Backup written: {written}" in result.stdout
    assert written.read_bytes().startswith(b"SQLite format 3\x00")
    assert _mode(written) == 0o600 and _mode(dest) == 0o700
    assert not list(dest.glob(".*partial"))
    assert not (sandbox.root / "rel-out").exists()  # nothing landed in the checkout


def test_backup_env_destination_is_also_caller_relative(sandbox, tmp_path):
    caller = tmp_path / "caller"
    caller.mkdir()
    result = _run(
        sandbox, "backup.sh", [], cwd=caller, FAKE_DOCKER_STATE="running",
        HOME_NOC_BACKUP_DIR="env-relative",
    )
    assert result.returncode == 0, result.stderr
    assert len(_backups_in(caller / "env-relative")) == 1
    assert not (sandbox.root / "env-relative").exists()


def test_backup_default_destination_is_the_checkouts_backups_directory(sandbox, tmp_path):
    caller = tmp_path / "caller"
    caller.mkdir()
    result = _run(sandbox, "backup.sh", [], cwd=caller, FAKE_DOCKER_STATE="running")
    assert result.returncode == 0, result.stderr
    assert len(_backups_in(sandbox.root / "backups")) == 1
    assert not (caller / "backups").exists()


def test_backup_accepts_an_absolute_destination_outside_the_checkout(sandbox, tmp_path):
    dest = tmp_path / "somewhere" / "else"
    result = _run(sandbox, "backup.sh", [str(dest)], cwd=tmp_path, FAKE_DOCKER_STATE="running")
    assert result.returncode == 0, result.stderr
    assert len(_backups_in(dest)) == 1


def test_backup_requires_a_running_backend_and_creates_nothing_otherwise(sandbox, tmp_path):
    dest = tmp_path / "dest"
    result = _run(sandbox, "backup.sh", [str(dest)], cwd=tmp_path, FAKE_DOCKER_STATE="exited")
    assert result.returncode != 0 and "not running" in result.stderr
    assert not dest.exists()


def test_backup_never_reports_success_over_an_existing_destination(sandbox, tmp_path):
    sandbox.fix_date()
    dest = tmp_path / "dest"
    dest.mkdir()
    existing = dest / f"home-noc-{FAKE_STAMP}.sqlite3"
    existing.write_bytes(b"precious-older-backup")

    result = _run(sandbox, "backup.sh", [str(dest)], cwd=tmp_path, FAKE_DOCKER_STATE="running")

    assert result.returncode != 0 and "already exists" in result.stderr
    assert "Backup written" not in result.stdout
    assert existing.read_bytes() == b"precious-older-backup"
    assert not list(dest.glob(".*partial"))


def test_backup_destination_race_is_an_error_not_a_silent_skip(sandbox, tmp_path):
    """The destination appears while the snapshot is being taken."""
    sandbox.fix_date()
    dest = tmp_path / "dest"
    dest.mkdir()
    final = dest / f"home-noc-{FAKE_STAMP}.sqlite3"

    result = _run(
        sandbox, "backup.sh", [str(dest)], cwd=tmp_path, FAKE_DOCKER_STATE="running",
        FAKE_RACE_DEST=str(final),
    )

    assert result.returncode != 0
    assert "appeared while the backup ran" in result.stderr
    assert "Backup written" not in result.stdout  # never claims success
    assert final.read_bytes() == b"raced-content"  # the other writer's file is intact
    assert not list(dest.glob(".*partial"))


def test_backup_treats_a_dangling_symlink_as_an_existing_destination(sandbox, tmp_path):
    sandbox.fix_date()
    dest = tmp_path / "dest"
    dest.mkdir()
    ghost = tmp_path / "ghost"
    final = dest / f"home-noc-{FAKE_STAMP}.sqlite3"
    final.symlink_to(ghost)

    result = _run(sandbox, "backup.sh", [str(dest)], cwd=tmp_path, FAKE_DOCKER_STATE="running")

    assert result.returncode != 0 and "Backup written" not in result.stdout
    assert final.is_symlink() and os.readlink(final) == str(ghost)
    assert not ghost.exists()  # nothing was written through the link


def test_backup_script_warns_that_backups_are_not_encrypted():
    text = (SCRIPTS / "backup.sh").read_text()
    assert "NOT encrypted" in text and "inventory" in text
    assert 'ln -- "$PARTIAL" "$FINAL"' in text  # no-clobber publish, not a silent mv -n
