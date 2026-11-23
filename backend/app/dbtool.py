"""Operator database tooling for backup, guarded restore and permissions (M07).

Run inside the backend container (see ``scripts/backup.sh`` / ``scripts/restore.sh``)::

    python -m app.dbtool backup  > backup.sqlite3     # stream a consistent snapshot
    python -m app.dbtool restore < backup.sqlite3     # refuses to overwrite
    python -m app.dbtool restore --replace < backup   # moves the old DB aside first
    python -m app.dbtool harden                       # chmod 0600 on database files
    python -m app.dbtool check-key                    # read-only: does the key fit the DB?

Design rules:

* Backups use SQLite's online backup API (``sqlite3.Connection.backup``), which
  yields a transactionally consistent copy while the application is running.
  The live file is never copied byte-for-byte.
* A backup holds the SQLite data only. The credential encryption key lives
  outside the database and is never read, written or embedded here; the
  database stores only the one-way ``credential_key_verifier``.
* Restore verifies the candidate (SQLite header, ``integrity_check``,
  ``foreign_key_check``, expected schema) and, when a key is configured, that the
  key matches the candidate's verifier *before* anything in ``/data`` changes.
  An existing database is never overwritten: without ``--replace`` restore
  aborts; with it the old files are moved aside (never deleted).
* Installation is *no-clobber at the filesystem level*: the validated candidate
  (spooled on the same filesystem) is hard-linked to the final name. ``link(2)``
  fails with EEXIST for any existing name, including a dangling symlink or a
  database created after the initial check, so a race can never overwrite data.
  If hard links are unavailable the restore fails closed instead of falling
  back to an overwriting rename.
* ``--replace`` moves the database *and* its journal sidecars aside with the
  same no-clobber primitive and rolls every move back if any later step fails.
  If a rollback itself cannot complete, the preserved file names are reported.
* A backup that predates the key-verifier table (migration 0005) is accepted
  only if every stored ciphertext authenticates under the configured key.
* Diagnostics go to stderr and never include key, password or ciphertext data.
"""
from __future__ import annotations

import argparse
import contextlib
import os
import sqlite3
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from .config import settings

SQLITE_HEADER = b"SQLite format 3\x00"
SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
REQUIRED_TABLES = frozenset({"alembic_version", "devices", "admin_sessions"})
DEFAULT_MAX_RESTORE_BYTES = 1024 * 1024 * 1024  # 1 GiB; far above a home inventory
_CHUNK = 1024 * 1024

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_REFUSED = 3


class DbToolError(Exception):
    """A fatal, operator-readable failure (message is secret-free)."""

    def __init__(self, message: str, code: int = EXIT_FAILURE) -> None:
        super().__init__(message)
        self.code = code


def _log(message: str) -> None:
    print(f"dbtool: {message}", file=sys.stderr)


def database_path(url: str | None = None) -> Path:
    """Resolve the SQLite file behind ``DATABASE_URL``; reject anything else."""
    parsed = make_url(url or settings.database_url)
    if parsed.get_backend_name() != "sqlite":
        raise DbToolError("only SQLite databases are supported")
    if not parsed.database or parsed.database == ":memory:":
        raise DbToolError("an on-disk SQLite database is required")
    return Path(parsed.database)


def _ro_uri(path: Path) -> str:
    return f"{path.resolve().as_uri()}?mode=ro"


def _check_integrity(path: Path) -> None:
    """Raise unless ``path`` is an intact SQLite database."""
    try:
        conn = sqlite3.connect(_ro_uri(path), uri=True, timeout=30)
    except sqlite3.Error:
        raise DbToolError("file is not a readable SQLite database") from None
    try:
        rows = conn.execute("PRAGMA integrity_check").fetchall()
        if rows != [("ok",)]:
            raise DbToolError("SQLite integrity_check failed")
        if conn.execute("PRAGMA foreign_key_check").fetchall():
            raise DbToolError("SQLite foreign_key_check failed")
    except sqlite3.Error:
        raise DbToolError("file is not a valid SQLite database") from None
    finally:
        conn.close()


def _tables(path: Path) -> set[str]:
    conn = sqlite3.connect(_ro_uri(path), uri=True, timeout=30)
    try:
        return {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    finally:
        conn.close()


# --------------------------------------------------------------------------
# backup
# --------------------------------------------------------------------------


def create_backup(source: Path, destination: Path) -> None:
    """Write a consistent snapshot of ``source`` to the new file ``destination``."""
    if not source.is_file():
        raise DbToolError("database file does not exist")
    # lexists: a dangling symlink is an existing name too.
    if os.path.lexists(destination):
        raise DbToolError("backup destination already exists", EXIT_REFUSED)
    try:
        # O_EXCL (no symlink following) closes the race between the check above
        # and creation. Only a file *we* created is ever cleaned up below.
        fd = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
    except FileExistsError:
        raise DbToolError("backup destination already exists", EXIT_REFUSED) from None
    os.close(fd)
    try:
        src = sqlite3.connect(_ro_uri(source), uri=True, timeout=30)
        try:
            dst = sqlite3.connect(destination)
            try:
                src.backup(dst)  # SQLite online backup API
                dst.execute("PRAGMA journal_mode=DELETE")
            finally:
                dst.close()
        finally:
            src.close()
    except sqlite3.Error:
        destination.unlink(missing_ok=True)
        raise DbToolError("SQLite backup failed") from None
    try:
        _check_integrity(destination)
    except DbToolError:
        destination.unlink(missing_ok=True)
        raise
    os.chmod(destination, 0o600)


def cmd_backup(args: argparse.Namespace) -> int:
    source = database_path()
    if args.output:
        create_backup(source, Path(args.output))
        _log(f"backup written to {args.output}")
        return EXIT_OK
    with tempfile.TemporaryDirectory(prefix="home-noc-backup-") as tmp:
        snapshot = Path(tmp) / "snapshot.sqlite3"
        create_backup(source, snapshot)
        out = sys.stdout.buffer
        with snapshot.open("rb") as fh:
            while chunk := fh.read(_CHUNK):
                out.write(chunk)
        out.flush()
    _log("backup streamed (verified with integrity_check)")
    return EXIT_OK


# --------------------------------------------------------------------------
# restore
# --------------------------------------------------------------------------


def _receive(stream, target_dir: Path, max_bytes: int) -> Path:
    """Spool ``stream`` into a private temp file next to the database."""
    fd, name = tempfile.mkstemp(prefix=".restore-", suffix=".tmp", dir=target_dir)
    path = Path(name)
    total = 0
    try:
        with os.fdopen(fd, "wb") as out:
            while chunk := stream.read(_CHUNK):
                total += len(chunk)
                if total > max_bytes:
                    raise DbToolError("backup exceeds the maximum accepted size")
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


def _validate_candidate(path: Path, *, check_key: bool) -> None:
    with path.open("rb") as fh:
        if fh.read(len(SQLITE_HEADER)) != SQLITE_HEADER:
            raise DbToolError("input is not a SQLite database")
    _check_integrity(path)
    missing = REQUIRED_TABLES - _tables(path)
    if missing:
        raise DbToolError("input is not a Home-NOC database (expected tables missing)")
    if check_key:
        _check_key_matches(path)


def _check_key_matches(path: Path) -> None:
    """Refuse a database whose credentials the configured key cannot open."""
    from . import crypto, key_binding

    try:
        key = crypto.load_key()
    except crypto.CredentialKeyError:
        raise DbToolError(
            "no usable credential encryption key is configured, so the backup cannot be "
            "matched to it; provide the original key (or pass --skip-key-check)"
        ) from None
    tables = _tables(path)
    engine = _readonly_engine(path)
    try:
        with Session(engine) as db:
            if "credential_key_verifier" in tables:
                key_binding.check_usable(db, key)
            elif "connector_credentials" in tables:
                # Pre-0005 backup: no verifier exists, so the key is accepted only
                # if every stored ciphertext authenticates under it. Deferring
                # this to the first credential write would let a wrong key be
                # installed and only fail later.
                key_binding.authenticate_existing(db, key)
            # else: pre-0004 backup, no ciphertext exists; nothing to authenticate.
    except key_binding.CredentialKeyMismatchError:
        raise DbToolError(
            "the configured credential encryption key does not match this backup; "
            "restore the key that was active when the backup was taken",
            EXIT_REFUSED,
        ) from None
    except (key_binding.CredentialKeyVerificationUnavailable, SQLAlchemyError):
        # Unsupported verifier version, unreadable table, ...: fail closed.
        raise DbToolError(
            "could not verify the credential encryption key against this backup, so it "
            "was not installed (use --skip-key-check only if you accept an unverified key)",
            EXIT_REFUSED,
        ) from None
    finally:
        engine.dispose()


def _readonly_engine(path: Path):
    """SQLAlchemy engine that can only read ``path`` (never creates or alters it)."""
    return create_engine(
        "sqlite://",
        creator=lambda: sqlite3.connect(_ro_uri(path), uri=True, timeout=30),
        poolclass=NullPool,
    )


def _family(target: Path) -> list[Path]:
    """The database file followed by its SQLite journal sidecars."""
    return [target, *(Path(f"{target}{s}") for s in SIDECAR_SUFFIXES)]


def _existing_family(target: Path) -> list[Path]:
    # lexists, not exists: a dangling symlink occupies the name and must count.
    return [p for p in _family(target) if os.path.lexists(p)]


def _refuse_existing() -> DbToolError:
    return DbToolError(
        "a database already exists; refusing to overwrite it. Re-run with --replace "
        "to move it aside (it is renamed, never deleted)",
        EXIT_REFUSED,
    )


def _fsync_dir(directory: Path) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        with contextlib.suppress(OSError):
            os.fsync(fd)
    finally:
        os.close(fd)


def _link_noclobber(src: Path, dst: Path) -> None:
    """Give ``src`` the additional name ``dst``; never replaces anything.

    ``FileExistsError`` propagates when ``dst`` is taken (including by a
    dangling symlink). Any other failure means the filesystem cannot offer the
    guarantee, so the operation fails closed rather than falling back to an
    overwriting ``rename``.
    """
    try:
        os.link(src, dst, follow_symlinks=False)
    except FileExistsError:
        raise
    except (OSError, NotImplementedError) as exc:
        reason = getattr(exc, "strerror", None) or type(exc).__name__
        raise DbToolError(
            f"the filesystem refused the hard link needed for a no-clobber install ({reason})"
        ) from None


def _move_aside(src: Path, dst: Path) -> None:
    """No-clobber move: link ``src`` to ``dst``, then drop the old name."""
    try:
        _link_noclobber(src, dst)
    except FileExistsError:
        raise DbToolError(
            "a pre-restore file name is already taken; nothing was overwritten, retry",
            EXIT_REFUSED,
        ) from None
    try:
        os.unlink(src)
    except OSError:
        # Keep the original where it is; drop only the extra name made above.
        Path(dst).unlink(missing_ok=True)
        raise DbToolError("could not move the existing database aside") from None


def _aside_base(target: Path, stamp: str) -> Path:
    """An unused ``<db>.pre-restore-<stamp>[-n]`` base name for the whole family."""
    for n in range(100):
        base = target.with_name(f"{target.name}.pre-restore-{stamp}" + (f"-{n}" if n else ""))
        if not any(os.path.lexists(Path(f"{base}{s}")) for s in ("", *SIDECAR_SUFFIXES)):
            return base
    raise DbToolError("could not choose an unused pre-restore name; retry")


def _rollback(moved: list[tuple[Path, Path]], cause: BaseException) -> None:
    """Undo ``--replace`` moves in reverse order; raise if any file stays displaced."""
    stuck: list[Path] = []
    for original, aside in reversed(moved):
        try:
            _move_aside(aside, original)
        except (DbToolError, OSError):
            stuck.append(aside)
    if stuck:
        reason = str(cause) if isinstance(cause, DbToolError) else type(cause).__name__
        code = cause.code if isinstance(cause, DbToolError) else EXIT_FAILURE
        raise DbToolError(
            f"restore failed ({reason}) and the original database could not be fully put "
            "back. Nothing was deleted; the original files are preserved at: "
            + ", ".join(str(p) for p in stuck),
            code,
        ) from None


def _same_file(a: Path, b: Path) -> bool:
    try:
        return os.path.samestat(os.lstat(a), os.lstat(b))
    except OSError:
        return False


def _install_candidate(candidate: Path, target: Path) -> None:
    """Atomically publish ``candidate`` as ``target`` without ever replacing a file."""
    try:
        _link_noclobber(candidate, target)
    except FileExistsError:
        raise DbToolError(
            "a database appeared while restoring; refusing to overwrite it", EXIT_REFUSED
        ) from None
    # A journal that appeared in the race window would corrupt the new database.
    if any(os.path.lexists(p) for p in _family(target)[1:]):
        if _same_file(candidate, target):
            target.unlink()  # only the link this call just created
        raise DbToolError(
            "database journal files appeared while restoring; nothing was installed",
            EXIT_REFUSED,
        )
    candidate.unlink()
    _fsync_dir(target.parent)


def restore_database(
    stream,
    target: Path,
    *,
    replace: bool = False,
    check_key: bool = True,
    max_bytes: int = DEFAULT_MAX_RESTORE_BYTES,
) -> Path | None:
    """Install a backup read from ``stream`` at ``target``.

    Returns the base path the previous database was moved to (``replace`` only).
    No existing file is ever overwritten or deleted, on any path.
    """
    target_dir = target.parent
    if not target_dir.is_dir():
        raise DbToolError("database directory does not exist")
    # Cheap early refusal before spooling; the authoritative check is the
    # no-clobber link in _install_candidate, which no race can bypass.
    if _existing_family(target) and not replace:
        raise _refuse_existing()

    candidate = _receive(stream, target_dir, max_bytes)
    moved_to: Path | None = None
    try:
        _validate_candidate(candidate, check_key=check_key)
        os.chmod(candidate, 0o600)
        # Re-evaluated after the (possibly long) upload: the state may have changed.
        existing = _existing_family(target)
        if existing and not replace:
            raise _refuse_existing()
        for path in existing:
            if path.is_dir() and not path.is_symlink():
                raise DbToolError("an existing database path is a directory; not touching it")

        moved: list[tuple[Path, Path]] = []
        if existing:
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            base = _aside_base(target, stamp)
            # Journals first, the main file last, so a main database is never left
            # sitting next to a journal that belongs to a different generation.
            for path in sorted(existing, key=lambda p: p == target):
                aside = Path(f"{base}{path.name[len(target.name):]}")
                try:
                    _move_aside(path, aside)
                except BaseException as exc:
                    _rollback(moved, exc)
                    raise
                moved.append((path, aside))
            moved_to = base
        try:
            _install_candidate(candidate, target)
        except BaseException as exc:
            _rollback(moved, exc)
            raise
    finally:
        # After a successful install the candidate name is already gone.
        Path(candidate).unlink(missing_ok=True)
    return moved_to


def cmd_restore(args: argparse.Namespace) -> int:
    target = database_path()
    moved = restore_database(
        sys.stdin.buffer,
        target,
        replace=args.replace,
        check_key=not args.skip_key_check,
        max_bytes=args.max_bytes,
    )
    if moved is not None:
        _log(f"previous database kept at {moved}")
    _log(f"database restored to {target}; start the stack to apply any newer migrations")
    return EXIT_OK


# --------------------------------------------------------------------------
# permissions
# --------------------------------------------------------------------------


def harden_permissions(target: Path) -> None:
    """Restrict the database, its journals and its directory to the owner."""
    for path in [target, *(Path(f"{target}{s}") for s in SIDECAR_SUFFIXES)]:
        if path.is_file():
            os.chmod(path, 0o600)
    try:
        os.chmod(target.parent, 0o700)
    except PermissionError:
        _log("could not restrict the data directory mode (not the owner)")


def cmd_harden(_args: argparse.Namespace) -> int:
    harden_permissions(database_path())
    return EXIT_OK


def cmd_check_key(_args: argparse.Namespace) -> int:
    """Read-only proof that the configured key belongs to the database.

    Lets an operator confirm that an existing key was moved to the secret-file
    configuration unchanged, or that a restored database matches its key.
    """
    target = database_path()
    if not target.is_file():
        raise DbToolError("database file does not exist")
    _check_key_matches(target)
    _log("the configured credential encryption key is valid for this database")
    return EXIT_OK


# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.dbtool")
    sub = parser.add_subparsers(dest="command", required=True)

    backup = sub.add_parser("backup", help="stream a consistent snapshot to stdout")
    backup.add_argument("--output", help="write to this new file instead of stdout")
    backup.set_defaults(func=cmd_backup)

    restore = sub.add_parser("restore", help="restore a backup read from stdin")
    restore.add_argument(
        "--replace",
        action="store_true",
        help="move an existing database aside (renamed, never deleted) before restoring",
    )
    restore.add_argument(
        "--skip-key-check",
        action="store_true",
        help="do not require the configured key to match the backup (not recommended)",
    )
    restore.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_RESTORE_BYTES)
    restore.set_defaults(func=cmd_restore)

    harden = sub.add_parser("harden", help="restrict database file permissions")
    harden.set_defaults(func=cmd_harden)

    check_key = sub.add_parser("check-key", help="verify the configured key (read-only)")
    check_key.set_defaults(func=cmd_check_key)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except DbToolError as exc:
        _log(f"ERROR: {exc}")
        return exc.code


if __name__ == "__main__":  # pragma: no cover - thin CLI wrapper
    raise SystemExit(main())
