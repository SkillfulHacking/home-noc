"""Generate an ``ADMIN_PASSWORD_HASH`` verifier for Home-NOC.

Usage (the password is read from a TTY prompt, never from argv, so it does
not land in shell history or the process table)::

    python -m app.admin_password

Prints only the verifier string. The raw password is never written to
stdout, to a file, or to the database.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

from .auth import DEFAULT_ITERATIONS, MIN_PASSWORD_LENGTH, PasswordPolicyError, hash_password


def format_env_line(verifier: str) -> str:
    """Render the env-file line for ``verifier``.

    Single quotes are required: Docker Compose interpolates ``$`` in
    ``env_file`` values, and the verifier uses ``$`` as its separator.
    """
    if "'" in verifier or "\n" in verifier:  # base64 alphabet never contains these
        raise ValueError("verifier contains characters that cannot be quoted safely")
    return f"ADMIN_PASSWORD_HASH='{verifier}'"


def _write_private_file(path: str, content: str) -> None:
    """Create ``path`` exclusively with mode 0600; never overwrite."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(content)


def main(argv: list[str] | None = None) -> int:
    # Default to no arguments (not sys.argv) so programmatic callers and tests
    # are unaffected; the ``__main__`` entry point passes the real argv.
    parser = argparse.ArgumentParser(prog="python -m app.admin_password")
    parser.add_argument(
        "--output",
        help="write the quoted env line to this new file (mode 0600) instead of stdout",
    )
    args = parser.parse_args(argv or [])

    if not sys.stdin.isatty():
        print(
            "Refusing to read the admin password from a pipe; run this "
            "interactively so the secret is not captured in logs or history.",
            file=sys.stderr,
        )
        return 2

    password = getpass.getpass("New Home-NOC admin password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords did not match.", file=sys.stderr)
        return 1
    try:
        verifier = hash_password(password, iterations=DEFAULT_ITERATIONS)
    except PasswordPolicyError as exc:
        print(f"{exc} (minimum {MIN_PASSWORD_LENGTH} characters).", file=sys.stderr)
        return 1

    if args.output:
        try:
            _write_private_file(args.output, format_env_line(verifier) + "\n")
        except (OSError, ValueError) as exc:
            print(f"Could not write verifier file: {type(exc).__name__}", file=sys.stderr)
            return 1
        return 0

    print("\nAdd this line to backend/.env (keep the file out of Git):\n")
    print(f"ADMIN_PASSWORD_HASH={verifier}")
    print(
        "\nNote: Docker Compose interpolates '$' in env files. Wrap the value in single "
        "quotes: ADMIN_PASSWORD_HASH='<value>' (scripts/bootstrap.sh does this for you).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - thin CLI wrapper
    raise SystemExit(main(sys.argv[1:]))
