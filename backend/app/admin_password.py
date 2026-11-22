"""Generate an ``ADMIN_PASSWORD_HASH`` verifier for Home-NOC.

Usage (the password is read from a TTY prompt, never from argv, so it does
not land in shell history or the process table)::

    python -m app.admin_password

Prints only the verifier string. The raw password is never written to
stdout, to a file, or to the database.
"""
from __future__ import annotations

import getpass
import sys

from .auth import DEFAULT_ITERATIONS, MIN_PASSWORD_LENGTH, PasswordPolicyError, hash_password


def main() -> int:
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

    print("\nAdd this line to backend/.env (keep the file out of Git):\n")
    print(f"ADMIN_PASSWORD_HASH={verifier}")
    return 0


if __name__ == "__main__":  # pragma: no cover - thin CLI wrapper
    raise SystemExit(main())
