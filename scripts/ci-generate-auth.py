#!/usr/bin/env python3
"""Generate disposable administrator credentials for CI only."""

import base64, hashlib, os, secrets

password = secrets.token_urlsafe(24)
# Mask before anything could possibly log it.
print(f"::add-mask::{password}")
iterations = 600_000
salt = secrets.token_bytes(16)
digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
b64 = lambda raw: base64.b64encode(raw).decode("ascii")
verifier = f"pbkdf2_sha256${iterations}${b64(salt)}${b64(digest)}"
print(f"::add-mask::{verifier}")

# Single quotes: Compose env_file would otherwise interpolate the
# '$' separators in the verifier.
with open(os.environ["ENV_FILE"], "a", encoding="utf-8") as fh:
    fh.write("\nADMIN_USERNAME=admin\n")
    fh.write(f"ADMIN_PASSWORD_HASH='{verifier}'\n")
    fh.write("SESSION_COOKIE_SECURE=false\n")
with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as fh:
    fh.write(f"HOME_NOC_ADMIN_PASSWORD={password}\n")
