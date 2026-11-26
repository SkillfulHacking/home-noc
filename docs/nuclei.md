# Nuclei vulnerability profile (M17)

An **opt-in, operator-approved** profile (`vuln`) that runs a curated set of read-only Nuclei checks against HTTP services that Home-NOC *already knows* on authorized hosts. Aggressive checks are out of the MVP.

## Enabling and running
1. Set `SCAN_VULN_PROFILE_ENABLED=true` for the API and the **scanner worker** (default off). Public addresses are never allowed (the profile is intrusive-class; the existing public-scan rules apply).
2. `POST /api/v1/scans/preflight` `{"targets": ["10.0.0.0/28"], "profile": "vuln"}` returns a `plan`: the exact URLs, templates, pinned versions, limits and an `approval_digest`.
3. Review it, then `POST /api/v1/scans/jobs` with the same body plus `"approval_digest"`. Missing → `409 approval_required`; stale → `409 approval_mismatch`. The digest is stored on the job, and the worker recomputes the plan and refuses (`approval_stale`) if targets, ports, the allowlist or pins changed since approval. The digest deliberately covers only container-independent data (the API image carries no Nuclei); the worker separately verifies the *installed* Nuclei/templates versions equal the pins in `app/nuclei.py::PINNED` (a test ties them to the Dockerfile) and fails with `version_mismatch` otherwise.
4. Cancel as for any job: the whole Nuclei process group is killed.

## Safety properties
- **No target expansion:** URLs are `http(s)://<authorized IPv4>:<port>` built from open HTTP ports (80, 443, 8000, 8080, 8443, 8888) already recorded for a device holding that address. No hostnames, CIDR sweeps or redirects; findings for any other host are discarded and counted.
- **Curated templates:** `app/nuclei.py::SAFE_TEMPLATES` (7 read-only HTTP GET templates: tech detection, favicon, security headers, directory listing, PHP errors, exposed `.git/config` and `.DS_Store`; nothing that sends unusual HTTP methods). Missing/symlinked files are excluded and reported. Tags `dos, fuzz, intrusive, bruteforce, rce, sqli, xss, dast, oast, default-login, takeover` are excluded, only the `http` protocol runs, interactsh/OAST (`-ni`) and update checks (`-duc`) are off, and the current `-jsonl` output flag is used.
- **Bounded:** rate limit (`NUCLEI_RATE_LIMIT`, 10 rps), concurrency (5), 5 s request timeout, no retries, 30 min job deadline (partial findings are kept and flagged `timed_out`), 8 MiB output cap, 500 findings, 64 URLs.
- **Minimal environment:** Nuclei runs with a scrubbed environment and a throw-away `HOME`; the scanner worker holds no credential key.
- **Sanitized output:** raw requests/responses and curl commands are dropped; text is length-bounded and secret-redacted (`app/redaction.py`).

## Image and versions
The worker image installs Nuclei **v3.11.1** and nuclei-templates **v10.5.2** (HTTP templates only) from GitHub releases, verifying sha256 values that match the upstream-published checksum files (build fails otherwise); versions are written to `/opt/nuclei/versions.json` and recorded in each result. Upgrade by changing the `NUCLEI_*` build args together and re-verifying the checksums. The templates archive is a GitHub tag archive; GitHub does not guarantee archive byte-stability, so a changed hash must be investigated, not silently updated.

## Verification
Automated with a fake scanner (argv safety, approval, scope, cancel, deadline, env scrubbing, out-of-scope discard). Also verified for real: the pinned binary run with our exact arguments against a throw-away loopback HTTP server, both on the host (`NUCLEI_BIN`/`NUCLEI_TEMPLATES` env enables that test) and inside the built, unprivileged, read-only worker image (7 templates usable, findings parsed). Not verified against a real lab service on the LAN; no template-content review beyond the allowlist.
