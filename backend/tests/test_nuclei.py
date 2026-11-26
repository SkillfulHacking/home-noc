"""M17 Nuclei profile: safe argv, plan/approval, bounded execution, sanitized parsing."""
from __future__ import annotations

import dataclasses
import json
import os
import stat
import time
import uuid

import pytest

from app import nuclei
from app.models import Device, ScanJob
from app.scan_runner import JobContext, JobStopped, RunnerError
from app.scan_scope import PROFILES, ScanProfile
from app.worker import Worker

pytestmark = pytest.mark.usefixtures("job_env")

HOST = "10.77.0.10"
FINDING = {
    "template-id": "http-missing-security-headers", "matcher-name": "referrer-policy",
    "type": "http", "host": HOST, "port": "80", "scheme": "http",
    "url": f"http://{HOST}:80", "matched-at": f"http://{HOST}:80/",
    "timestamp": "2026-11-26T16:15:16-05:00",
    "info": {"name": "HTTP Missing Security Headers", "severity": "info",
             "tags": ["misconfig", "headers"], "description": "Header missing.\n",
             "classification": {"cve-id": None, "cwe-id": ["cwe-693"]}},
    "curl-command": "curl -H 'Authorization: Bearer SECRETTOKEN12345' http://x",
    "extracted-results": ["password=hunter2hunter2", "plain value"],
    "request": "GET / HTTP/1.1", "response": "HTTP/1.1 200",
}


@pytest.fixture
def env(tmp_path, monkeypatch):
    root = tmp_path / "templates"
    for rel in nuclei.SAFE_TEMPLATES[:6]:
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("id: test\n")
    versions = tmp_path / "versions.json"
    versions.write_text(json.dumps({"nuclei": "3.11.1", "templates": "10.5.2"}))
    fake = tmp_path / "nuclei"
    fake.write_text("#!/bin/sh\n")  # replaced per test via write_fake
    fake.chmod(0o755)
    marker = tmp_path / "ran.txt"
    monkeypatch.setattr(nuclei.settings, "nuclei_binary", str(fake))
    monkeypatch.setattr(nuclei.settings, "nuclei_templates_dir", str(root))
    monkeypatch.setattr(nuclei.settings, "nuclei_versions_file", str(versions))
    monkeypatch.setattr(nuclei.settings, "scan_vuln_profile_enabled", True)
    return dataclasses.make_dataclass("Env", ["root", "fake", "marker", "tmp"])(
        root, fake, marker, tmp_path)


def write_fake(env, body: str):
    env.fake.write_text("#!/bin/sh\n" + body)
    env.fake.chmod(env.fake.stat().st_mode | stat.S_IXUSR)


def lines(*objs, raw=()):
    return "".join(json.dumps(o) + "\n" for o in objs) + "".join(r + "\n" for r in raw)


def add_device(factory, ip=HOST, ports=((80, "open"),), proto="tcp"):
    did = str(uuid.uuid4())
    with factory() as db:
        db.add(Device(id=did, hostname=f"h-{did[:5]}", ip={"v": [ip]}, roles={"v": []},
                      ports={"v": [{"port": p, "proto": proto, "service": None, "state": st}
                                   for p, st in ports]}))
        db.commit()
    return did


def plan_for(factory, nets=("10.77.0.0/28",)):
    import ipaddress

    with factory() as db:
        return nuclei.build_plan(db, [ipaddress.ip_network(n) for n in nets])


def ctx_for(plan=None, approval=None, **kw):
    state = {"pid": None, "events": [], "progress": []}
    ctx = JobContext(
        job_id="j1", profile="vuln", targets=["10.77.0.0/28"], attempt=1,
        check=kw.pop("check", lambda: None),
        progress=lambda d, t: state["progress"].append((d, t)),
        event=lambda t, m: state["events"].append((t, m)),
        set_pid=lambda p: state.__setitem__("pid", p or state["pid"]),
        kind="scan", approval=approval or (plan or {}).get("approval_digest"))
    return ctx, state


# ------------------------------------------------------------- argv & plan ---

def test_argv_is_fixed_safe_and_uses_current_jsonl_flag(env):
    argv = nuclei.build_argv(str(env.tmp / "t.txt"), list(nuclei.SAFE_TEMPLATES[:2]), str(env.root))
    assert argv[0] == str(env.fake) and "-jsonl" in argv and "-json" not in argv
    for flag in ("-silent", "-duc", "-ni", "-no-stdin", "-omit-raw"):
        assert flag in argv
    assert argv[argv.index("-pt") + 1] == "http"
    assert set(argv[argv.index("-etags") + 1].split(",")) >= {"dos", "intrusive", "rce", "oast"}
    assert argv[argv.index("-rl") + 1] == str(nuclei.settings.nuclei_rate_limit)
    templates = [argv[i + 1] for i, a in enumerate(argv) if a == "-t"]
    assert templates and all(t.startswith(str(env.root) + os.sep) for t in templates)
    assert not any(any(c in a for c in ";|&$`\n") for a in argv)
    assert "-update-templates" not in argv and "-ut" not in argv


def test_unsupported_missing_and_symlinked_templates_are_excluded(env, tmp_path):
    rel = nuclei.SAFE_TEMPLATES[0]
    (env.root / rel).unlink()
    outside = tmp_path / "evil.yaml"
    outside.write_text("id: evil\n")
    (env.root / rel).symlink_to(outside)
    usable, excluded = nuclei.usable_templates()
    assert rel in excluded and rel not in usable
    assert set(nuclei.SAFE_TEMPLATES[6:]) <= set(excluded)  # never installed in this fixture
    assert len(usable) == 5


def test_plan_only_uses_known_open_http_ports_inside_authorized_networks(job_session_factory, env):
    add_device(job_session_factory, HOST, ports=((80, "open"), (22, "open"), (8080, "closed"),
                                                 (443, "open")))
    add_device(job_session_factory, "10.77.0.11", ports=((22, "open"),))      # no HTTP port
    add_device(job_session_factory, "10.99.1.1", ports=((80, "open"),))       # outside networks
    add_device(job_session_factory, "10.77.0.12", ports=((80, "open"),), proto="udp")
    plan = plan_for(job_session_factory)
    assert plan["urls"] == [f"http://{HOST}:80", f"https://{HOST}:443"]
    assert plan["versions"] == {"nuclei": "3.11.1", "templates": "10.5.2"}
    assert len(plan["approval_digest"]) == 64


def test_digest_changes_when_targets_or_templates_change(job_session_factory, env):
    did = add_device(job_session_factory)
    first = plan_for(job_session_factory)["approval_digest"]
    assert plan_for(job_session_factory)["approval_digest"] == first
    with job_session_factory() as db:
        dev = db.get(Device, did)
        dev.ports = {"v": [{"port": 80, "proto": "tcp", "state": "open", "service": None},
                           {"port": 8080, "proto": "tcp", "state": "open", "service": None}]}
        db.commit()
    second = plan_for(job_session_factory)["approval_digest"]
    assert second != first
    (env.root / nuclei.SAFE_TEMPLATES[0]).unlink()
    assert plan_for(job_session_factory)["approval_digest"] != second


# ----------------------------------------------------------------- parsing ---

def test_parse_keeps_findings_in_scope_and_strips_raw_material():
    huge = json.dumps({"template-id": "x", "matched-at": f"http://{HOST}/", "pad": "A" * 70000})
    text = lines(FINDING, {**FINDING, "matched-at": "http://203.0.113.9/", "host": "203.0.113.9"},
                 {**FINDING, "info": {**FINDING["info"], "severity": "catastrophic"}},
                 {"template-id": ""}, raw=["not json", huge, "[]"])
    found, counters = nuclei.parse_jsonl(text, {HOST})
    assert len(found) == 2 and counters["out_of_scope"] == 1 and counters["invalid"] == 4
    first = found[0]
    assert first["severity"] == "info" and found[1]["severity"] == "unknown"
    assert first["host"] == HOST and first["port"] == 80 and first["cwe"] == ["cwe-693"]
    blob = json.dumps(first)
    for leak in ("SECRETTOKEN", "hunter2", "curl", "GET /", "HTTP/1.1"):
        assert leak not in blob
    assert "plain value" in first["evidence"] and "password=[REDACTED]" in first["evidence"]
    assert "curl-command" not in first and "request" not in first


def test_parse_caps_findings(monkeypatch):
    monkeypatch.setattr(nuclei, "MAX_FINDINGS", 3)
    found, counters = nuclei.parse_jsonl(lines(*[FINDING] * 5), {HOST})
    assert len(found) == 3 and counters["dropped_over_limit"] == 2


# --------------------------------------------------------------- execution ---

def run(factory, ctx):
    return nuclei.run_nuclei(ctx, factory)


def test_run_executes_scanner_and_returns_sanitized_findings(job_session_factory, env):
    add_device(job_session_factory)
    write_fake(env, f"echo ran > {env.marker}\ncat <<'EOF'\n{json.dumps(FINDING)}\nEOF\n")
    plan = plan_for(job_session_factory)
    ctx, state = ctx_for(plan)
    result = run(job_session_factory, ctx)
    assert env.marker.exists() and result["probe"] == "nuclei"
    assert len(result["findings"]) == 1 and result["timed_out"] is False
    assert result["versions"]["templates"] == "10.5.2"
    assert result["approval_digest"] == plan["approval_digest"]
    assert "SECRETTOKEN" not in json.dumps(result)
    assert state["progress"][-1] == (1, 1)


def test_stale_or_missing_approval_never_executes(job_session_factory, env):
    add_device(job_session_factory)
    write_fake(env, f"echo ran > {env.marker}\n")
    plan = plan_for(job_session_factory)
    for approval in (None, "0" * 64):
        ctx, _ = ctx_for(plan, approval=approval)
        ctx = dataclasses.replace(ctx, approval=approval)
        with pytest.raises(RunnerError) as exc:
            run(job_session_factory, ctx)
        assert exc.value.code == "approval_stale" and not exc.value.retryable
    assert not env.marker.exists()


def test_profile_disabled_fails_closed_before_anything_runs(job_session_factory, env, monkeypatch):
    add_device(job_session_factory)
    write_fake(env, f"echo ran > {env.marker}\n")
    plan = plan_for(job_session_factory)
    monkeypatch.setattr(nuclei.settings, "scan_vuln_profile_enabled", False)
    with pytest.raises(RunnerError) as exc:
        run(job_session_factory, ctx_for(plan)[0])
    assert exc.value.code == "scope_rejected" and not env.marker.exists()


def test_no_known_http_services_means_nothing_is_scanned(job_session_factory, env):
    add_device(job_session_factory, ports=((22, "open"),))
    write_fake(env, f"echo ran > {env.marker}\n")
    plan = plan_for(job_session_factory)
    result = run(job_session_factory, ctx_for(plan)[0])
    assert result["findings"] == [] and "nothing was scanned" in result["note"]
    assert not env.marker.exists()


def test_out_of_scope_findings_from_the_scanner_are_discarded(job_session_factory, env):
    add_device(job_session_factory)
    evil = {**FINDING, "matched-at": "http://198.51.100.7/", "host": "198.51.100.7"}
    write_fake(env, f"cat <<'EOF'\n{json.dumps(evil)}\n{json.dumps(FINDING)}\nEOF\n")
    result = run(job_session_factory, ctx_for(plan_for(job_session_factory))[0])
    assert [f["host"] for f in result["findings"]] == [HOST]
    assert result["counters"]["out_of_scope"] == 1


def test_scanner_environment_has_no_application_secrets(job_session_factory, env, monkeypatch):
    add_device(job_session_factory)
    monkeypatch.setenv("CREDENTIAL_ENCRYPTION_KEY", "super-secret-value")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    write_fake(env, f"env > {env.tmp}/env.txt\n")
    run(job_session_factory, ctx_for(plan_for(job_session_factory))[0])
    seen = (env.tmp / "env.txt").read_text()
    assert "super-secret" not in seen and "sk-test" not in seen and "HOME=" in seen


def test_nonzero_exit_and_missing_binary_are_classified(job_session_factory, env):
    add_device(job_session_factory)
    plan = plan_for(job_session_factory)
    write_fake(env, "exit 3\n")
    with pytest.raises(RunnerError) as exc:
        run(job_session_factory, ctx_for(plan)[0])
    assert exc.value.code == "scanner_failed"
    env.fake.unlink()
    with pytest.raises(RunnerError) as exc:
        run(job_session_factory, ctx_for(plan)[0])
    assert exc.value.code == "scanner_missing"


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_cancel_kills_the_whole_process_group(job_session_factory, env):
    add_device(job_session_factory)
    child_pid_file = env.tmp / "child.pid"
    write_fake(env, f"sleep 300 &\necho $! > {child_pid_file}\nwait\n")
    plan = plan_for(job_session_factory)
    calls = {"n": 0}

    def check():
        calls["n"] += 1
        if calls["n"] >= 2 and child_pid_file.exists():
            raise JobStopped("cancel")

    ctx, state = ctx_for(plan, check=check)
    with pytest.raises(JobStopped):
        run(job_session_factory, ctx)
    child = int(child_pid_file.read_text())
    deadline = time.monotonic() + 5
    while alive(child) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not alive(state["pid"]) and not alive(child)


def test_deadline_kills_scanner_and_keeps_partial_findings(job_session_factory, env, monkeypatch):
    add_device(job_session_factory)
    short = dataclasses.replace(PROFILES[ScanProfile.VULN], timeout_seconds=1)
    monkeypatch.setattr(nuclei, "PROFILES", {**PROFILES, ScanProfile.VULN: short})
    write_fake(env, f"cat <<'EOF'\n{json.dumps(FINDING)}\nEOF\nsleep 300\n")
    result = run(job_session_factory, ctx_for(plan_for(job_session_factory))[0])
    assert result["timed_out"] is True and len(result["findings"]) == 1


def test_worker_dispatches_vuln_profile_to_nuclei_runner(job_session_factory, env):
    from app import jobs

    add_device(job_session_factory)
    write_fake(env, f"cat <<'EOF'\n{json.dumps(FINDING)}\nEOF\n")
    digest = plan_for(job_session_factory)["approval_digest"]
    with job_session_factory() as db:
        job = jobs.enqueue_scan(db, profile="vuln", targets=["10.77.0.0/28"], progress_total=14,
                                created_by="op", targets_extra={"approval": digest})
    worker = Worker(job_session_factory, "w")
    assert worker.run_next() == job.id
    with job_session_factory() as db:
        done = db.get(ScanJob, job.id)
        assert done.status == "succeeded" and done.result["probe"] == "nuclei"
        assert len(done.result["findings"]) == 1


# --------------------------------------------------------------------- API ---

def test_api_requires_opt_in_then_explicit_approval(client, job_session_factory, env, monkeypatch):
    from app.db import SessionLocal

    body = {"targets": ["10.77.0.0/28"], "profile": "vuln"}
    monkeypatch.setattr(nuclei.settings, "scan_vuln_profile_enabled", False)
    off = client.post("/api/v1/scans/preflight", json=body, headers=client.csrf_headers)
    assert off.status_code == 403 and off.json()["detail"]["code"] == "profile_disabled"
    profiles = {p["name"]: p for p in client.get("/api/v1/scans/scope").json()["profiles"]}
    assert profiles["vuln"]["enabled"] is False and profiles["vuln"]["intrusive"] is True

    monkeypatch.setattr(nuclei.settings, "scan_vuln_profile_enabled", True)
    with SessionLocal() as db:
        did = str(uuid.uuid4())
        db.add(Device(id=did, hostname="lab", ip={"v": ["10.77.0.5"]}, roles={"v": []},
                      ports={"v": [{"port": 80, "proto": "tcp", "state": "open",
                                    "service": None}]}))
        db.commit()
    try:
        pre = client.post("/api/v1/scans/preflight", json=body, headers=client.csrf_headers)
        assert pre.status_code == 200, pre.text
        plan = pre.json()["plan"]
        assert plan["urls"] == ["http://10.77.0.5:80"] and plan["approval_digest"]
        jobs_url = "/api/v1/scans/jobs"
        none = client.post(jobs_url, json=body, headers=client.csrf_headers)
        assert none.status_code == 409 and none.json()["detail"]["code"] == "approval_required"
        wrong = client.post(jobs_url, json={**body, "approval_digest": "0" * 64},
                            headers=client.csrf_headers)
        assert wrong.status_code == 409 and wrong.json()["detail"]["code"] == "approval_mismatch"
        ok = client.post(jobs_url, json={**body, "approval_digest": plan["approval_digest"]},
                         headers=client.csrf_headers)
        assert ok.status_code == 202, ok.text
        assert "approval" not in json.dumps(ok.json())
    finally:
        with SessionLocal() as db:
            db.query(ScanJob).delete()
            db.query(Device).filter_by(id=did).delete()
            db.commit()


def test_vuln_is_not_reachable_through_the_nmap_runner(job_session_factory, env):
    from app.scan_runner import run_scan

    ctx, _ = ctx_for()
    with pytest.raises(RunnerError) as exc:
        run_scan(ctx)
    assert exc.value.code == "invalid_profile"


def test_public_targets_are_rejected_for_vuln_profile(client, monkeypatch):
    monkeypatch.setattr(nuclei.settings, "scan_vuln_profile_enabled", True)
    r = client.post("/api/v1/scans/preflight", json={"targets": ["8.8.8.8"], "profile": "vuln"},
                    headers=client.csrf_headers)
    assert r.status_code in (403, 422)


@pytest.mark.skipif(not os.environ.get("NUCLEI_BIN") or not os.environ.get("NUCLEI_TEMPLATES"),
                    reason="set NUCLEI_BIN and NUCLEI_TEMPLATES to run against a real Nuclei")
def test_real_nuclei_against_loopback_lab_service(tmp_path, monkeypatch):
    """Integration check of our argv and parser against the real, pinned Nuclei binary.

    The lab service is a throwaway loopback HTTP server started here; nothing else is probed.
    """
    import functools
    import http.server
    import subprocess
    import threading

    www = tmp_path / "www"
    www.mkdir()
    (www / "index.html").write_text("<html><title>lab</title></html>")
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(www))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    monkeypatch.setattr(nuclei.settings, "nuclei_binary", os.environ["NUCLEI_BIN"])
    root = os.environ["NUCLEI_TEMPLATES"]
    usable, _ = nuclei.usable_templates(__import__("pathlib").Path(root))
    assert "http/misconfiguration/http-missing-security-headers.yaml" in usable
    targets = tmp_path / "targets.txt"
    targets.write_text(f"http://127.0.0.1:{port}\n")
    argv = nuclei.build_argv(str(targets), usable, root)
    env = {**nuclei._scanner_env(), "HOME": str(tmp_path), "XDG_CONFIG_HOME": str(tmp_path),
           "XDG_CACHE_HOME": str(tmp_path)}
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=240, env=env,  # noqa: S603
                              stdin=subprocess.DEVNULL, cwd=str(tmp_path), check=False)
    finally:
        server.shutdown()
    assert done.returncode == 0, done.stderr[-500:]
    findings, counters = nuclei.parse_jsonl(done.stdout, {"127.0.0.1"})
    assert findings and counters["invalid"] == 0 and counters["out_of_scope"] == 0
    ids = {f["template_id"] for f in findings}
    assert "http-missing-security-headers" in ids
    assert all(f["host"] == "127.0.0.1" and f["port"] == port for f in findings)
    assert "curl" not in json.dumps(findings)
