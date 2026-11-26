"""M18 findings: dedupe, lifecycle, audit trail, redaction, API."""
from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import select

from app.findings import persist_nuclei_result
from app.models import Device, Event, Finding, FindingEvent

HOST = "10.77.0.10"
TPL = "http/misconfiguration/http-missing-security-headers.yaml"


def finding(**kw):
    base = {"template_id": "http-missing-security-headers", "name": "Missing headers",
            "severity": "medium", "host": HOST, "port": 80, "scheme": "http", "path": "/",
            "matcher_name": "referrer-policy", "description": "d", "tags": ["misconfig"],
            "cve": [], "cwe": ["cwe-693"], "evidence": [], "type": "http"}
    return {**base, **kw}


def result(*findings, complete=True, templates=(TPL,), urls=(f"http://{HOST}:80",)):
    return {"probe": "nuclei", "versions": {"nuclei": "3.11.1", "templates": "10.5.2"},
            "templates": list(templates), "urls": list(urls), "findings": list(findings),
            "counters": {}, "timed_out": not complete}


@pytest.fixture
def db():
    from app.db import Base, SessionLocal, engine

    Base.metadata.create_all(bind=engine)
    s = SessionLocal()

    def wipe():
        for model in (FindingEvent, Finding, Event, Device):
            s.query(model).delete()
        s.commit()

    wipe()
    did = str(uuid.uuid4())
    s.add(Device(id=did, hostname="lab", ip={"v": [HOST]}, roles={"v": []}, ports={"v": []}))
    s.commit()
    s.did = did
    yield s
    wipe()
    s.close()


def run(db, res, job="j1"):
    persist_nuclei_result(db, job, res)
    db.commit()
    return res["finding_persistence"]


def rows(db):
    return list(db.scalars(select(Finding)))


def trail(db, f):
    return [e.type for e in db.scalars(select(FindingEvent).where(FindingEvent.finding_id == f.id)
                                       .order_by(FindingEvent.at, FindingEvent.id))]


def test_new_finding_captures_template_versions_and_timestamps(db):
    summary = run(db, result(finding()))
    assert summary["created"] == 1
    (f,) = rows(db)
    assert f.device_id == db.did and f.status == "open" and f.severity == "medium"
    assert f.template_version == "10.5.2" and f.scanner_version == "3.11.1"
    assert f.first_seen == f.last_seen and f.occurrences == 1 and f.last_job_id == "j1"
    assert trail(db, f) == ["opened"]


def test_identical_repeat_updates_one_finding(db):
    run(db, result(finding()), "j1")
    first = rows(db)[0].first_seen
    summary = run(db, result(finding()), "j2")
    (f,) = rows(db)
    assert summary == {**summary, "created": 0, "updated": 1}
    assert f.occurrences == 2 and f.first_seen == first and f.last_seen >= first
    assert f.last_job_id == "j2" and trail(db, f) == ["opened", "seen"]


def test_distinct_matcher_or_port_is_a_distinct_finding(db):
    run(db, result(finding(), finding(matcher_name="x-frame-options"), finding(port=443)))
    assert len(rows(db)) == 3


def test_resolved_after_complete_rerun_and_reopened_when_back(db):
    run(db, result(finding()), "j1")
    summary = run(db, result(), "j2")  # complete run, template covered, nothing reported
    (f,) = rows(db)
    assert summary["resolved"] == 1 and f.status == "resolved" and f.resolved_at
    summary = run(db, result(finding()), "j3")
    f = rows(db)[0]
    assert summary["reopened"] == 1 and f.status == "open" and f.resolved_at is None
    assert trail(db, f) == ["opened", "resolved", "reopened"]


def test_incomplete_or_uncovering_runs_never_resolve(db):
    run(db, result(finding()), "j1")
    assert run(db, result(complete=False), "j2")["resolved"] == 0           # timed out
    assert run(db, result(templates=("http/technologies/tech-detect.yaml",)), "j3")["resolved"] == 0
    assert run(db, result(urls=("http://10.77.0.99:80",)), "j4")["resolved"] == 0  # not scanned
    assert rows(db)[0].status == "open"


def test_suppression_is_sticky_across_reruns_and_audited(db):
    from app.findings import set_suppressed

    run(db, result(finding()), "j1")
    (f,) = rows(db)
    set_suppressed(db, f, True, "alice", "accepted risk: lab only")
    db.commit()
    run(db, result(finding()), "j2")
    run(db, result(), "j3")  # also not resolved while suppressed
    f = rows(db)[0]
    assert f.status == "suppressed" and f.occurrences == 2 and f.suppressed_reason
    set_suppressed(db, f, False, "alice")
    db.commit()
    assert rows(db)[0].status == "open"
    assert trail(db, rows(db)[0]) == ["opened", "suppressed", "seen", "unsuppressed"]


def test_unmatched_and_ambiguous_hosts_are_not_persisted(db):
    db.add(Device(id=str(uuid.uuid4()), hostname="dup", ip={"v": [HOST]}, roles={"v": []},
                  ports={"v": []}))
    db.commit()
    summary = run(db, result(finding(), finding(host="10.77.0.200")))
    assert summary["unmatched"] == 2 and rows(db) == []


def test_non_nuclei_results_are_ignored(db):
    res = {"probe": "icmp_echo", "findings": [finding()]}
    persist_nuclei_result(db, "j", res)
    assert rows(db) == [] and "finding_persistence" not in res


def test_secrets_are_redacted_even_if_the_scanner_parser_missed_them(db):
    run(db, result(finding(description="token=abcd1234efgh5678 leaked",
                           evidence=["Authorization: Bearer SECRETVALUE12345", "ok"])))
    blob = json.dumps(rows(db)[0].details)
    assert "abcd1234efgh5678" not in blob and "SECRETVALUE" not in blob and "ok" in blob


def test_medium_and_above_open_one_event_lows_do_not(db):
    run(db, result(finding(), finding(template_id="low-one", severity="low", port=8080),
                   finding(template_id="crit", severity="critical", port=8443)))
    run(db, result(finding(), finding(template_id="crit", severity="critical", port=8443)), "j2")
    evs = list(db.scalars(select(Event).where(Event.type == "finding_opened")))
    assert sorted(e.details["finding_severity"] for e in evs) == ["critical", "medium"]
    assert {e.severity for e in evs} == {"warning", "critical"}


# --------------------------------------------------------------------- API ---

URL = "/api/v1/findings"


def test_api_requires_session(anon_client):
    assert anon_client.get(URL).status_code in (401, 403)


def test_api_filters_detail_and_suppress(client, db):
    run(db, result(finding(), finding(template_id="crit", severity="critical", port=8443,
                                      name="Critical thing")))
    body = client.get(URL).json()
    assert body["total"] == 2 and body["by_status"]["open"] == 2
    assert body["findings"][0]["severity"] == "critical"  # most severe first
    assert client.get(URL + "?severity=medium").json()["total"] == 1
    assert client.get(URL + f"?device_id={db.did}").json()["total"] == 2
    assert client.get(URL + "?device_id=other").json()["total"] == 0
    assert client.get(URL + "?q=critical").json()["total"] == 1
    assert client.get(URL + "?q=%25").json()["total"] == 0
    assert client.get(URL + "?status=bogus").status_code == 422
    assert client.get(URL + "?limit=1&offset=1").json()["findings"][0]["severity"] == "medium"
    fid = body["findings"][1]["id"]
    detail = client.get(f"{URL}/{fid}").json()
    assert detail["history"][0]["type"] == "opened" and detail["details"]["cwe"] == ["cwe-693"]
    for forbidden in ("request", "response", "curl", "raw"):
        assert forbidden not in json.dumps(detail).lower().replace("description", "")
    assert client.post(f"{URL}/{fid}/suppress", json={"reason": "lab only"}).status_code == 403
    assert client.post(f"{URL}/{fid}/suppress", json={"reason": "x"},
                       headers=client.csrf_headers).status_code == 422
    sup = client.post(f"{URL}/{fid}/suppress", json={"reason": "lab only"},
                      headers=client.csrf_headers).json()
    assert sup["status"] == "suppressed" and sup["suppressed_reason"] == "lab only"
    assert client.get(URL + "?status=suppressed").json()["total"] == 1
    back = client.post(f"{URL}/{fid}/unsuppress", headers=client.csrf_headers).json()
    assert back["status"] == "open"
    assert client.get(f"{URL}/nope").status_code == 404
