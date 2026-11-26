"""M15 interface normalization, bounds and role derivation (fixture tables)."""
from __future__ import annotations

import asyncio

from pydantic import SecretStr

from app.connectors.snmp import MISSING, SnmpTarget, UsmCredentials
from app.connectors.snmp_interfaces import (
    IF_COLUMNS as C,
)
from app.connectors.snmp_interfaces import (
    MAX_INTERFACES,
    collect_interfaces,
    derive_roles,
    normalize_interfaces,
)


def target():
    return SnmpTarget("192.0.2.1", UsmCredentials(
        "u", "SHA256", SecretStr("authpass-1234"), "AES128", SecretStr("privpass-1234")))


class Table:
    def __init__(self, tables):
        self.tables, self.walks = tables, []

    async def walk(self, target, oid, *, max_rows, deadline):
        self.walks.append((oid, max_rows, deadline))
        return list(self.tables.get(oid, []))[:max_rows]


def col(prefix, mapping):
    return [(f"{prefix}.{i}", v) for i, v in mapping.items()]


def run(c):
    return asyncio.run(c)


SWITCH_FACTS = {"sys_services": 6, "ip_forwarding": 2, "bridge_address": "00:11:22:33:44:55"}


def test_switch_ports_captured_with_status_and_macs():
    t = Table({
        C["name"]: col(C["name"], {1: b"Port 1", 2: b"Port 2", 3: b"Port 3"}),
        C["descr"]: col(C["descr"], {1: b"eth1", 2: b"eth2", 3: b"eth3"}),
        C["type"]: col(C["type"], {1: 6, 2: 6, 3: 6}),
        C["oper_status"]: col(C["oper_status"], {1: 1, 2: 2, 3: 99}),
        C["phys_address"]: col(
            C["phys_address"], {1: b"\x00\x01\x02\x03\x04\x01", 2: b"", 3: b"\x00" * 6}),
    })
    out = run(collect_interfaces(t, target(), SWITCH_FACTS))
    names = [(i["name"], i["oper_status"], i["mac"]) for i in out["interfaces"]]
    assert names == [("Port 1", "up", "00:01:02:03:04:01"), ("Port 2", "down", None),
                     ("Port 3", None, None)]
    assert out["roles"] == ["switch"] and out["truncated"] is False


def test_non_physical_weird_and_empty_rows_ignored():
    t = Table({
        C["name"]: col(C["name"], {1: b"eth0", 2: b"lo", 3: b"", 4: b"\x00\x01"}),
        C["type"]: col(C["type"], {1: 6, 2: 24, 3: 6, 4: 6, 5: 6}),
        C["descr"]: col(C["descr"], {3: b"   "}),
    })
    t.tables[C["name"]] += [(f"{C['name']}.abc", b"bad"), (f"{C['name']}.0", b"zero"),
                            ("1.3.6.1.9.9.9.7", b"foreign")]
    out = run(collect_interfaces(t, target(), {}))
    assert [i["name"] for i in out["interfaces"]] == ["eth0"]
    assert out["ignored"] == 4  # lo (non physical), blank, control-chars, descr-less idx5


def test_missing_markers_and_bad_types_never_become_values():
    rows, ignored = normalize_interfaces({"type": {1: MISSING, 2: "6", 3: True},
                                          "name": {1: b"a", 2: b"b", 3: b"c"}})
    assert rows == [] and ignored == 3


def test_row_cap_and_truncation_flag():
    n = MAX_INTERFACES + 50
    t = Table({
        C["name"]: col(C["name"], {i: f"p{i}".encode() for i in range(1, n + 1)}),
        C["type"]: col(C["type"], {i: 6 for i in range(1, n + 1)}),
    })
    out = run(collect_interfaces(t, target(), {}))
    assert len(out["interfaces"]) == MAX_INTERFACES and out["truncated"] is True
    assert all(w[1] == MAX_INTERFACES + 1 for w in t.walks)


def test_only_allowlisted_columns_are_walked_with_a_deadline():
    t = Table({})
    run(collect_interfaces(t, target(), {}))
    assert {w[0] for w in t.walks} == set(C.values())
    assert all(0 < w[2] <= 20 for w in t.walks)


def test_roles_from_standard_mib_semantics_only():
    assert derive_roles(SWITCH_FACTS, 24) == ["switch"]
    router = {"sys_services": 78, "ip_forwarding": 1, "bridge_address": None}
    assert derive_roles(router, 4) == ["router"]
    both = {"sys_services": 78, "ip_forwarding": 1, "bridge_address": "00:11:22:33:44:55"}
    assert derive_roles(both, 8) == ["switch", "router"]
    assert derive_roles(SWITCH_FACTS, 1) == []          # too little evidence
    assert derive_roles({"sys_services": None}, 10) == []
    assert derive_roles({"sys_services": 72, "ip_forwarding": 2}, 5) == []  # host, not router
