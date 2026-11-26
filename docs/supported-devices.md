# Supported sources and deliberate limitations (0.1.0-beta.1)

| Source | What it provides | Requirements | Verified how |
|---|---|---|---|
| ICMP discovery | host liveness, `last_seen`, health evidence | private ranges in scope; Linux ping sockets (set by Compose) | automated (fixtures), not on a real LAN |
| TCP connect scan | open ports on known/discovered hosts | `ports` profile | automated (fixtures + real socket tests) |
| SNMPv3 (authPriv) | sysName/sysDescr/sysObjectID/uptime/engine ID, interfaces (physical ports, status, MACs), switch/router role hints | SNMPv3 user with auth **and** privacy, UDP/161 reachable, read view for IF-MIB/system/bridge | automated: fake transport and a real pysnmp loopback agent; **no real switch yet** |
| UniFi Network 9+ | managed devices (id, MAC, IP, model, state, role hint) and connected clients | Integration API token (view-only), `https://<IPv4>` controller | automated with a mocked controller; **no real UDM yet** |
| Nuclei (opt-in) | exposure/misconfiguration findings on known HTTP services | `SCAN_VULN_PROFILE_ENABLED`, approved plan | real pinned binary vs loopback lab service |

Deliberately not supported in the MVP: IPv6 discovery, SNMPv1/v2c, LLDP/CDP topology, mDNS, other vendor APIs (Synology, MikroTik, Omada), notification delivery, scheduled vulnerability scans, aggressive/intrusive checks, hostnames as scan targets, multi-user accounts. These are tracked as fast-follow issues (#32–#47, #69).

Unknown identity fields stay unknown (the system never invents a vendor, model or serial). Service names on ports are labelled *reported*, *conventional (not verified)* or unknown.
