"""M10 container privilege and scanner deployment assertions."""
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "docker-compose.yml"


def _service_block(text: str, name: str, next_name: str) -> str:
    return text.split(f"  {name}:\n", 1)[1].split(f"  {next_name}:\n", 1)[0]


def test_only_worker_gets_narrow_ping_socket_sysctl_and_no_net_raw():
    text = COMPOSE.read_text()
    backend = _service_block(text, "backend", "worker")
    worker = _service_block(text, "worker", "frontend")

    assert 'user: "10001:10001"' in worker
    assert 'net.ipv4.ping_group_range: "10001 10001"' in worker
    assert "cap_drop:\n      - ALL" in worker
    assert "no-new-privileges:true" in worker
    assert "cap_add:\n      - NET_RAW" not in worker
    assert "ping_group_range" not in backend
    assert "privileged:" not in text and "network_mode: host" not in text
