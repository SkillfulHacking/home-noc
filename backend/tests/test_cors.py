# backend/tests/test_cors.py
from __future__ import annotations


def test_no_cors_headers_without_configured_origins(client):
    """Default/production config (no CORS_ORIGINS) must not echo a cross-origin
    Access-Control-Allow-Origin header. The app and frontend are served
    through the same Nginx origin (see frontend/nginx.conf), so no
    cross-origin access should be granted."""
    r = client.get("/health", headers={"Origin": "http://evil.example.com"})
    assert r.status_code == 200
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}


def test_preflight_not_handled_without_configured_origins(client):
    """Without CORS enabled there is no CORS middleware to answer an OPTIONS
    preflight, matching the single-origin deployment where browsers never
    need to send one."""
    r = client.options(
        "/api/v1/devices",
        headers={
            "Origin": "http://evil.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}
