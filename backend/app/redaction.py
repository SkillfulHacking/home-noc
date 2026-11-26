"""Redaction of secrets from scanner/finding text before it is stored or returned."""
from __future__ import annotations

import re

REDACTED = "[REDACTED]"
_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
               re.S),
    re.compile(r"(?i)\b(authorization|proxy-authorization)\b\s*[:=]\s*[^\r\n]+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
               r"client[_-]?secret|auth)\b(\s*[:=]\s*|\"\s*:\s*\")[^\s\"'&,;]+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),  # JWT
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),                                      # AWS key id
    re.compile(r"\b[A-Fa-f0-9]{40,}\b"),                                             # long hex
    re.compile(r"(?i)\b(?:set-cookie|cookie)\b\s*:\s*[^\r\n]+"),
    re.compile(r"://[^/\s:@]+:[^/\s@]+@"),                                           # url creds
]
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def redact(text: str) -> str:
    """Remove credential-shaped substrings; the key names stay so findings stay readable."""
    for pattern in _PATTERNS:
        text = pattern.sub(_replace, text)
    return text


def _replace(match: re.Match) -> str:
    whole = match.group(0)
    if whole.startswith("://"):
        return "://" + REDACTED + "@"
    head = re.match(r"(?i)^[A-Za-z_-]+(\s*[:=]\s*|\"\s*:\s*\")", whole)
    return (head.group(0) if head else "") + REDACTED


def clean(text: object, limit: int) -> str | None:
    """Bounded, control-character-free, redacted single value (None when empty)."""
    if not isinstance(text, str):
        return None
    cleaned = redact(_CONTROL.sub("", text)).strip()
    return cleaned[:limit] or None
