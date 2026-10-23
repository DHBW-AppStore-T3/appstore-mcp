"""Scrub secrets out of anything the server returns (logs, events, status messages)."""

from __future__ import annotations

import logging
import re
from typing import Any

MASK = "[REDACTED]"

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), MASK),
    # GitHub tokens, our own tokens, JWTs, Slack, AWS access keys
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), MASK),
    (re.compile(r"\b(?:asmcp|asa)_[A-Za-z0-9_\-=]{16,}"), MASK),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"), MASK),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), MASK),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), MASK),
    # Authorization headers / bearer tokens
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/\-]{8,}=*"), r"\1 " + MASK),
    # user:password@host in URLs (postgresql://, amqp://, https://)
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+):[^\s@/]+@"), r"\1:" + MASK + "@"),
    # key=value / key: value / "key": "value" for secret-looking keys
    (
        re.compile(
            r"""(?ix)
            (["']?[\w.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|private[_\-]?key|
            credential|authorization|encryption[_\-]?key|signing[_\-]?key)[\w.\-]*["']?\s*[=:]\s*)
            ("[^"]*"|'[^']*'|[^\s,;&"']+)"""
        ),
        r"\1" + MASK,
    ),
    # Fernet / urlsafe-base64 32-byte keys
    (re.compile(r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{43}=(?![A-Za-z0-9_\-=])"), MASK),
]


def redact(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_obj(value: Any) -> Any:
    """Redact every string in a JSON-like structure."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: redact_obj(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact_obj(v) for v in value]
    return value


class RedactingFilter(logging.Filter):
    """Logging filter: nothing secret reaches our own logs either."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = ()
        return True
