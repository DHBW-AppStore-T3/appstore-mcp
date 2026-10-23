import logging

import pytest

from appstore_mcp.redact import RedactingFilter, redact, redact_obj


@pytest.mark.parametrize("secret", [
    "ghp_" + "a" * 36,
    "github_pat_" + "A1" * 20,
    "asmcp_" + "x" * 40,
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_nature-123",
    "AKIAABCDEFGHIJKLMNOP",
])
def test_tokens_are_masked(secret):
    assert secret not in redact(f"call failed with {secret} in header")


@pytest.mark.parametrize("line", [
    "password=hunter2", "PASSWORD: hunter2", '"client_secret": "hunter2"', "api_key = hunter2",
    "Authorization: Bearer hunter2hunter2", "TOKEN=hunter2;",
])
def test_key_value_secrets_are_masked(line):
    assert "hunter2" not in redact(line)


def test_url_credentials_and_fernet_keys():
    out = redact("dsn postgresql://appstore_t3:s3cr3tpw@postgres:5432/db key Q1PNlFd4It9oQPtjCcXcmB7wGDkY4w8KwpIRNSF4u7U=")
    assert "s3cr3tpw" not in out and "Q1PNlFd4" not in out and "postgres:5432/db" in out


def test_ordinary_text_is_kept():
    text = "2026-01-01T00:00:00Z INFO GET /api/health 200 in 3ms digest sha256:" + "a" * 64
    assert redact(text) == text


def test_private_key_block():
    assert "MIIE" not in redact("-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----")


def test_redact_obj_walks_structures():
    assert redact_obj({"a": ["password=x1"], "b": 3}) == {"a": ["password=" + "[REDACTED]"], "b": 3}


def test_logging_filter(caplog):
    logger = logging.getLogger("t")
    logger.addFilter(RedactingFilter())
    with caplog.at_level(logging.INFO):
        logger.info("login with %s", "token=abc123def")
    assert "abc123def" not in caplog.text
