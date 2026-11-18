"""Unit tests for Weber MCP SSRF, DNS-rebinding, URL validation, and rate limiting."""

import socket

import pytest

from weber_mcp.security import RateLimiter, SecurityError, verify_url_safety


@pytest.mark.parametrize(
    "blocked_url",
    [
        "http://127.0.0.1:8080",
        "http://localhost/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://[::1]/",
        "file:///C:/Windows/System32/drivers/etc/hosts",
        "javascript:alert(1)",
        "http://user:pass@example.com",
        "https://example.com/malware.exe",
        "data:text/html,<script>alert(1)</script>",
        "ftp://example.com/file.txt",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://service.internal/secret",
        "http://100.64.0.1/",
        "http://[::ffff:127.0.0.1]/",
        "http://0x7f000001/",
        "http://2130706433/",
        "http://0177.0.0.1/",
        "https://example.com/archive.zip",
    ],
)
def test_dangerous_and_ssrf_urls_blocked(blocked_url: str) -> None:
    verdict = verify_url_safety(blocked_url, resolve_dns=False)
    assert verdict.allowed is False, f"Expected {blocked_url} to be blocked, got: {verdict}"


def test_public_url_allowed() -> None:
    verdict = verify_url_safety("https://example.com", resolve_dns=True)
    assert verdict.allowed is True
    assert verdict.normalized_url.startswith("https://example.com")
    assert len(verdict.resolved_ips) >= 1


def test_dns_rebinding_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host: str, port: int, proto: int = 0):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    verdict = verify_url_safety("https://rebind-attacker.example.com", resolve_dns=True)
    assert verdict.allowed is False
    assert "rebinding" in verdict.reason.lower() or "loopback" in verdict.reason.lower()


def test_rate_limiter() -> None:
    limiter = RateLimiter(max_requests=2, window_seconds=60.0)
    limiter.check_or_raise("test")
    limiter.check_or_raise("test")
    assert limiter.remaining() == 0
    with pytest.raises(SecurityError):
        limiter.check_or_raise("test")
    limiter.reset()
    assert limiter.remaining() == 2
