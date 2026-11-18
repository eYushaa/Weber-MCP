"""Multi-layer network, SSRF, DNS-rebinding, and rate-limiting security engine for Weber MCP."""

from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048

ALLOWED_SCHEMES = frozenset({"http", "https"})

EXPLICITLY_BLOCKED_SCHEMES = frozenset({
    "file",
    "javascript",
    "data",
    "vbscript",
    "ftp",
    "ftps",
    "gopher",
    "ws",
    "wss",
    "chrome",
    "chrome-extension",
    "about",
    "blob",
    "mailto",
    "tel",
    "ssh",
    "smb",
    "ldap",
    "ldaps",
})

DANGEROUS_EXTENSIONS = frozenset({
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".scr",
    ".dll",
    ".sys",
    ".com",
    ".pif",
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".iso",
    ".img",
    ".dmg",
    ".apk",
    ".jar",
    ".bin",
})

BLOCKED_EXACT_HOSTNAMES = frozenset({
    "localhost",
    "broadcasthost",
    "local",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "host.docker.internal",
    "kubernetes.default",
    "kubernetes.default.svc",
})

BLOCKED_HOSTNAME_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".corp",
    ".home",
    ".lan",
    ".localdomain",
)

_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_HEX_OR_INT_HOST_RE = re.compile(r"^(?:0x[0-9a-f]+|\d+)$", re.IGNORECASE)
_OBFUSCATED_IPV4_PART_RE = re.compile(r"^(?:0x[0-9a-f]+|0[0-7]+|\d+)$", re.IGNORECASE)


class SecurityError(Exception):
    """Raised when a URL, network request, or rate limit violates security policy."""

    def __init__(self, message: str, verdict: SecurityVerdict | None = None) -> None:
        super().__init__(message)
        self.verdict = verdict


@dataclass
class SecurityVerdict:
    """Result of validating a URL or IP against Weber MCP security rules."""

    allowed: bool
    url: str
    normalized_url: str
    reason: str
    resolved_ips: list[str] = field(default_factory=list)
    risk_level: str = "low"  # low, medium, high, critical


def _extract_hostname(raw_url: str) -> str:
    """Return lowercase hostname without brackets or trailing dots."""
    parsed = urlsplit(raw_url)
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    return host


def _is_obfuscated_ip_hostname(hostname: str) -> bool:
    """Detect integer, hex, or octal IP obfuscations such as 0x7f000001, 2130706433, 0177.0.0.1."""
    if not hostname:
        return False

    # Pure integer or hex single-label host (e.g., 2130706433 or 0x7f000001)
    if _HEX_OR_INT_HOST_RE.match(hostname):
        return True

    # Dotted notation where every segment looks numeric/hex/octal and at least one
    # segment uses 0x hex or leading-zero octal (e.g., 0177.0.0.1, 0x7f.0.0.1),
    # or has fewer than 4 numeric parts (e.g., 127.1).
    parts = hostname.split(".")
    if 1 < len(parts) <= 4 and all(_OBFUSCATED_IPV4_PART_RE.match(p) for p in parts):
        if len(parts) < 4:
            return True
        for part in parts:
            if part.lower().startswith("0x") or (len(part) > 1 and part.startswith("0")):
                return True

    return False


def validate_url_syntax(url: str) -> SecurityVerdict:
    """Validate URL syntax, scheme, length, credentials, and dangerous file extensions."""
    if not isinstance(url, str):
        return SecurityVerdict(
            allowed=False,
            url=str(url),
            normalized_url="",
            reason="URL must be a string.",
            risk_level="high",
        )

    stripped = url.strip()
    if not stripped:
        return SecurityVerdict(
            allowed=False,
            url=url,
            normalized_url="",
            reason="URL cannot be empty.",
            risk_level="medium",
        )

    if len(stripped) > MAX_URL_LENGTH:
        return SecurityVerdict(
            allowed=False,
            url=stripped[:120] + "...",
            normalized_url="",
            reason=f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters.",
            risk_level="high",
        )

    if _CONTROL_CHAR_RE.search(stripped):
        return SecurityVerdict(
            allowed=False,
            url=stripped,
            normalized_url="",
            reason="URL contains forbidden control characters or null bytes.",
            risk_level="critical",
        )

    try:
        parsed = urlsplit(stripped)
    except ValueError as exc:
        return SecurityVerdict(
            allowed=False,
            url=stripped,
            normalized_url="",
            reason=f"Malformed URL syntax: {exc}",
            risk_level="high",
        )

    scheme = parsed.scheme.lower()
    if scheme in EXPLICITLY_BLOCKED_SCHEMES or scheme not in ALLOWED_SCHEMES:
        return SecurityVerdict(
            allowed=False,
            url=stripped,
            normalized_url="",
            reason=f"Blocked or unsupported URL scheme '{scheme or 'none'}'. Only http and https are allowed.",
            risk_level="critical",
        )

    if parsed.username is not None or parsed.password is not None:
        return SecurityVerdict(
            allowed=False,
            url=stripped,
            normalized_url="",
            reason="Embedded credentials (username/password) in URL are forbidden.",
            risk_level="critical",
        )

    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        return SecurityVerdict(
            allowed=False,
            url=stripped,
            normalized_url="",
            reason="URL does not contain a valid hostname.",
            risk_level="high",
        )

    try:
        port = parsed.port
        if port is not None and not (1 <= port <= 65535):
            return SecurityVerdict(
                allowed=False,
                url=stripped,
                normalized_url="",
                reason=f"Invalid port number: {port}.",
                risk_level="high",
            )
    except ValueError as exc:
        return SecurityVerdict(
            allowed=False,
            url=stripped,
            normalized_url="",
            reason=f"Invalid port in URL: {exc}",
            risk_level="high",
        )

    # Check dangerous executable or archive file extensions in path
    path_lower = PurePosixPath(parsed.path or "").suffix.lower()
    if path_lower in DANGEROUS_EXTENSIONS:
        return SecurityVerdict(
            allowed=False,
            url=stripped,
            normalized_url="",
            reason=f"Blocked dangerous file extension '{path_lower}' in URL path.",
            risk_level="high",
        )

    normalized = urlunsplit((scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    return SecurityVerdict(
        allowed=True,
        url=stripped,
        normalized_url=normalized,
        reason="URL syntax passed validation.",
        risk_level="low",
    )


def is_ip_safe(ip_str: str) -> tuple[bool, str]:
    """Validate that an IP address is strictly public and routable (no loopback/private/metadata/CGNAT)."""
    if not ip_str or "%" in ip_str:
        return False, f"Blocked IP address with empty value or zone identifier: '{ip_str}'."

    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False, f"Invalid IP address format: '{ip_str}'."

    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            mapped_safe, mapped_reason = is_ip_safe(str(ip.ipv4_mapped))
            if not mapped_safe:
                return False, f"IPv4-mapped IPv6 address blocked ({mapped_reason})"
        if ip.sixtofour is not None:
            stf_safe, stf_reason = is_ip_safe(str(ip.sixtofour))
            if not stf_safe:
                return False, f"6to4 IPv6 address blocked ({stf_reason})"

    if ip.is_loopback:
        return False, f"Loopback IP address blocked: {ip}"
    if ip.is_private:
        return False, f"Private/internal IP address blocked: {ip}"
    if ip.is_link_local:
        return False, f"Link-local/cloud metadata IP address blocked: {ip}"
    if ip.is_multicast:
        return False, f"Multicast IP address blocked: {ip}"
    if ip.is_reserved:
        return False, f"Reserved IP address blocked: {ip}"
    if ip.is_unspecified:
        return False, f"Unspecified IP address blocked: {ip}"
    if isinstance(ip, ipaddress.IPv4Address):
        if ip in _CGNAT_NETWORK:
            return False, f"Carrier-Grade NAT IP address (100.64.0.0/10) blocked: {ip}"
        if ip in _THIS_NETWORK:
            return False, f"Zero/this-network IP address (0.0.0.0/8) blocked: {ip}"

    return True, f"Public IP {ip} verified safe."


def verify_url_safety(url: str, resolve_dns: bool = True) -> SecurityVerdict:
    """Run full SSRF, hostname, obfuscation, and DNS-resolution safety checks on a URL."""
    syntax_verdict = validate_url_syntax(url)
    if not syntax_verdict.allowed:
        return syntax_verdict

    parsed = urlsplit(syntax_verdict.normalized_url)
    hostname = _extract_hostname(syntax_verdict.normalized_url)

    if hostname in BLOCKED_EXACT_HOSTNAMES or any(
        hostname.endswith(suffix) for suffix in BLOCKED_HOSTNAME_SUFFIXES
    ):
        return SecurityVerdict(
            allowed=False,
            url=syntax_verdict.url,
            normalized_url=syntax_verdict.normalized_url,
            reason=f"Blocked internal/reserved hostname '{hostname}'.",
            risk_level="critical",
        )

    if _is_obfuscated_ip_hostname(hostname):
        return SecurityVerdict(
            allowed=False,
            url=syntax_verdict.url,
            normalized_url=syntax_verdict.normalized_url,
            reason=f"Blocked obfuscated IP hostname '{hostname}'.",
            risk_level="critical",
        )

    # Check if hostname is an IP literal directly
    try:
        ipaddress.ip_address(hostname)
        ip_literal = True
    except ValueError:
        ip_literal = False

    if ip_literal:
        safe, reason = is_ip_safe(hostname)
        if not safe:
            return SecurityVerdict(
                allowed=False,
                url=syntax_verdict.url,
                normalized_url=syntax_verdict.normalized_url,
                reason=reason,
                resolved_ips=[hostname],
                risk_level="critical",
            )
        return SecurityVerdict(
            allowed=True,
            url=syntax_verdict.url,
            normalized_url=syntax_verdict.normalized_url,
            reason="Public IP literal verified safe.",
            resolved_ips=[hostname],
            risk_level="low",
        )

    if not resolve_dns:
        return SecurityVerdict(
            allowed=True,
            url=syntax_verdict.url,
            normalized_url=syntax_verdict.normalized_url,
            reason="URL passed static syntax and hostname checks (DNS resolution skipped).",
            resolved_ips=[],
            risk_level="low",
        )

    # Resolve all IPv4/IPv6 addresses via system resolver and inspect every single one
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        ascii_host = hostname.encode("idna").decode("ascii")
        addr_info = socket.getaddrinfo(ascii_host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as exc:
        return SecurityVerdict(
            allowed=False,
            url=syntax_verdict.url,
            normalized_url=syntax_verdict.normalized_url,
            reason=f"DNS resolution failed for '{hostname}': {exc}",
            resolved_ips=[],
            risk_level="high",
        )

    resolved_ips: list[str] = []
    seen: set[str] = set()
    for info in addr_info:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_str = str(sockaddr[0])
        if ip_str not in seen:
            seen.add(ip_str)
            resolved_ips.append(ip_str)

    if not resolved_ips:
        return SecurityVerdict(
            allowed=False,
            url=syntax_verdict.url,
            normalized_url=syntax_verdict.normalized_url,
            reason=f"No IP addresses returned by DNS for '{hostname}'.",
            resolved_ips=[],
            risk_level="high",
        )

    for ip_str in resolved_ips:
        safe, reason = is_ip_safe(ip_str)
        if not safe:
            return SecurityVerdict(
                allowed=False,
                url=syntax_verdict.url,
                normalized_url=syntax_verdict.normalized_url,
                reason=f"DNS rebinding / internal resolution blocked for '{hostname}': {reason}",
                resolved_ips=resolved_ips,
                risk_level="critical",
            )

    return SecurityVerdict(
        allowed=True,
        url=syntax_verdict.url,
        normalized_url=syntax_verdict.normalized_url,
        reason=f"All resolved DNS targets for '{hostname}' verified public.",
        resolved_ips=resolved_ips,
        risk_level="low",
    )


class RateLimiter:
    """Thread-safe sliding-window rate limiter to prevent automated loop abuse."""

    def __init__(self, max_requests: int = 30, window_seconds: float = 60.0) -> None:
        if max_requests <= 0 or window_seconds <= 0:
            raise ValueError("max_requests and window_seconds must be positive.")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: deque[float] = deque()
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._timestamps and self._timestamps[0] <= cutoff:
            self._timestamps.popleft()

    def allow(self) -> bool:
        """Record a request if under the limit; return True if allowed, False otherwise."""
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            if len(self._timestamps) >= self.max_requests:
                return False
            self._timestamps.append(now)
            return True

    def check_or_raise(self, action: str = "request") -> None:
        """Consume one request slot or raise SecurityError if rate limit is exceeded."""
        if not self.allow():
            raise SecurityError(
                f"Rate limit exceeded for {action}: maximum {self.max_requests} requests "
                f"per {self.window_seconds:.0f}s allowed."
            )

    def remaining(self) -> int:
        """Return number of requests remaining in the current window."""
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            return max(0, self.max_requests - len(self._timestamps))

    def reset(self) -> None:
        """Clear all recorded request timestamps."""
        with self._lock:
            self._timestamps.clear()
