"""Hardened Playwright Headless Chromium controller for Weber MCP."""

from __future__ import annotations

import asyncio
import random
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, quote_plus, unquote, urlsplit

from bs4 import BeautifulSoup
from playwright.async_api import Browser, BrowserContext, Page, Playwright, Route, async_playwright

from weber_mcp.sandbox import WeberSandbox, activate_sandbox, get_sandbox
from weber_mcp.sanitizer import SanitizedContent, sanitize_html_and_extract
from weber_mcp.security import RateLimiter, SecurityVerdict, verify_url_safety

DEFAULT_IDLE_TIMEOUT_SECONDS = 180.0

HARDENED_CHROMIUM_ARGS = [
    "--disable-extensions",
    "--disable-plugins",
    "--no-first-run",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-translate",
    "--mute-audio",
    "--disable-client-side-phishing-detection",
    "--disable-component-update",
    "--disable-dev-shm-usage",
    "--disable-blink-features=AutomationControlled",
    "--window-size=1920,1080",
    "--lang=tr-TR,tr,en-US,en",
]

CHROMIUM_IGNORE_DEFAULT_ARGS = ["--enable-automation"]

_BROWSER_PROFILES: tuple[dict[str, Any], ...] = (
    {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/130.0.0.0 Safari/537.36"
        ),
        "sec_ch_ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
        "viewport": {"width": 1366, "height": 768},
        "screen": {"width": 1366, "height": 768},
    },
    {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "viewport": {"width": 1536, "height": 864},
        "screen": {"width": 1536, "height": 864},
    },
    {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/132.0.0.0 Safari/537.36"
        ),
        "sec_ch_ua": '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
        "viewport": {"width": 1920, "height": 1080},
        "screen": {"width": 1920, "height": 1080},
    },
)

DEFAULT_USER_AGENT = _BROWSER_PROFILES[1]["user_agent"]

STEALTH_INIT_SCRIPT = """
(() => {
    try {
        Object.defineProperty(Navigator.prototype, 'webdriver', {
            get: () => undefined,
            configurable: true
        });
    } catch (_) {}

    try {
        Object.defineProperty(navigator, 'languages', {
            get: () => ['tr-TR', 'tr', 'en-US', 'en'],
            configurable: true
        });
        Object.defineProperty(navigator, 'language', {
            get: () => 'tr-TR',
            configurable: true
        });
        Object.defineProperty(navigator, 'platform', {
            get: () => 'Win32',
            configurable: true
        });
        Object.defineProperty(navigator, 'hardwareConcurrency', {
            get: () => 8,
            configurable: true
        });
        Object.defineProperty(navigator, 'deviceMemory', {
            get: () => 8,
            configurable: true
        });
        Object.defineProperty(navigator, 'maxTouchPoints', {
            get: () => 0,
            configurable: true
        });
    } catch (_) {}

    try {
        if (!window.chrome) {
            Object.defineProperty(window, 'chrome', {
                value: {},
                writable: true,
                enumerable: true,
                configurable: true
            });
        }
        if (!window.chrome.runtime) {
            window.chrome.runtime = {
                PlatformOs: { MAC: 'mac', WIN: 'win', ANDROID: 'android', CROS: 'cros', LINUX: 'linux', OPENBSD: 'openbsd' },
                PlatformArch: { ARM: 'arm', ARM64: 'arm64', X86_32: 'x86-32', X86_64: 'x86-64', MIPS: 'mips', MIPS64: 'mips64' },
                RequestUpdateCheckStatus: { THROTTLED: 'throttled', NO_UPDATE: 'no_update', UPDATE_AVAILABLE: 'update_available' }
            };
        }
        if (!window.chrome.app) {
            window.chrome.app = {
                isInstalled: false,
                InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
                RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' },
                getDetails: () => null,
                getIsInstalled: () => false
            };
        }
        if (!window.chrome.csi) {
            window.chrome.csi = () => ({ onloadT: Date.now(), pageT: 120.5, startE: Date.now() - 120, tran: 15 });
        }
        if (!window.chrome.loadTimes) {
            window.chrome.loadTimes = () => ({
                commitLoadTime: Date.now() / 1000,
                connectionInfo: 'h2',
                finishDocumentLoadTime: Date.now() / 1000,
                finishLoadTime: Date.now() / 1000,
                firstPaintAfterLoadTime: 0,
                firstPaintTime: Date.now() / 1000,
                navigationType: 'Other',
                npnNegotiatedProtocol: 'h2',
                requestTime: Date.now() / 1000,
                startLoadTime: Date.now() / 1000,
                wasAlternateProtocolAvailable: false,
                wasFetchedViaSpdy: true,
                wasNpnNegotiated: true
            });
        }
    } catch (_) {}

    try {
        const fakePlugins = [
            { name: 'PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'Microsoft Edge PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            { name: 'WebKit built-in PDF', filename: 'internal-pdf-viewer', description: 'Portable Document Format' }
        ];
        const pluginArray = fakePlugins.map((p) => {
            const mime = Object.defineProperties(Object.create(MimeType.prototype), {
                type: { value: 'application/pdf', enumerable: true },
                suffixes: { value: 'pdf', enumerable: true },
                description: { value: 'Portable Document Format', enumerable: true }
            });
            return Object.defineProperties(Object.create(Plugin.prototype), {
                name: { value: p.name, enumerable: true },
                filename: { value: p.filename, enumerable: true },
                description: { value: p.description, enumerable: true },
                length: { value: 1, enumerable: true },
                0: { value: mime, enumerable: true },
                item: { value: (i) => (i === 0 ? mime : null) },
                namedItem: { value: (n) => (n === 'application/pdf' ? mime : null) }
            });
        });
        pluginArray.item = (i) => pluginArray[i] || null;
        pluginArray.namedItem = (name) => pluginArray.find((p) => p.name === name) || null;
        pluginArray.refresh = () => {};
        Object.defineProperty(Navigator.prototype, 'plugins', {
            get: () => pluginArray,
            configurable: true
        });
        const fakeMimes = [
            Object.defineProperties(Object.create(MimeType.prototype), {
                type: { value: 'application/pdf', enumerable: true },
                suffixes: { value: 'pdf', enumerable: true },
                description: { value: 'Portable Document Format', enumerable: true },
                enabledPlugin: { value: pluginArray[0], enumerable: true }
            }),
            Object.defineProperties(Object.create(MimeType.prototype), {
                type: { value: 'text/pdf', enumerable: true },
                suffixes: { value: 'pdf', enumerable: true },
                description: { value: 'Portable Document Format', enumerable: true },
                enabledPlugin: { value: pluginArray[0], enumerable: true }
            })
        ];
        fakeMimes.item = (i) => fakeMimes[i] || null;
        fakeMimes.namedItem = (name) => fakeMimes.find((m) => m.type === name) || null;
        Object.defineProperty(Navigator.prototype, 'mimeTypes', {
            get: () => fakeMimes,
            configurable: true
        });
    } catch (_) {}

    try {
        if (navigator.permissions && navigator.permissions.query) {
            const origQuery = navigator.permissions.query.bind(navigator.permissions);
            navigator.permissions.query = (parameters) => (
                parameters && parameters.name === 'notifications'
                    ? Promise.resolve({ state: Notification.permission })
                    : origQuery(parameters)
            );
        }
    } catch (_) {}

    try {
        if (!window.outerWidth) {
            Object.defineProperty(window, 'outerWidth', { get: () => window.innerWidth, configurable: true });
        }
        if (!window.outerHeight) {
            Object.defineProperty(window, 'outerHeight', { get: () => window.innerHeight + 80, configurable: true });
        }
    } catch (_) {}

    try {
        const patchWebGL = (proto) => {
            if (!proto || !proto.getParameter) return;
            const origGetParam = proto.getParameter;
            proto.getParameter = function (param) {
                if (param === 37445) return 'Google Inc. (NVIDIA)';
                if (param === 37446) return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)';
                return origGetParam.call(this, param);
            };
        };
        if (typeof WebGLRenderingContext !== 'undefined') patchWebGL(WebGLRenderingContext.prototype);
        if (typeof WebGL2RenderingContext !== 'undefined') patchWebGL(WebGL2RenderingContext.prototype);
    } catch (_) {}
})();
"""

ALLOWED_CONTENT_TYPES = frozenset({
    "text/html",
    "text/plain",
    "application/xhtml+xml",
    "application/json",
    "application/xml",
    "text/xml",
})

BLOCKED_RESOURCE_TYPES = frozenset({
    "media",
    "font",
    "websocket",
    "eventsource",
    "manifest",
    "image",
})

_CAPTCHA_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Cloudflare Turnstile / Challenge", re.compile(r"cf-turnstile|challenges\.cloudflare\.com|cf-chl-widget", re.I)),
    ("Cloudflare Interstitial", re.compile(r"<title>\s*(?:Just a moment\.\.\.|Attention Required!\s*\|\s*Cloudflare)\s*</title>", re.I)),
    ("Google reCAPTCHA", re.compile(r"class=[\"'][^\"']*g-recaptcha|google\.com/recaptcha/api", re.I)),
    ("hCaptcha", re.compile(r"class=[\"'][^\"']*h-captcha|hcaptcha\.com/1/api\.js", re.I)),
    (
        "Anti-bot verification gate",
        re.compile(
            r"verify you are human|are you a robot|unusual traffic from your computer network|"
            r"robot olmadığınızı doğrulayın|insan olduğunuzu doğrulayın|"
            r"تحقق من أنك إنسان|لست برنامج روبوت",
            re.I,
        ),
    ),
)

_YAHOO_RU_RE = re.compile(r"/RU=([^/]+)/R[KP]=")


@dataclass
class SearchHit:
    """Single search engine result item."""

    title: str
    url: str
    snippet: str
    engine: str
    matched_query: str
    score: float = 0.0


@dataclass
class SearchExecutionResult:
    """Result bundle from multi-engine headless search."""

    results: list[SearchHit] = field(default_factory=list)
    engines_tried: list[str] = field(default_factory=list)
    queries_executed: list[str] = field(default_factory=list)
    blocked_urls: list[dict[str, str]] = field(default_factory=list)
    captcha_warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class PageFetchResult:
    """Result of fetching and sanitizing a web page in hardened headless Chromium."""

    requested_url: str
    final_url: str
    status_code: int | None
    content_type: str
    allowed: bool
    blocked_reason: str = ""
    captcha_detected: bool = False
    captcha_detail: str = ""
    sanitized: SanitizedContent | None = None
    security_verdict: SecurityVerdict | None = None
    blocked_subrequests: list[dict[str, str]] = field(default_factory=list)
    error: str = ""


def _detect_captcha(title: str, html: str) -> tuple[bool, str]:
    """Detect CAPTCHA or anti-bot human verification gates without attempting to bypass them."""
    combined = f"<title>{title}</title>\n{html[:25000]}"
    for label, pattern in _CAPTCHA_MARKERS:
        if pattern.search(combined):
            return True, label
    return False, ""


def _unwrap_search_url(raw_href: str) -> str:
    """Unwrap DuckDuckGo / Yahoo redirect URLs to extract the real target URL."""
    href = (raw_href or "").strip()
    if not href:
        return ""
    if href.startswith("//"):
        href = "https:" + href

    parsed = urlsplit(href)
    # DuckDuckGo redirect: //duckduckgo.com/l/?uddg=https%3A%2F%2F...
    if "duckduckgo.com" in parsed.netloc and parsed.path.startswith("/l/"):
        qs = parse_qs(parsed.query)
        if "uddg" in qs and qs["uddg"]:
            return unquote(qs["uddg"][0])

    # Yahoo redirect: https://r.search.yahoo.com/.../RU=https%3a%2f%2f.../RK=2/...
    if "search.yahoo.com" in parsed.netloc and "/RU=" in href:
        m = _YAHOO_RU_RE.search(href)
        if m:
            return unquote(m.group(1))

    return href


def _score_search_hit(title: str, snippet: str, url: str, intent_keywords: list[str]) -> float:
    """Score search result relevance based on intent keywords."""
    score = 1.0
    title_l = title.lower()
    snippet_l = snippet.lower()
    url_l = url.lower()

    for kw in intent_keywords:
        kw_l = kw.lower()
        if not kw_l:
            continue
        if kw_l in title_l:
            score += 3.0
        if kw_l in url_l:
            score += 1.5
        if kw_l in snippet_l:
            score += 1.2
    return score


def _parse_duckduckgo_html(html: str, query: str) -> list[SearchHit]:
    soup = BeautifulSoup(html, "html.parser")
    hits: list[SearchHit] = []
    for result_div in soup.select("div.result, div.web-result"):
        a_tag = result_div.select_one("a.result__a")
        if not a_tag:
            continue
        href = _unwrap_search_url(str(a_tag.get("href", "")))
        title = a_tag.get_text(" ", strip=True)
        snippet_el = result_div.select_one(".result__snippet")
        snippet = snippet_el.get_text(" ", strip=True) if snippet_el else ""
        if href and title:
            hits.append(
                SearchHit(
                    title=title,
                    url=href,
                    snippet=snippet,
                    engine="duckduckgo_html",
                    matched_query=query,
                )
            )
    return hits


def _parse_brave_html(html: str, query: str) -> list[SearchHit]:
    soup = BeautifulSoup(html, "html.parser")
    hits: list[SearchHit] = []
    for card in soup.select("#results div.snippet, #results div[data-type='web']"):
        a_tag = card.select_one("a[href^='http']")
        if not a_tag:
            continue
        href = _unwrap_search_url(str(a_tag.get("href", "")))
        if "search.brave.com" in href:
            continue
        title_el = card.select_one(".title, .snippet-title") or a_tag
        title = title_el.get_text(" ", strip=True)
        desc_el = card.select_one(".snippet-description, .snippet-content")
        snippet = desc_el.get_text(" ", strip=True) if desc_el else ""
        if href and title:
            hits.append(
                SearchHit(
                    title=title,
                    url=href,
                    snippet=snippet,
                    engine="brave_search",
                    matched_query=query,
                )
            )
    return hits


def _parse_yahoo_html(html: str, query: str) -> list[SearchHit]:
    soup = BeautifulSoup(html, "html.parser")
    hits: list[SearchHit] = []
    for algo in soup.select("div.algo"):
        a_tag = algo.select_one("h3.title a, a[href^='http']")
        if not a_tag:
            continue
        href = _unwrap_search_url(str(a_tag.get("href", "")))
        title = a_tag.get_text(" ", strip=True)
        desc_el = algo.select_one(".compText, p")
        snippet = desc_el.get_text(" ", strip=True) if desc_el else ""
        if href and title and "yahoo.com/preferences" not in href:
            hits.append(
                SearchHit(
                    title=title,
                    url=href,
                    snippet=snippet,
                    engine="yahoo_search",
                    matched_query=query,
                )
            )
    return hits


class HardenedBrowser:
    """Isolated, SSRF-intercepted, OS-sandboxed Playwright headless Chromium controller."""

    def __init__(
        self,
        rate_limiter: RateLimiter | None = None,
        sandbox: WeberSandbox | None = None,
        idle_timeout_seconds: float = DEFAULT_IDLE_TIMEOUT_SECONDS,
    ) -> None:
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = asyncio.Lock()
        self.rate_limiter = rate_limiter or RateLimiter(max_requests=30, window_seconds=60.0)
        self.sandbox = sandbox or activate_sandbox()
        self.idle_timeout_seconds = max(0.0, float(idle_timeout_seconds))
        self._active_contexts: int = 0
        self._last_activity_ts: float = 0.0
        self._idle_watchdog_task: asyncio.Task[None] | None = None
        self.idle_shutdown_count: int = 0

    async def __aenter__(self) -> HardenedBrowser:
        await self._ensure_browser()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()

    def is_browser_running(self) -> bool:
        """Return True if Chromium is currently connected and running."""
        return self._browser is not None and self._browser.is_connected()

    def _cancel_idle_watchdog(self) -> None:
        """Cancel any scheduled idle shutdown timer."""
        if self._idle_watchdog_task is not None and not self._idle_watchdog_task.done():
            try:
                if self._idle_watchdog_task is not asyncio.current_task():
                    self._idle_watchdog_task.cancel()
            except Exception:
                pass
        self._idle_watchdog_task = None

    def _schedule_idle_watchdog(self) -> None:
        """Schedule automatic Chromium shutdown after idle_timeout_seconds of inactivity."""
        self._cancel_idle_watchdog()
        if self.idle_timeout_seconds <= 0 or not self.is_browser_running():
            return
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return
        self._idle_watchdog_task = asyncio.create_task(self._idle_watchdog_worker())

    async def _idle_watchdog_worker(self) -> None:
        """Background timer task that shuts down Chromium when idle."""
        try:
            await asyncio.sleep(self.idle_timeout_seconds)
            async with self._lock:
                if (
                    self._active_contexts == 0
                    and self._browser is not None
                    and (time.monotonic() - self._last_activity_ts) >= self.idle_timeout_seconds * 0.95
                ):
                    await self._close_locked()
                    self.idle_shutdown_count += 1
        except asyncio.CancelledError:
            return
        finally:
            try:
                if self._idle_watchdog_task is asyncio.current_task():
                    self._idle_watchdog_task = None
            except Exception:
                pass

    async def _close_locked(self) -> None:
        """Close browser and Playwright driver (caller must hold self._lock)."""
        if self._browser is not None:
            try:
                await self._browser.close()
            except Exception:
                pass
            self._browser = None
        if self._playwright is not None:
            try:
                await self._playwright.stop()
            except Exception:
                pass
            self._playwright = None
        self._loop = None

    async def _ensure_browser(self) -> Browser:
        current_loop = asyncio.get_running_loop()
        async with self._lock:
            self.sandbox.activate()
            if self._browser is not None and self._loop is not current_loop:
                # Reset cleanly if called from a different event loop (e.g., separate tests)
                self._browser = None
                self._playwright = None
                self._loop = None
                self._idle_watchdog_task = None
                self._active_contexts = 0

            if self._browser is None or not self._browser.is_connected():
                clean_env, _ = self.sandbox.get_sanitized_env()
                launch_args = [
                    *HARDENED_CHROMIUM_ARGS,
                    "--disk-cache-size=10485760",
                    "--media-cache-size=1",
                    "--disable-gpu-shader-disk-cache",
                ]
                if self.sandbox.chromium_cache_dir:
                    launch_args.append(f"--disk-cache-dir={self.sandbox.chromium_cache_dir}")

                self._playwright = await async_playwright().start()
                self._browser = await self._playwright.chromium.launch(
                    headless=True,
                    args=launch_args,
                    ignore_default_args=CHROMIUM_IGNORE_DEFAULT_ARGS,
                    env=clean_env,
                )
                self._loop = current_loop
                self._last_activity_ts = time.monotonic()
            return self._browser

    async def close(self) -> None:
        """Close Chromium browser and Playwright driver cleanly."""
        self._cancel_idle_watchdog()
        async with self._lock:
            await self._close_locked()

    async def _new_isolated_context(
        self,
        java_script_enabled: bool = True,
        referer: str | None = None,
    ) -> BrowserContext:
        browser = await self._ensure_browser()
        profile = random.choice(_BROWSER_PROFILES)
        headers: dict[str, str] = {
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
            "Sec-CH-UA": profile["sec_ch_ua"],
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"Windows"',
            "Upgrade-Insecure-Requests": "1",
            "DNT": "1",
        }
        if referer:
            headers["Referer"] = referer

        context = await browser.new_context(
            accept_downloads=False,
            service_workers="block",
            permissions=[],
            java_script_enabled=java_script_enabled,
            user_agent=profile["user_agent"],
            locale="tr-TR",
            timezone_id="Europe/Istanbul",
            color_scheme="light",
            viewport=profile["viewport"],
            screen=profile["screen"],
            device_scale_factor=1,
            has_touch=False,
            is_mobile=False,
            extra_http_headers=headers,
        )
        if java_script_enabled:
            await context.add_init_script(STEALTH_INIT_SCRIPT)
        return context

    @asynccontextmanager
    async def _managed_context(
        self,
        java_script_enabled: bool = True,
        referer: str | None = None,
    ) -> AsyncIterator[BrowserContext]:
        """Acquire an isolated stealth context and manage the 180s idle auto-shutdown timer."""
        self._cancel_idle_watchdog()
        self._active_contexts += 1
        self._last_activity_ts = time.monotonic()
        context = await self._new_isolated_context(
            java_script_enabled=java_script_enabled,
            referer=referer,
        )
        try:
            yield context
        finally:
            try:
                await context.close()
            except Exception:
                pass
            self._active_contexts = max(0, self._active_contexts - 1)
            self._last_activity_ts = time.monotonic()
            if self._active_contexts == 0:
                self._schedule_idle_watchdog()

    def get_browser_status(self) -> dict[str, Any]:
        """Return live browser lifecycle, idle timeout, and anti-bot normalization status."""
        since_last = (
            round(time.monotonic() - self._last_activity_ts, 2)
            if self._last_activity_ts > 0
            else None
        )
        return {
            "browser_running": self.is_browser_running(),
            "idle_timeout_seconds": self.idle_timeout_seconds,
            "active_contexts": self._active_contexts,
            "seconds_since_last_activity": since_last,
            "idle_shutdown_count": self.idle_shutdown_count,
            "stealth_features": [
                "automation_controlled_disabled",
                "enable_automation_removed",
                "webdriver_undefined",
                "client_hints_headers",
                "realistic_desktop_profiles",
                "webgl_plugins_normalized",
                "inter_query_pacing",
            ],
        }

    async def _attach_security_interceptor(
        self,
        page: Page,
        audit_log: dict[str, list[dict[str, str]]],
        block_images: bool = True,
    ) -> None:
        """Intercept every network request (and redirect hop) to enforce SSRF & resource rules."""

        async def _route_handler(route: Route) -> None:
            request = route.request
            res_type = request.resource_type
            req_url = request.url

            blocked_types = BLOCKED_RESOURCE_TYPES if block_images else (
                BLOCKED_RESOURCE_TYPES - {"image"}
            )
            if res_type in blocked_types:
                await route.abort("blockedbyclient")
                return

            verdict = await asyncio.to_thread(verify_url_safety, req_url, True)
            if not verdict.allowed:
                audit_log["blocked_requests"].append({
                    "url": req_url,
                    "resource_type": res_type,
                    "reason": verdict.reason,
                    "risk_level": verdict.risk_level,
                })
                await route.abort("accessdenied")
                return

            await route.continue_()

        await page.route("**/*", _route_handler)

    async def fetch_page_headless(
        self,
        url: str,
        wait_for_selector: str | None = None,
        max_chars: int = 12000,
        extract_links: bool = False,
        java_script_enabled: bool = True,
        timeout_ms: int = 15000,
    ) -> PageFetchResult:
        """Safely navigate to a URL in headless Chromium, verify redirects, and sanitize content."""
        self.rate_limiter.check_or_raise("fetch_page_headless")

        pre_verdict = await asyncio.to_thread(verify_url_safety, url, True)
        if not pre_verdict.allowed:
            return PageFetchResult(
                requested_url=url,
                final_url=url,
                status_code=None,
                content_type="",
                allowed=False,
                blocked_reason=pre_verdict.reason,
                security_verdict=pre_verdict,
            )

        audit_log: dict[str, list[dict[str, str]]] = {"blocked_requests": []}
        try:
            async with self._managed_context(java_script_enabled=java_script_enabled) as context:
                page = await context.new_page()
                await self._attach_security_interceptor(page, audit_log, block_images=True)

                response = await page.goto(
                    pre_verdict.normalized_url,
                    wait_until="domcontentloaded",
                    timeout=timeout_ms,
                )

                final_url = page.url or pre_verdict.normalized_url
                post_verdict = await asyncio.to_thread(verify_url_safety, final_url, True)
                if not post_verdict.allowed:
                    return PageFetchResult(
                        requested_url=url,
                        final_url=final_url,
                        status_code=response.status if response else None,
                        content_type="",
                        allowed=False,
                        blocked_reason=f"Post-redirect security check failed: {post_verdict.reason}",
                        security_verdict=post_verdict,
                        blocked_subrequests=audit_log["blocked_requests"],
                    )

                status_code = response.status if response else None
                raw_ct = response.headers.get("content-type", "") if response else ""
                base_ct = raw_ct.split(";")[0].strip().lower()
                if base_ct and base_ct not in ALLOWED_CONTENT_TYPES:
                    return PageFetchResult(
                        requested_url=url,
                        final_url=final_url,
                        status_code=status_code,
                        content_type=raw_ct,
                        allowed=False,
                        blocked_reason=f"Blocked unsupported Content-Type '{raw_ct}'.",
                        security_verdict=post_verdict,
                        blocked_subrequests=audit_log["blocked_requests"],
                    )

                if wait_for_selector:
                    try:
                        await page.wait_for_selector(wait_for_selector, timeout=min(5000, timeout_ms))
                    except Exception:
                        pass

                title = await page.title()
                html = await page.content()

                is_captcha, captcha_label = _detect_captcha(title, html)
                if is_captcha:
                    return PageFetchResult(
                        requested_url=url,
                        final_url=final_url,
                        status_code=status_code,
                        content_type=raw_ct,
                        allowed=True,
                        captcha_detected=True,
                        captcha_detail=captcha_label,
                        security_verdict=post_verdict,
                        blocked_subrequests=audit_log["blocked_requests"],
                        error=(
                            f"Page gated by anti-bot / CAPTCHA challenge ({captcha_label}). "
                            "Weber MCP stopped immediately per security policy."
                        ),
                    )

                sanitized = sanitize_html_and_extract(
                    html=html,
                    source_url=final_url,
                    max_chars=max_chars,
                    extract_links=extract_links,
                )
                return PageFetchResult(
                    requested_url=url,
                    final_url=final_url,
                    status_code=status_code,
                    content_type=raw_ct,
                    allowed=True,
                    sanitized=sanitized,
                    security_verdict=post_verdict,
                    blocked_subrequests=audit_log["blocked_requests"],
                )
        except Exception as exc:
            return PageFetchResult(
                requested_url=url,
                final_url=url,
                status_code=None,
                content_type="",
                allowed=True,
                security_verdict=pre_verdict,
                blocked_subrequests=audit_log["blocked_requests"],
                error=f"Navigation error: {exc}",
            )

    async def _query_engine_once(
        self,
        engine_name: str,
        search_url: str,
        query: str,
        parser: Any,
        audit_log: dict[str, list[dict[str, str]]],
    ) -> tuple[list[SearchHit], str | None]:
        """Run a single search engine request inside an isolated headless Chromium context."""
        try:
            async with self._managed_context(
                java_script_enabled=(engine_name != "duckduckgo_html")
            ) as context:
                page = await context.new_page()
                await self._attach_security_interceptor(page, audit_log, block_images=True)
                await page.goto(search_url, wait_until="domcontentloaded", timeout=15000)

                if engine_name == "brave_search":
                    try:
                        await page.wait_for_selector(
                            "#results .snippet, #results div[data-type='web']", timeout=4000
                        )
                    except Exception:
                        pass

                title = await page.title()
                html = await page.content()
                is_captcha, captcha_label = _detect_captcha(title, html)
                if is_captcha:
                    return [], f"{engine_name}: blocked by {captcha_label}"

                return parser(html, query), None
        except Exception as exc:
            return [], f"{engine_name}: {exc}"

    async def search_web_headless(
        self,
        queries: list[str],
        max_results: int = 5,
        intent_keywords: list[str] | None = None,
    ) -> SearchExecutionResult:
        """Search across DuckDuckGo HTML, Brave Search, and Yahoo Search using headless Chromium."""
        self.rate_limiter.check_or_raise("search_web_headless")

        cleaned_queries = [q.strip() for q in queries if q and q.strip()]
        if not cleaned_queries:
            return SearchExecutionResult(errors=["No valid search queries provided."])

        keywords = intent_keywords or []
        exec_result = SearchExecutionResult()
        audit_log: dict[str, list[dict[str, str]]] = {"blocked_requests": []}

        engines = [
            (
                "duckduckgo_html",
                lambda q: f"https://html.duckduckgo.com/html/?q={quote_plus(q)}",
                _parse_duckduckgo_html,
            ),
            (
                "brave_search",
                lambda q: f"https://search.brave.com/search?q={quote_plus(q)}",
                _parse_brave_html,
            ),
            (
                "yahoo_search",
                lambda q: f"https://search.yahoo.com/search?p={quote_plus(q)}",
                _parse_yahoo_html,
            ),
        ]

        # Run up to 2 queries to combine precision + diversity
        active_queries = cleaned_queries[:2]
        collected_by_url: dict[str, SearchHit] = {}

        for query_idx, q in enumerate(active_queries):
            if query_idx > 0:
                await asyncio.sleep(random.uniform(0.15, 0.35))
            exec_result.queries_executed.append(q)
            query_hits: list[SearchHit] = []

            for engine_name, url_builder, parser in engines:
                if engine_name not in exec_result.engines_tried:
                    exec_result.engines_tried.append(engine_name)

                search_url = url_builder(q)
                hits, warning = await self._query_engine_once(
                    engine_name, search_url, q, parser, audit_log
                )
                if warning:
                    if "blocked by" in warning.lower():
                        exec_result.captcha_warnings.append(warning)
                    else:
                        exec_result.errors.append(warning)
                if hits:
                    query_hits.extend(hits)
                    break  # Primary engine succeeded for this query

            for hit in query_hits:
                verdict = verify_url_safety(hit.url, resolve_dns=False)
                if not verdict.allowed:
                    exec_result.blocked_urls.append({
                        "url": hit.url,
                        "reason": verdict.reason,
                    })
                    continue

                norm_url = verdict.normalized_url
                hit_score = _score_search_hit(hit.title, hit.snippet, norm_url, keywords)
                # Slight priority boost for primary query (index 0)
                if query_idx == 0:
                    hit_score += 1.0

                if norm_url in collected_by_url:
                    existing = collected_by_url[norm_url]
                    existing.score += 1.5  # Boost URLs confirmed by multiple query variants
                else:
                    hit.url = norm_url
                    hit.score = hit_score
                    collected_by_url[norm_url] = hit

            if query_idx == 0 and len(collected_by_url) >= max(max_results, 5):
                # Still run the 2nd query if user supplied multiple queries & max_results > 2
                # Wait: running query 2 boosts cross-query ranking when we have <= max_results + 2
                pass

        ranked = sorted(collected_by_url.values(), key=lambda h: h.score, reverse=True)
        exec_result.results = ranked[:max_results]
        return exec_result
