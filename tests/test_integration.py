"""Integration tests running real Playwright headless Chromium via Weber MCP."""

import pytest

from weber_mcp.server import (
    close_browser,
    weber_fetch_url,
    weber_search,
    weber_security_audit_url,
    weber_transform_query,
)


@pytest.mark.asyncio
async def test_live_fetch_example_dot_com_and_ssrf_block() -> None:
    try:
        res_ok = await weber_fetch_url("https://example.com")
        assert "Example Domain" in res_ok
        assert "<untrusted_web_content" in res_ok
        assert "</untrusted_web_content>" in res_ok

        res_blocked_loopback = await weber_fetch_url("http://127.0.0.1:8080")
        assert "Blocked by Security Policy" in res_blocked_loopback

        res_blocked_metadata = await weber_fetch_url("http://169.254.169.254/latest/meta-data/")
        assert "Blocked by Security Policy" in res_blocked_metadata

        audit_json = await weber_security_audit_url("http://localhost/admin")
        assert '"allowed": false' in audit_json

        transform_json = await weber_transform_query(
            "Metro Exodus oyunu ne hakkındaydı?",
            search_queries=["Metro Exodus oyununun hikayesi", "Metro Exodus Hikayesi"],
            intent="story_subject",
            extracted_entity="Metro Exodus",
        )
        assert "Metro Exodus oyununun hikayesi" in transform_json
        assert "Metro Exodus Hikayesi" in transform_json
    finally:
        await close_browser()


@pytest.mark.asyncio
async def test_live_weber_search_metro_exodus() -> None:
    try:
        report = await weber_search(
            query="Metro Exodus oyunu ne hakkındaydı?",
            search_queries=["Metro Exodus oyununun hikayesi", "Metro Exodus Hikayesi"],
            intent="story_subject",
            extracted_entity="Metro Exodus",
            intent_keywords=["hikayesi", "konusu"],
            max_results=3,
            deep_fetch=True,
            deep_fetch_count=1,
            language="tr",
        )
        assert "query_analysis" in report
        assert "Metro Exodus oyununun hikayesi" in report
        assert "Metro Exodus Hikayesi" in report
        assert "search_results" in report
        assert "security_audit" in report
        assert "skipped_deep_pages" in report
        assert '"stripped_vars"' not in report
        # Ensure we actually got search hits OR a clear anti-bot report if engines gated
        assert ("http" in report) or ("captcha_warnings" in report)
    finally:
        await close_browser()


def test_is_usable_deep_page_skips_404_and_accepts_valid() -> None:
    from weber_mcp.browser import PageFetchResult
    from weber_mcp.sanitizer import SanitizedContent
    from weber_mcp.server import _is_usable_deep_page

    page_404 = PageFetchResult(
        requested_url="https://example.com/missing",
        final_url="https://example.com/missing",
        status_code=404,
        content_type="text/html",
        allowed=True,
        sanitized=SanitizedContent(
            title="Page Not Found",
            clean_text="Not found " * 30,
            wrapped_content="<untrusted_web_content>...</untrusted_web_content>",
        ),
    )
    ok_404, reason_404 = _is_usable_deep_page(page_404)
    assert ok_404 is False
    assert reason_404 == "http_404"

    page_200_valid = PageFetchResult(
        requested_url="https://example.com/good",
        final_url="https://example.com/good",
        status_code=200,
        content_type="text/html",
        allowed=True,
        sanitized=SanitizedContent(
            title="Cyberpunk 2077",
            clean_text="Cyberpunk 2077 is an open-world action-adventure RPG set in Night City. " * 4,
            wrapped_content="<untrusted_web_content>...</untrusted_web_content>",
        ),
    )
    ok_200, reason_200 = _is_usable_deep_page(page_200_valid)
    assert ok_200 is True
    assert reason_200 == "ok"
