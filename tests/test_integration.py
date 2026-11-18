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
        # Ensure we actually got search hits OR a clear anti-bot report if engines gated
        assert ("http" in report) or ("captcha_warnings" in report)
    finally:
        await close_browser()
