"""Unit tests for Weber MCP AI-First Query Engine (Caller AI, MCP Sampling, Direct URL, Fallback)."""

from types import SimpleNamespace

import pytest

from weber_mcp.query_engine import (
    generate_query_plan_with_ai,
    parse_ai_query_json,
    transform_query,
)


def test_caller_ai_queries_multilingual() -> None:
    # Turkish
    tr_plan = transform_query(
        "Metro Exodus oyunu ne hakkındaydı?",
        search_queries=["Metro Exodus oyununun hikayesi", "Metro Exodus Hikayesi"],
        intent="story_subject",
        extracted_entity="Metro Exodus",
        intent_keywords=["hikayesi", "konusu"],
        language="tr",
    )
    assert tr_plan.query_source == "caller_ai"
    assert tr_plan.detected_intent == "story_subject"
    assert tr_plan.extracted_entity == "Metro Exodus"
    assert "Metro Exodus oyununun hikayesi" in tr_plan.expanded_queries
    assert "Metro Exodus Hikayesi" in tr_plan.expanded_queries

    # English
    en_plan = transform_query(
        "What was the Metro Exodus game about?",
        search_queries=["Metro Exodus game story", "Metro Exodus Story"],
        intent="story_subject",
        extracted_entity="Metro Exodus",
        language="en",
    )
    assert en_plan.query_source == "caller_ai"
    assert en_plan.primary_query == "Metro Exodus game story"

    # Arabic
    ar_plan = transform_query(
        "عن ماذا تتحدث لعبة Metro Exodus؟",
        search_queries=["قصة لعبة Metro Exodus", "قصة Metro Exodus"],
        intent="story_subject",
        extracted_entity="Metro Exodus",
        language="ar",
    )
    assert ar_plan.query_source == "caller_ai"
    assert "قصة لعبة Metro Exodus" in ar_plan.expanded_queries
    assert "قصة Metro Exodus" in ar_plan.expanded_queries


@pytest.mark.asyncio
async def test_mcp_sampling_ai_query_generation() -> None:
    async def fake_create_message(**kwargs):
        ai_json = (
            '```json\n'
            '{"entity": "Metro Exodus", "domain_category": "game", "intent": "story_subject", '
            '"language": "tr", "search_queries": ["Metro Exodus oyununun hikayesi", "Metro Exodus Hikayesi"], '
            '"intent_keywords": ["hikayesi", "konusu"]}'
            '\n```'
        )
        return SimpleNamespace(content=SimpleNamespace(text=ai_json))

    mock_ctx = SimpleNamespace(session=SimpleNamespace(create_message=fake_create_message))
    plan = await generate_query_plan_with_ai("Metro Exodus oyunu ne hakkındaydı?", ctx=mock_ctx)
    assert plan.query_source == "mcp_sampling_ai"
    assert plan.detected_intent == "story_subject"
    assert plan.detected_language == "tr"
    assert plan.extracted_entity == "Metro Exodus"
    assert "Metro Exodus oyununun hikayesi" in plan.expanded_queries
    assert "Metro Exodus Hikayesi" in plan.expanded_queries


def test_parse_ai_query_json_invalid_returns_none() -> None:
    assert parse_ai_query_json("not json at all", "hello") is None
    assert parse_ai_query_json('{"search_queries": []}', "hello") is None


def test_direct_url_detection() -> None:
    plan_mixed = transform_query("https://example.com inspect this page")
    assert plan_mixed.is_direct_url is True
    assert plan_mixed.query_source == "direct_url"
    assert plan_mixed.detected_intent == "direct_url"
    assert plan_mixed.detected_urls == ["https://example.com"]
    assert plan_mixed.remaining_question == "inspect this page"

    plan_only = transform_query("https://docs.python.org/3/library/asyncio.html")
    assert plan_only.is_direct_url is True
    assert plan_only.detected_urls == ["https://docs.python.org/3/library/asyncio.html"]

    plan_bare = transform_query("www.example.com/about check it")
    assert plan_bare.is_direct_url is True
    assert plan_bare.detected_urls == ["https://www.example.com/about"]


def test_raw_fallback_and_non_url_dotted_names() -> None:
    plan = transform_query("Node.js nedir?")
    assert plan.is_direct_url is False
    assert plan.query_source == "raw_fallback"
    assert plan.primary_query == "Node.js nedir"

    ar_fallback = transform_query("ما هو Rust؟")
    assert ar_fallback.is_direct_url is False
    assert ar_fallback.query_source == "raw_fallback"
    assert ar_fallback.primary_query == "ما هو Rust"
