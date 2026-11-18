"""AI-First Query Intelligence Engine for Weber MCP.

Supports:
1. Direct URL detection for immediate safe page fetching.
2. Caller AI-generated search queries (`search_queries` passed by the calling LLM in any language).
3. MCP Sampling (`ctx.session.create_message`) fallback when only a raw question is provided.
4. Universal punctuation-cleaned raw fallback for offline CLI usage.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

# Matches explicit http(s):// URLs
_FULL_URL_RE = re.compile(r"https?://[^\s<>\"'{}|\\^`\[\]]+", re.IGNORECASE)

# Matches bare domain URLs like www.example.com/path or github.com/owner/repo
_BARE_DOMAIN_RE = re.compile(
    r"(?<![@\w.-])(?:www\.[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+|[a-zA-Z0-9-]+\."
    r"(?:com|org|net|io|dev|edu|gov|ai|app|info|xyz|co|uk|de|fr|tr|com\.tr|org\.tr|edu\.tr|gov\.tr))"
    r"(?:/[^\s<>\"'{}|\\^`\[\]]*)?",
    re.IGNORECASE,
)

_UNICODE_PUNCT_STRIP = "?!¿¡？！؟。.…،, \t\r\n"

AI_QUERY_PLANNER_SYSTEM_PROMPT = """\
You are a search query strategist for Weber MCP.
Analyze the user's question in whatever language it is written in (English, Turkish, Arabic, German, French, Spanish, Russian, Japanese, Chinese, etc.) and transform it into 2 to 4 crisp, high-signal web search queries in the same language.

Example:
User: "Metro Exodus oyunu ne hakkındaydı?"
-> {"entity": "Metro Exodus", "domain_category": "game", "intent": "story_subject", "language": "tr", "search_queries": ["Metro Exodus oyununun hikayesi", "Metro Exodus Hikayesi", "Metro Exodus oyun konusu"], "intent_keywords": ["hikayesi", "konusu", "story"]}

Example:
User: "What was the Metro Exodus game about?"
-> {"entity": "Metro Exodus", "domain_category": "game", "intent": "story_subject", "language": "en", "search_queries": ["Metro Exodus game story", "Metro Exodus Story", "Metro Exodus plot summary"], "intent_keywords": ["story", "plot", "summary"]}

Return ONLY a valid JSON object with exact keys:
- "entity": string (main subject)
- "domain_category": string ("game" | "movie" | "series" | "book" | "software" | "person" | "general")
- "intent": string ("story_subject" | "definition" | "how_to" | "troubleshooting" | "biography" | "comparison" | "review_specs" | "general_search")
- "language": string (ISO-639-1 code such as "en", "tr", "ar", "de", "fr", "es", "ru", "ja", "zh")
- "search_queries": list of 2 to 4 optimized search query strings
- "intent_keywords": list of 3 to 6 relevant keywords for search result ranking
"""


@dataclass
class QueryPlan:
    """Structured query plan produced by URL detection, Caller AI, MCP Sampling, or raw fallback."""

    original_input: str
    is_direct_url: bool = False
    detected_urls: list[str] = field(default_factory=list)
    remaining_question: str = ""
    extracted_entity: str = ""
    domain_category: str = "general"
    detected_intent: str = "general_search"
    detected_language: str = "auto"
    primary_query: str = ""
    expanded_queries: list[str] = field(default_factory=list)
    intent_keywords: list[str] = field(default_factory=list)
    query_source: str = "raw_fallback"  # direct_url | caller_ai | mcp_sampling_ai | raw_fallback


def _extract_urls(raw_input: str) -> tuple[list[str], str]:
    """Detect explicit and bare domain URLs in input and return (urls, remaining_text)."""
    urls: list[str] = []
    seen: set[str] = set()
    remaining = raw_input

    for match in _FULL_URL_RE.finditer(raw_input):
        candidate = match.group(0).rstrip(".,;!?)'\"")
        if candidate and candidate not in seen:
            seen.add(candidate)
            urls.append(candidate)
            remaining = remaining.replace(match.group(0), " ", 1)

    for match in _BARE_DOMAIN_RE.finditer(remaining):
        raw_bare = match.group(0).rstrip(".,;!?)'\"")
        candidate = f"https://{raw_bare}"
        if candidate not in seen:
            seen.add(candidate)
            urls.append(candidate)
            remaining = remaining.replace(match.group(0), " ", 1)

    remaining_clean = re.sub(r"\s+", " ", remaining).strip(_UNICODE_PUNCT_STRIP)
    return urls, remaining_clean


def _dedupe_queries(queries: list[str]) -> list[str]:
    """Preserve order while removing empty or case-insensitive duplicate queries."""
    out: list[str] = []
    seen: set[str] = set()
    for q in queries:
        norm = re.sub(r"\s+", " ", str(q)).strip()
        if not norm:
            continue
        key = norm.casefold()
        if key not in seen:
            seen.add(key)
            out.append(norm)
    return out


def _infer_keywords(*texts: str) -> list[str]:
    """Extract clean keyword tokens for search ranking fallback."""
    keywords: list[str] = []
    seen: set[str] = set()
    for text in texts:
        for token in re.split(r"[\s,.;:!?¿¡？！؟。/\\()\"']+", text or ""):
            tok = token.strip()
            if len(tok) > 2:
                low = tok.casefold()
                if low not in seen:
                    seen.add(low)
                    keywords.append(low)
    return keywords[:8]


def parse_ai_query_json(raw_text: str, original_input: str) -> QueryPlan | None:
    """Parse structured JSON returned by an AI Sampling call into a QueryPlan."""
    if not raw_text or not raw_text.strip():
        return None

    candidate = raw_text.strip()
    # Strip optional markdown code fences
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", candidate, re.DOTALL | re.IGNORECASE)
    if fence_match:
        candidate = fence_match.group(1)
    else:
        brace_start = candidate.find("{")
        brace_end = candidate.rfind("}")
        if brace_start != -1 and brace_end > brace_start:
            candidate = candidate[brace_start : brace_end + 1]

    try:
        data = json.loads(candidate)
    except (json.JSONDecodeError, TypeError):
        return None

    if not isinstance(data, dict):
        return None

    raw_queries = data.get("search_queries")
    if not isinstance(raw_queries, list):
        return None

    queries = _dedupe_queries([str(q) for q in raw_queries if isinstance(q, str) and q.strip()])
    if not queries:
        return None

    entity = str(data.get("entity") or "").strip() or queries[0]
    domain_cat = str(data.get("domain_category") or "general").strip() or "general"
    intent = str(data.get("intent") or "general_search").strip() or "general_search"
    lang = str(data.get("language") or "auto").strip() or "auto"

    raw_kws = data.get("intent_keywords")
    if isinstance(raw_kws, list) and raw_kws:
        keywords = _dedupe_queries([str(k).casefold() for k in raw_kws if str(k).strip()])
    else:
        keywords = _infer_keywords(*queries, entity)

    return QueryPlan(
        original_input=original_input,
        extracted_entity=entity,
        domain_category=domain_cat,
        detected_intent=intent,
        detected_language=lang,
        primary_query=queries[0],
        expanded_queries=queries,
        intent_keywords=keywords,
        query_source="mcp_sampling_ai",
    )


def transform_query(
    raw_input: str,
    search_queries: list[str] | None = None,
    intent: str = "general_search",
    extracted_entity: str = "",
    domain_category: str = "general",
    intent_keywords: list[str] | None = None,
    language: str = "auto",
) -> QueryPlan:
    """Build a QueryPlan from direct URLs, AI-supplied queries, or universal raw cleanup."""
    original = raw_input or ""
    cleaned_raw = re.sub(r"\s+", " ", original).strip()

    if not cleaned_raw and not search_queries:
        return QueryPlan(original_input=original, detected_language=language)

    # 1. Direct URL detection takes priority
    detected_urls, remaining_question = _extract_urls(cleaned_raw)
    if detected_urls:
        return QueryPlan(
            original_input=original,
            is_direct_url=True,
            detected_urls=detected_urls,
            remaining_question=remaining_question,
            extracted_entity=extracted_entity or remaining_question or detected_urls[0],
            domain_category=domain_category or "general",
            detected_intent="direct_url",
            detected_language=language,
            primary_query=detected_urls[0],
            expanded_queries=detected_urls,
            intent_keywords=[],
            query_source="direct_url",
        )

    # 2. Caller AI supplied optimized search queries
    cleaned_ai_queries = _dedupe_queries(search_queries or [])
    if cleaned_ai_queries:
        entity = extracted_entity.strip() or cleaned_ai_queries[0]
        keywords = (
            _dedupe_queries([k.casefold() for k in intent_keywords if k.strip()])
            if intent_keywords
            else _infer_keywords(*cleaned_ai_queries, entity)
        )
        return QueryPlan(
            original_input=original,
            extracted_entity=entity,
            domain_category=domain_category or "general",
            detected_intent=intent or "general_search",
            detected_language=language,
            primary_query=cleaned_ai_queries[0],
            expanded_queries=cleaned_ai_queries,
            intent_keywords=keywords,
            query_source="caller_ai",
        )

    # 3. Universal punctuation-stripped fallback (when neither Caller AI nor Sampling ran)
    stripped_core = cleaned_raw.strip(_UNICODE_PUNCT_STRIP) or cleaned_raw
    fallback_queries = _dedupe_queries([stripped_core])
    entity = extracted_entity.strip() or stripped_core
    keywords = (
        _dedupe_queries([k.casefold() for k in intent_keywords if k.strip()])
        if intent_keywords
        else _infer_keywords(stripped_core)
    )
    return QueryPlan(
        original_input=original,
        extracted_entity=entity,
        domain_category=domain_category or "general",
        detected_intent=intent or "general_search",
        detected_language=language,
        primary_query=fallback_queries[0],
        expanded_queries=fallback_queries,
        intent_keywords=keywords,
        query_source="raw_fallback",
    )


async def generate_query_plan_with_ai(
    raw_input: str,
    search_queries: list[str] | None = None,
    intent: str = "general_search",
    extracted_entity: str = "",
    domain_category: str = "general",
    intent_keywords: list[str] | None = None,
    language: str = "auto",
    ctx: Any = None,
) -> QueryPlan:
    """Resolve QueryPlan via Caller AI queries or MCP Sampling (`ctx.session.create_message`)."""
    plan = transform_query(
        raw_input=raw_input,
        search_queries=search_queries,
        intent=intent,
        extracted_entity=extracted_entity,
        domain_category=domain_category,
        intent_keywords=intent_keywords,
        language=language,
    )
    if plan.is_direct_url or plan.query_source == "caller_ai":
        return plan

    session = getattr(ctx, "session", None) if ctx is not None else None
    if session is not None and hasattr(session, "create_message"):
        try:
            from mcp.types import SamplingMessage, TextContent

            result = await session.create_message(
                messages=[
                    SamplingMessage(
                        role="user",
                        content=TextContent(type="text", text=raw_input),
                    )
                ],
                max_tokens=300,
                system_prompt=AI_QUERY_PLANNER_SYSTEM_PROMPT,
                temperature=0.1,
            )
            content = getattr(result, "content", None)
            if isinstance(content, list) and content:
                content = content[0]
            ai_text = getattr(content, "text", None)
            if isinstance(ai_text, str):
                sampled_plan = parse_ai_query_json(ai_text, original_input=raw_input)
                if sampled_plan is not None:
                    return sampled_plan
        except Exception:
            # Client may not support MCP Sampling; fall back cleanly without failing search
            pass

    return plan
