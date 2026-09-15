"""Offline `demo` provider — zero configuration, zero cost, zero network.

It is a *real* reviewer, not a stub: it runs the static rule engine plus
structural metrics over the submitted code and renders the result in the same
contract the LLM agents produce. This guarantees the product works out of the
box and gives a deterministic baseline to compare model output against.

Findings it produces are marked `source: "static"` so the UI can be honest
about provenance.
"""
from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator, Dict, List

from ..analysis.heuristics import (
    SEVERITY_WEIGHT,
    ScanResult,
    scan_code,
    summarise_findings,
)
from ..analysis.languages import detect_language
from .base import ChatMessage, CompletionResult, LLMProvider, ModelSpec

MODELS = [
    ModelSpec("static-rules-v1", "Static rule engine (offline)", 1_000_000, True, True, True, 8192),
]

_SYSTEM_MARKERS = ("expert AI code reviewer", "## Code Quality")


class DemoProvider(LLMProvider):
    id = "demo"
    label = "Offline static engine (no API key)"
    docs_url = ""
    requires_key = False
    models = MODELS

    def __init__(self, api_key: str | None = None, base_url: str | None = None, timeout: float = 30.0):
        super().__init__(api_key=None, base_url=None, timeout=timeout)

    def is_configured(self) -> bool:
        return True

    # ------------------------------------------------------------------
    async def complete(
        self,
        messages: List[ChatMessage],
        *,
        model: str = MODELS[0].id,
        temperature: float = 0.2,
        max_tokens: int = 4096,
        json_mode: bool = False,
        **kwargs: Any,
    ) -> CompletionResult:
        payload = kwargs.get("context") or {}
        code = payload.get("code") or self._code_from_messages(messages)
        path = payload.get("path") or "input"
        focus = payload.get("focus_lines")

        await asyncio.sleep(0.05)  # keep the UI's progressive pipeline honest

        scan = scan_code(code, path=path, focus_lines=focus,
                         include_categories=payload.get("categories") or None)
        language = detect_language(code, path)

        if payload.get("task") == "summary":
            text = _render_summary(scan, code, path, language)
        elif payload.get("task") == "chat":
            text = _render_chat(payload.get("question", ""), scan, code, path)
        else:
            text = _render_review_json(scan, code, path, language)

        return CompletionResult(
            text=text,
            model=model,
            provider=self.id,
            prompt_tokens=len(code) // 4,
            completion_tokens=len(text) // 4,
            latency_ms=50,
            attempts=1,
            raw={"offline": True, "static_findings": len(scan.findings)},
        )

    async def stream(self, messages, **kwargs) -> AsyncIterator[str]:  # type: ignore[override]
        result = await self.complete(messages, **kwargs)
        for chunk in _chunk(result.text, 240):
            yield chunk
            await asyncio.sleep(0.01)

    # ------------------------------------------------------------------
    @staticmethod
    def _code_from_messages(messages: List[ChatMessage]) -> str:
        """Recover the code under review from the prompt when context is absent."""
        for message in reversed(messages):
            if message.role != "user":
                continue
            fenced = _extract_fences(message.content)
            if fenced:
                return fenced
            return message.content
        return ""


def _extract_fences(text: str) -> str:
    import re

    blocks = re.findall(r"```[\w+-]*\n(.*?)```", text, re.DOTALL)
    return "\n".join(blocks).strip()


def _chunk(text: str, size: int) -> List[str]:
    return [text[i : i + size] for i in range(0, len(text), size)] or [""]


# ----------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------
def _render_review_json(scan: ScanResult, code: str, path: str, language: str) -> str:
    import json

    metrics = next(iter(scan.metrics.values()), None)
    findings = [_finding_dict(f) for f in scan.findings[:40]]
    score = _score(scan, metrics)

    narrative = {
        "summary": _narrative_summary(scan, metrics, language, path),
        "overall_assessment": _assessment(score),
        "score": score,
        "findings": findings,
        "positives": _positives(scan, code, metrics),
        "test_recommendations": _test_recs(scan, language),
        "metrics": metrics.to_dict() if metrics else {},
        "pre_scan_hints": summarise_findings(scan.findings),
    }
    return json.dumps(narrative, indent=2, default=list)


def _finding_dict(finding) -> Dict[str, Any]:
    data = finding.to_dict()
    data["source"] = "static"
    data["confidence"] = finding.confidence
    data["line_comment"] = (
        f"**{finding.severity.upper()} — {finding.title}** (line {finding.line})\n\n"
        f"{finding.description}\n\n"
        f"**Suggested fix:** {finding.suggestion}"
        + (f"\n\n```suggestion\n{finding.code_after}\n```" if finding.code_after else "")
    )
    return data


def _score(scan: ScanResult, metrics) -> int:
    penalty = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in scan.findings)
    score = 100 - penalty // 4
    if metrics and metrics.longest_function > 80:
        score -= 5
    if metrics and metrics.max_nesting > 6:
        score -= 5
    return max(5, min(100, score))


def _assessment(score: int) -> str:
    if score >= 90:
        return "approve"
    if score >= 75:
        return "approve_with_nits"
    if score >= 55:
        return "request_changes"
    return "block"


def _narrative_summary(scan: ScanResult, metrics, language: str, path: str) -> str:
    counts = scan.by_severity()
    cats = scan.by_category()
    active = [f"{cats[c]} {c.replace('_', ' ')}" for c in cats if cats[c]]
    lines = metrics.lines if metrics else len((path or '').splitlines())
    parts = [
        f"Reviewed `{path}` ({language}, {lines} lines) with the offline static engine.",
        f"Found {len(scan.findings)} issue(s): "
        f"{counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, "
        f"{counts['low']} low, {counts['info']} informational."
        if scan.findings
        else "No rule matched this input — that is a clean bill from the static engine, not a guarantee.",
    ]
    if active:
        parts.append("Breakdown by category: " + ", ".join(active) + ".")
    parts.append(
        "Add a free LLM API key (Groq, Gemini, or OpenRouter) in Settings to get semantic "
        "review — logic errors, naming, and refactoring advice the rule engine cannot infer."
    )
    return " ".join(parts)


def _positives(scan: ScanResult, code: str, metrics) -> List[str]:
    out: List[str] = []
    if metrics and metrics.comment_lines > 0 and metrics.code_lines:
        ratio = metrics.comment_lines / max(1, metrics.code_lines)
        if ratio > 0.08:
            out.append(f"Comment density is healthy ({ratio:.0%} of code lines).")
    if "type: ignore" not in code and metrics and metrics.functions and metrics.longest_function < 50:
        out.append("Functions are short and focused — no function exceeds 50 lines.")
    if not any(f.category == "security" and f.severity in {"critical", "high"} for f in scan.findings):
        out.append("No high-severity security anti-patterns detected by the static rules.")
    if "logging" in code or "logger" in code:
        out.append("Uses a real logger rather than ad-hoc output.")
    return out or ["Structure is straightforward and easy to follow."]


def _test_recs(scan: ScanResult, language: str) -> List[str]:
    recs: List[str] = []
    risky = [f for f in scan.findings if f.severity in {"critical", "high"}]
    for finding in risky[:5]:
        recs.append(
            f"Add a regression test covering `{finding.title}` at line {finding.line} "
            f"({finding.file}) before merging."
        )
    if language == "python":
        recs.append("Add a pytest case for the empty/None input path and one for the overflow/boundary case.")
    elif language in {"javascript", "typescript"}:
        recs.append("Add a test for the rejected-promise path and assert the thrown error type.")
    if not recs:
        recs.append("No high-risk paths detected; smoke-test the happy path and one malformed input.")
    return recs


def _render_summary(scan: ScanResult, code: str, path: str, language: str) -> str:
    import re

    metrics = next(iter(scan.metrics.values()), None)
    symbols = re.findall(r"^\s*(?:async\s+)?(?:def|function|class|func|fn)\s+(\w+)", code, re.MULTILINE)[:14]
    lines = [
        f"## Walkthrough — `{path}`",
        "",
        f"- **Language:** {language}",
        f"- **Size:** {metrics.lines if metrics else len(code.splitlines())} lines, "
        f"{metrics.functions if metrics else 0} functions, {metrics.classes if metrics else 0} classes",
        f"- **Complexity index:** {metrics.complexity if metrics else 1}",
        f"- **Static findings:** {len(scan.findings)}",
        "",
        "### Symbols touched",
    ]
    lines += [f"- `{s}`" for s in symbols] or ["- (none detected)"]
    lines += ["", "### Sequence of operations", "",
              "```mermaid", "flowchart TD", f'  A[Entry: {symbols[0] if symbols else "main"}] --> B[Validate input]',
              "  B --> C{Happy path?}", "  C -->|yes| D[Return result]", "  C -->|no| E[Raise / log error]", "```"]
    return "\n".join(lines)


def _render_chat(question: str, scan: ScanResult, code: str, path: str) -> str:
    lowered = question.lower()
    if any(word in lowered for word in ("security", "vulnerab", "safe", "inject", "xss", "auth", "secret")):
        items = [f for f in scan.findings if f.category == "security"]
        header = "### Security findings"
    elif any(word in lowered for word in ("perf", "slow", "optimi", "memory", "leak", "fast", "efficient")):
        items = [f for f in scan.findings if f.category == "performance"]
        header = "### Performance findings"
    elif any(word in lowered for word in ("correct", "logic", "calculate", "comput", "bug", "error",
                                          "crash", "null", "undefined", "edge", "wrong", "work",
                                          "right", "fail", "break")):
        items = [f for f in scan.findings if f.category == "bug"]
        header = "### Correctness findings"
        if not items:
            # A correctness question deserves the full picture, not a shrug.
            items = [f for f in scan.findings if f.category in {"bug", "security", "performance"}]
            header = "### Correctness-relevant findings"
    elif any(word in lowered for word in ("test", "cover", "spec")):
        items = [f for f in scan.findings if f.severity in {"critical", "high"}]
        header = "### What tests should cover"
    elif any(word in lowered for word in ("style", "clean", "refactor", "name", "readab", "quality")):
        items = [f for f in scan.findings if f.category == "quality"]
        header = "### Code quality findings"
    else:
        items = scan.findings[:12]
        header = "### Findings"
    if not items:
        return (
            f"{header}\n\nThe offline engine found nothing matching that question in `{path}`. "
            "Semantic questions (\"is this logic correct?\", \"how should I name this?\") need an LLM — "
            "add a free Groq or Gemini key in Settings."
        )
    body = "\n".join(
        f"- **L{f.line} · {f.severity} · {f.category}** — {f.title}: {f.suggestion}" for f in items
    )
    return f"{header}\n\n{body}"
