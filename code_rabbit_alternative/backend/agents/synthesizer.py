"""Synthesizer — the lead reviewer that merges specialist passes.

Deduplicates, verifies line numbers against the real source, resolves severity
conflicts, and writes the top-level verdict. Falls back to deterministic
merging when the LLM is unavailable, so a review is never lost.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Dict, List, Optional

from ..analysis.heuristics import SEVERITY_WEIGHT
from ..models import Finding
from ..providers.base import ChatMessage, ProviderError
from .base import AgentContext, AgentOutcome, BaseAgent, json_dumps
from .prompts import SYNTHESIS_HEADER, build_system_prompt


class SynthesizerAgent(BaseAgent):
    key = "synthesizer"
    label = "Lead reviewer (synthesis)"
    emoji = "⚖️"
    description = "Merges, verifies, de-duplicates and ranks the specialist findings."

    def is_enabled(self, ctx: AgentContext) -> bool:
        return True

    def max_tokens(self, ctx: AgentContext) -> int:
        return {"quick": 1500, "standard": 3500, "deep": 5000}.get(ctx.effort, 3500)

    def system_prompt(self, ctx: AgentContext) -> str:
        return build_system_prompt(
            "synthesizer", max_findings=ctx.max_findings, is_diff=ctx.is_diff, has_prescan=False
        )

    def user_message(self, ctx: AgentContext) -> str:
        findings_json = json_dumps(
            [f.model_dump(include={
                "id", "category", "severity", "title", "description", "file", "line",
                "end_line", "suggestion", "code_before", "code_after", "confidence",
                "agent", "references",
            }) for f in ctx.prior_findings[:80]]
        )
        code_block = ctx.code_block_for_prompt()
        # Keep the merged prompt inside the context window: trim the code if needed.
        budget = 60_000
        if len(code_block) > budget:
            code_block = code_block[:budget] + "\n... [code truncated] ...\n"
        return SYNTHESIS_HEADER.format(findings_json=findings_json, code_block=code_block)

    def normalise(self, payload: Dict[str, Any], ctx: AgentContext) -> List[Finding]:
        return super().normalise(payload, ctx)


def deterministic_merge(findings: List[Finding], *, max_findings: int = 60) -> Dict[str, Any]:
    """Merge without an LLM: dedupe by (file, line, category, title-ish)."""
    if not findings:
        return {
            "summary": "No issues were found in this submission.",
            "overall_assessment": "approve",
            "score": 95,
            "positives": [],
            "test_recommendations": [],
            "findings": [],
        }

    grouped: Dict[str, Finding] = {}
    for finding in findings:
        key = _merge_key(finding)
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = finding.model_copy(deep=True)
            continue
        winner = grouped[key]
        if SEVERITY_WEIGHT.get(finding.severity, 0) > SEVERITY_WEIGHT.get(winner.severity, 0):
            winner.severity = finding.severity
        winner.confidence = max(winner.confidence, finding.confidence)
        if len(finding.description) > len(winner.description):
            winner.description = finding.description
        if finding.code_after and not winner.code_after:
            winner.code_after = finding.code_after
            winner.suggestion = finding.suggestion or winner.suggestion
        winner.references = list(dict.fromkeys([*winner.references, *finding.references]))[:6]
        winner.agent = f"{winner.agent}+{finding.agent}"
        winner.source = "merged"
        winner.upvotes += 1

    merged = sorted(
        grouped.values(),
        key=lambda f: (-SEVERITY_WEIGHT.get(f.severity, 0), -f.confidence, f.file, f.line or 0),
    )[:max_findings]

    counts = defaultdict(int)
    for finding in merged:
        counts[finding.severity] += 1
    penalty = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in merged)
    score = max(5, min(100, 100 - penalty // 3))
    verdict = _verdict_for(score, counts)

    summary = (
        f"Reviewed {len({f.file for f in merged})} file(s) and confirmed {len(merged)} issue(s): "
        f"{counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, "
        f"{counts['low']} low, {counts['info']} informational. "
        f"{'Multiple findings are corroborated by more than one specialist.' if any(f.upvotes for f in merged) else ''}"
    ).strip()

    top = merged[0] if merged else None
    if top:
        summary += f" The most important item is {top.title.lower()} at {top.file}:{top.line or '?'}."

    return {
        "summary": summary,
        "overall_assessment": verdict,
        "score": score,
        "positives": [],
        "test_recommendations": _test_recs(merged),
        "findings": merged,
    }


def _merge_key(finding: Finding) -> str:
    title = re.sub(r"[^a-z0-9]+", " ", finding.title.lower()).strip().split()
    stem = " ".join(title[:4])
    return f"{finding.file}|{finding.line}|{finding.category}|{stem}"


def _verdict_for(score: int, counts: Dict[str, int]) -> str:
    if counts["critical"] > 0:
        return "block"
    if counts["high"] >= 3 or score < 55:
        return "request_changes"
    if score < 80:
        return "request_changes" if counts["high"] else "approve_with_nits"
    return "approve"


def _test_recs(findings: List[Finding]) -> List[str]:
    recs: List[str] = []
    for finding in findings:
        if finding.severity in {"critical", "high"} and len(recs) < 5:
            where = f"{finding.file}:{finding.line}" if finding.line else finding.file
            recs.append(f"Regression test for '{finding.title}' at {where} — assert the failure is handled, not just that the happy path works.")
    if not recs:
        recs.append("Add a test for the empty-input and malformed-input paths.")
    return recs


async def synthesise(
    ctx: AgentContext,
    agent: SynthesizerAgent,
    *,
    prefer_llm: bool = True,
) -> AgentOutcome:
    """Run synthesis, degrading gracefully to the deterministic merge."""
    fallback = deterministic_merge(ctx.prior_findings, max_findings=ctx.max_findings)

    if not prefer_llm or not ctx.prior_findings:
        outcome = AgentOutcome(agent="synthesizer", label=agent.label, status="done")
        outcome.payload = fallback
        outcome.findings = list(fallback["findings"])
        outcome.model = "deterministic-merge"
        outcome.provider = "local"
        return outcome

    outcome = await agent.run(ctx)
    if outcome.error or not outcome.payload:
        merged = AgentOutcome(agent="synthesizer", label=agent.label, status="done")
        merged.payload = fallback
        merged.findings = list(fallback["findings"])
        merged.model = "deterministic-merge"
        merged.provider = "local"
        if outcome.error:
            merged.error = f"LLM synthesis unavailable ({outcome.error[:160]}); used deterministic merge."
        return merged

    payload = outcome.payload
    llm_findings = outcome.findings

    # Always keep specialist findings the model silently dropped, unless it
    # explicitly verified them out. Union is safer than trusting the merge alone.
    seen = {_normalise_title(f.title) for f in llm_findings}
    for finding in ctx.prior_findings:
        if _normalise_title(finding.title) not in seen:
            finding.source = "llm" if finding.source == "llm" else finding.source
            llm_findings.append(finding)
    llm_findings = _dedupe(llm_findings)[: ctx.max_findings]
    outcome.findings = llm_findings

    counts = defaultdict(int)
    for finding in llm_findings:
        counts[finding.severity] += 1
    score = payload.get("score")
    try:
        score = int(score)
    except (TypeError, ValueError):
        score = None
    if score is None or not 0 <= score <= 100:
        penalty = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in llm_findings)
        score = max(5, min(100, 100 - penalty // 3))
    payload["score"] = score
    payload.setdefault("summary", fallback["summary"])
    if payload.get("overall_assessment") not in {"approve", "approve_with_nits", "request_changes", "block"}:
        payload["overall_assessment"] = _verdict_for(score, counts)
    payload.setdefault("test_recommendations", fallback["test_recommendations"])
    payload.setdefault("positives", [])
    return outcome


def _normalise_title(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (title or "").lower()).strip()[:60]


def _dedupe(findings: List[Finding]) -> List[Finding]:
    seen: Dict[str, Finding] = {}
    for finding in findings:
        key = _merge_key(finding)
        if key in seen:
            existing = seen[key]
            existing.confidence = max(existing.confidence, finding.confidence)
            if SEVERITY_WEIGHT.get(finding.severity, 0) > SEVERITY_WEIGHT.get(existing.severity, 0):
                existing.severity = finding.severity
            if len(finding.description) > len(existing.description):
                existing.description = finding.description
            continue
        seen[key] = finding
    return sorted(
        seen.values(),
        key=lambda f: (-SEVERITY_WEIGHT.get(f.severity, 0), -f.confidence, f.file, f.line or 0),
    )
