"""Summarizer — the PR walkthrough, mermaid diagram and merge checklist."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..models import Finding
from .base import AgentContext, AgentOutcome, BaseAgent
from .prompts import build_system_prompt

CHECKLIST_TEMPLATE = [
    "Tests cover the new/changed behaviour, including failure paths",
    "No secrets, credentials or PII added to the repository",
    "Database migrations are reversible and tested against production-shaped data",
    "Error paths are logged with enough context to debug an incident",
    "Public API changes are backwards compatible or versioned",
    "Feature is behind a flag if the rollout needs to be reversible",
]


class SummarizerAgent(BaseAgent):
    key = "summarizer"
    label = "Walkthrough & summary"
    emoji = "📝"
    description = "Writes the PR description, sequence diagram and merge checklist."

    def is_enabled(self, ctx: AgentContext) -> bool:
        return ctx.effort != "quick"

    def json_mode(self) -> bool:
        return True

    def max_tokens(self, ctx: AgentContext) -> int:
        return 1800

    def system_prompt(self, ctx: AgentContext) -> str:
        base = build_system_prompt("summarizer", is_diff=ctx.is_diff, has_prescan=False)
        # The summarizer writes prose, not findings: swap in its own contract.
        return base.split("## Output contract")[0].strip() + "\n\n---\n\n" + \
            build_system_prompt("summarizer").split("## Your focus for this pass: PR WALKTHROUGH AND SUMMARY")[-1].split("## Output contract")[0].strip()

    def user_message(self, ctx: AgentContext) -> str:
        code_block = ctx.code_block_for_prompt()
        budget = 45_000
        if len(code_block) > budget:
            code_block = code_block[:budget] + "\n... [truncated] ...\n"
        confirmed = ""
        if ctx.prior_findings:
            lines = [
                f"- {f.severity}/{f.category} @ {f.file}:{f.line or '?'} — {f.title}"
                for f in ctx.prior_findings[:25]
            ]
            confirmed = "\n\n## Findings the review confirmed (reference these where relevant)\n\n" + "\n".join(lines)
        return code_block + confirmed

    def normalise(self, payload, ctx):  # summarizer emits prose, not findings
        return []


def deterministic_summary(ctx: AgentContext, findings: List[Finding]) -> Dict[str, Any]:
    """Fallback walkthrough built from static facts — always available."""
    code = ctx.code or "\n".join(f.get("content", "") for f in ctx.files)
    lines = code.splitlines()
    symbols = re.findall(
        r"^\s*(?:async\s+)?(?:def|function|func|fn|class|interface|struct|enum)\s+(\w+)",
        code, re.MULTILINE,
    )[:12]

    if ctx.is_diff and ctx.diffset:
        head = f"Changed {len(ctx.diffset.files)} file(s): +{ctx.diffset.additions} / -{ctx.diffset.deletions}."
        files = "\n".join(f"- `{f.path}` (+{f.additions}/-{f.deletions})" for f in ctx.diffset.files[:15])
        walkthrough = f"## Walkthrough\n\n{head}\n\n{files}\n"
    else:
        walkthrough = (
            f"## Walkthrough\n\nReviewed `{ctx.path}` ({ctx.language}, {len(lines)} lines).\n\n"
            f"**Symbols:** {', '.join(f'`{s}`' for s in symbols) or 'none detected'}\n"
        )

    if findings:
        by_sev: Dict[str, int] = {}
        for finding in findings:
            by_sev[finding.severity] = by_sev.get(finding.severity, 0) + 1
        order = [s for s in ("critical", "high", "medium", "low", "info") if by_sev.get(s)]
        walkthrough += "\n**Issues:** " + ", ".join(f"{by_sev[s]} {s}" for s in order) + ".\n"
        top = findings[0]
        walkthrough += (
            f"\nHighest priority: **{top.title}** at `{top.file}:{top.line or '?'}` — {top.description[:220]}\n"
        )

    diagram = _fallback_diagram(ctx, symbols)
    risk_areas = [
        f"`{f.file}:{f.line}` — {f.title}" for f in findings if f.severity in {"critical", "high"}
    ][:4] or ["No high-risk paths detected by static analysis."]

    return {
        "title": _title_for(ctx, symbols),
        "walkthrough": walkthrough,
        "sequence_diagram": diagram,
        "risk_areas": risk_areas,
        "checklist": CHECKLIST_TEMPLATE,
        "changelog_entry": _changelog_for(ctx, symbols),
    }


def _title_for(ctx: AgentContext, symbols: List[str]) -> str:
    if ctx.diffset and ctx.diffset.files:
        first = ctx.diffset.files[0].path
        extra = len(ctx.diffset.files) - 1
        return f"Update {first}" + (f" and {extra} other file(s)" if extra > 0 else "")
    if symbols:
        return f"Changes to {symbols[0]}"
    return f"Review of {ctx.path}"


def _changelog_for(ctx: AgentContext, symbols: List[str]) -> str:
    scope = symbols[0] if symbols else ctx.path
    return f"- `{scope}`: reviewed; see PR for fix list."


def _fallback_diagram(ctx: AgentContext, symbols: List[str]) -> str:
    entry = symbols[0] if symbols else "main"
    rest = symbols[1:4]
    lines = ["sequenceDiagram", "    participant C as Caller", f"    participant {entry} as {entry}()"]
    for symbol in rest:
        lines.append(f"    participant {symbol} as {symbol}()")
    lines.append(f"    C->>{entry}: invoke(input)")
    for symbol in rest:
        lines.append(f"    {entry}->>{symbol}: delegate()")
        lines.append(f"    {symbol}-->>{entry}: result")
    lines.append(f"    {entry}-->>C: response")
    return "\n".join(lines)


async def summarise(
    ctx: AgentContext,
    agent: SummarizerAgent,
    findings: List[Finding],
    *,
    prefer_llm: bool = True,
) -> AgentOutcome:
    fallback = deterministic_summary(ctx, findings)
    if not prefer_llm or not agent.is_enabled(ctx):
        return AgentOutcome(
            agent="summarizer", label=agent.label, status="done",
            payload=fallback, model="deterministic-summary", provider="local",
        )

    ctx_for_summary = AgentContext(**{**ctx.__dict__, "prior_findings": findings})
    outcome = await agent.run(ctx_for_summary)
    if outcome.error or not outcome.payload or "walkthrough" not in outcome.payload:
        outcome.payload = fallback
        outcome.status = "done"
        outcome.model = outcome.model or "deterministic-summary"
        if outcome.error:
            outcome.payload = {**fallback, "_note": f"LLM summary unavailable ({outcome.error[:120]})"}
            outcome.error = ""
        return outcome

    payload = outcome.payload
    payload.setdefault("title", fallback["title"])
    payload.setdefault("sequence_diagram", fallback["sequence_diagram"])
    payload.setdefault("risk_areas", fallback["risk_areas"])
    payload.setdefault("changelog_entry", fallback["changelog_entry"])
    payload["checklist"] = _merge_checklist(payload.get("checklist"))
    # strip accidental fences from the mermaid source
    diagram = str(payload.get("sequence_diagram") or "")
    payload["sequence_diagram"] = re.sub(r"^```(?:mermaid)?\s*|\s*```$", "", diagram.strip(), flags=re.MULTILINE).strip()
    return outcome


def _merge_checklist(items: Optional[List[Any]]) -> List[str]:
    out: List[str] = []
    for item in (items or []):
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
    for item in CHECKLIST_TEMPLATE:
        if item not in out:
            out.append(item)
    return out[:12]
