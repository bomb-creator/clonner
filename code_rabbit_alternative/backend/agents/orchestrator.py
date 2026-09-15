"""Review orchestrator.

Pipeline:
    1. intake        — build context (parse diff / fetch PR / detect language)
    2. pre-scan      — deterministic static analysis (always runs, free)
    3. specialists   — quality / bugs / security / performance / best practices,
                       concurrently, bounded so free-tier rate limits survive
    4. synthesizer   — lead reviewer merges, verifies, ranks, verdicts
    5. summarizer    — walkthrough, mermaid diagram, checklist

Every stage emits progress events so the UI can show the agents working.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional, Sequence

from .. import config
from ..analysis.diff import DiffSet, looks_like_diff, number_source, parse_unified_diff
from ..analysis.heuristics import (
    CATEGORIES,
    SEVERITIES,
    SEVERITY_WEIGHT,
    ScanResult,
    scan_code,
    scan_diff,
)
from ..analysis.languages import detect_language, is_binary_or_ignorable, language_for_path
from ..integrations.github import fetch_pull_request, parse_pr_ref
from ..models import (
    AgentTrace,
    FileMetrics,
    Finding,
    ReviewRequest,
    ReviewResponse,
    Verdict,
)
from ..providers.base import LLMProvider, ProviderError
from ..providers.registry import build_provider
from .base import AgentContext
from .intake import IntakeAgent, deterministic_intake
from .specialists import (
    BestPracticesAgent,
    BugAgent,
    PerformanceAgent,
    QualityAgent,
    SecurityAgent,
    plan_for,
    second_round_prompt,
)
from .summarizer import SummarizerAgent, deterministic_summary, summarise
from .synthesizer import SynthesizerAgent, deterministic_merge, synthesise

AGENT_CLASSES = {
    "quality": QualityAgent,
    "bugs": BugAgent,
    "security": SecurityAgent,
    "performance": PerformanceAgent,
    "best_practices": BestPracticesAgent,
}
EMOJI = {"intake": "🧭", "prescan": "🔍", "synthesizer": "⚖️", "summarizer": "📝"}
MAX_CONCURRENCY = 3          # free tiers rate-limit aggressively
REVIEW_STORE: Dict[str, ReviewResponse] = {}
STORE_LIMIT = 25


@dataclass
class Session:
    request: ReviewRequest
    review_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started: float = field(default_factory=time.perf_counter)
    traces: List[AgentTrace] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    usage: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    provider_id: str = "demo"
    model: str = ""

    def trace(self, agent: str, label: str) -> AgentTrace:
        entry = AgentTrace(agent=agent, label=label, status="pending")
        self.traces.append(entry)
        return entry


# ----------------------------------------------------------------------
# Context building
# ----------------------------------------------------------------------
async def build_context(request: ReviewRequest) -> AgentContext:
    """Turn any supported input shape into one AgentContext."""
    ctx = AgentContext(
        effort=request.effort,
        categories=list(request.categories),
        instructions=request.instructions or "",
        max_findings=request.max_findings,
    )

    # 1. GitHub pull request
    if request.pull_request:
        ref = parse_pr_ref(request.pull_request)
        if not ref:
            raise ProviderError(
                "Could not parse that pull request reference. "
                "Use `owner/repo#123` or a full GitHub PR URL."
            )
        pr = await fetch_pull_request(ref["owner"], ref["repo"], ref["number"])
        if not pr.diff:
            raise ProviderError(
                f"PR {ref['owner']}/{ref['repo']}#{ref['number']} has no reviewable text diff "
                "(it may be empty or contain only binary files)."
            )
        request.diff = pr.diff
        request.instructions = (request.instructions or "") + (
            f"\n\nPull request: \"{pr.title}\" by {pr.author} ({pr.owner}/{pr.repo}#{pr.number}, "
            f"{pr.changed_files} files, +{pr.additions}/-{pr.deletions})."
            + (f"\nAuthor's description:\n{pr.body}" if pr.body else "")
        )
        ctx.path = f"{ref['owner']}/{ref['repo']}#{ref['number']}"

    # 2. Multiple files
    if request.files and not request.diff:
        entries = [
            {"path": f.path, "content": f.content,
             "language": f.language or language_for_path(f.path)}
            for f in request.files
            if f.content and not is_binary_or_ignorable(f.path)
        ]
        if not entries:
            raise ProviderError("No reviewable files were supplied.")
        ctx.files = entries
        ctx.path = entries[0]["path"] if len(entries) == 1 else f"{len(entries)} files"
        combined = "\n\n".join(e["content"] for e in entries)
        ctx.code = combined
        ctx.language = request.language or entries[0]["language"]
        ctx.is_diff = False
        for entry in entries:
            ctx.max_line_by_file[entry["path"]] = len(entry["content"].splitlines())
        return ctx

    # 3. Diff
    raw = request.diff or request.code or ""
    if not raw.strip():
        raise ProviderError("Nothing to review: supply `code`, `diff`, `files`, or `pull_request`.")

    if request.diff or looks_like_diff(raw):
        diffset: DiffSet = parse_unified_diff(raw)
        if not diffset.files:
            raise ProviderError(
                "That diff could not be parsed. Expected a git-style unified diff "
                "with `@@ -a,b +c,d @@` hunk headers."
            )
        ctx.diffset = diffset
        ctx.diff_text = "\n\n".join(f.patch_text() for f in diffset.files)
        ctx.is_diff = True
        ctx.path = diffset.files[0].path if len(diffset.files) == 1 else f"{len(diffset.files)} files changed"
        ctx.language = request.language or language_for_path(diffset.files[0].path)
        added_all = [text for f in diffset.files for _, text in f.added]
        ctx.code = "\n".join(added_all)
        for file_diff in diffset.files:
            ctx.max_line_by_file[file_diff.path] = max(
                [n for n, _ in file_diff.added] or [file_diff.additions or 1]
            )
        if request.focus_changed_lines:
            ctx.focus_lines = {n for f in diffset.files for n, _ in f.added}
        return ctx

    # 4. Plain code
    ctx.code = raw
    ctx.is_diff = False
    ctx.path = request.files[0].path if request.files else "input"
    ctx.language = request.language or detect_language(raw, ctx.path)
    ctx.max_line_by_file[ctx.path] = len(raw.splitlines())
    return ctx


def run_prescan(ctx: AgentContext) -> ScanResult:
    """Deterministic static pass. Always runs: it is free and grounds the LLM."""
    if ctx.is_diff and ctx.diffset:
        return scan_diff(ctx.diffset, include_categories=ctx.categories)
    if ctx.files:
        combined = ScanResult()
        for entry in ctx.files:
            sub = scan_code(entry["content"], path=entry["path"], language=entry.get("language"))
            combined.findings.extend(sub.findings)
            combined.metrics.update(sub.metrics)
        return combined
    return scan_code(ctx.code, path=ctx.path, language=ctx.language,
                     include_categories=ctx.categories)


def prescan_to_findings(scan: ScanResult, ctx: AgentContext) -> List[Finding]:
    """Static hits become real findings (marked `source=static`)."""
    from .base import build_line_comment

    out: List[Finding] = []
    for hit in scan.findings:
        finding = Finding(
            id=f"static-{hit.rule_id}-{hit.file}-{hit.line}",
            category=hit.category,           # type: ignore[arg-type]
            severity=hit.severity,           # type: ignore[arg-type]
            title=hit.title,
            description=hit.description,
            file=hit.file,
            line=hit.line,
            end_line=hit.end_line,
            suggestion=hit.suggestion,
            snippet=hit.snippet,
            code_after=hit.code_after,
            confidence=hit.confidence,
            source="static",
            agent="prescan",
            references=list(hit.references),
        )
        finding.line_comment = build_line_comment(finding)
        out.append(finding)
    return out


# ----------------------------------------------------------------------
# Pipeline
# ----------------------------------------------------------------------
def _event(kind: str, **payload: Any) -> Dict[str, Any]:
    return {"event": kind, **payload}


async def run_pipeline(request: ReviewRequest) -> AsyncIterator[Dict[str, Any]]:
    """Execute a review, yielding progress events. The last event is `done`."""
    session = Session(request=request)
    yield _event("start", review_id=session.review_id, effort=request.effort)

    # ---- resolve provider ------------------------------------------------
    provider_id = request.provider or config.get_provider_id()
    try:
        # Resolved inside the try: an unknown provider id must degrade to the
        # offline engine, not 500 the whole review.
        model = request.model or config.get_model(provider_id)
        provider: LLMProvider = build_provider(
            provider_id,
            api_key=request.api_key or config.get_api_key(provider_id),
            base_url=config.get_base_url(provider_id),
            timeout=float(request.effort == "deep" and 150 or 100),
        )
    except ProviderError as exc:
        session.errors.append(str(exc))
        provider = build_provider("demo")
        provider_id, model = "demo", "static-rules-v1"
        yield _event("log", level="warn", message=f"{exc} — falling back to the offline engine.")

    if provider.requires_key and not provider.is_configured() and provider_id != "demo":
        message = (
            f"{provider_id} is not configured (no API key). Running the offline static "
            "engine instead. Add a free key in Settings for semantic review."
        )
        session.errors.append(message)
        yield _event("log", level="warn", message=message)
        provider = build_provider("demo")
        provider_id, model = "demo", "static-rules-v1"

    session.provider_id = provider_id
    session.model = model
    temperature = config.get_temperature()
    yield _event("provider", provider=provider_id, model=model,
                 offline=(provider_id == "demo"))

    # ---- stage 1: intake -------------------------------------------------
    intake_trace = session.trace("intake", "Intake & context")
    intake_trace.status = "running"
    intake_trace.started_at = time.perf_counter()
    yield _event("agent:start", agent="intake", label="Intake & context", emoji=EMOJI["intake"])

    try:
        ctx = await build_context(request)
    except ProviderError as exc:
        intake_trace.status = "error"
        intake_trace.error = str(exc)
        yield _event("agent:done", agent="intake", status="error", error=str(exc))
        yield _event("error", message=str(exc), review_id=session.review_id)
        return
    except Exception as exc:  # noqa: BLE001
        message = f"{type(exc).__name__}: {exc}"
        intake_trace.status = "error"
        intake_trace.error = message
        yield _event("agent:done", agent="intake", status="error", error=message)
        yield _event("error", message=message, review_id=session.review_id)
        return

    plan = plan_for(request.effort, request.categories)
    ctx.max_findings = min(request.max_findings, plan["max_findings"])
    intake_report = deterministic_intake(ctx)
    ctx.language = intake_report.language

    intake_trace.status = "done"
    intake_trace.finished_at = time.perf_counter()
    intake_trace.duration_ms = int((intake_trace.finished_at - intake_trace.started_at) * 1000)
    yield _event("agent:done", agent="intake", status="done",
                 duration_ms=intake_trace.duration_ms,
                 payload={"language": ctx.language, "lines": intake_report.lines,
                          "symbols": intake_report.symbols[:20],
                          "risk_areas": intake_report.risk_areas,
                          "is_diff": ctx.is_diff, "path": ctx.path})

    # ---- stage 2: deterministic pre-scan --------------------------------
    scan_trace = session.trace("prescan", "Static pre-scan")
    scan_trace.status = "running"
    scan_trace.started_at = time.perf_counter()
    yield _event("agent:start", agent="prescan", label="Static pre-scan", emoji=EMOJI["prescan"])

    scan = run_prescan(ctx)
    ctx.prescan = scan
    static_findings = prescan_to_findings(scan, ctx)
    session.findings.extend(static_findings)

    scan_trace.status = "done"
    scan_trace.finished_at = time.perf_counter()
    scan_trace.duration_ms = int((scan_trace.finished_at - scan_trace.started_at) * 1000)
    scan_trace.findings = len(static_findings)
    scan_trace.provider = "local"
    scan_trace.model = "rule-engine-v1"
    yield _event("agent:done", agent="prescan", status="done",
                 duration_ms=scan_trace.duration_ms, findings=len(static_findings),
                 payload={"by_severity": scan.by_severity(), "by_category": scan.by_category(),
                          "metrics": {k: v.to_dict() for k, v in scan.metrics.items()}})
    yield _event("findings", agent="prescan", findings=[f.model_dump() for f in static_findings[:40]])

    # ---- stage 3: specialists -------------------------------------------
    offline = provider_id == "demo"
    agent_keys: List[str] = list(plan["agents"])
    rounds = 1 if offline else int(plan["rounds"])
    if offline:
        # The offline engine already produced everything it can; one pass is enough.
        agent_keys = agent_keys[:1] if request.effort == "quick" else agent_keys

    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    queue: asyncio.Queue = asyncio.Queue()
    specialist_findings: List[Finding] = []
    round_titles: List[str] = [f.title for f in static_findings]

    async def run_agent(key: str, round_index: int) -> None:
        cls = AGENT_CLASSES[key]
        agent = cls(provider, model, temperature)
        trace = session.trace(
            agent.key if round_index == 0 else f"{agent.key}-r{round_index + 1}",
            f"{agent.label}" + (f" (round {round_index + 1})" if round_index else ""),
        )
        trace.status = "running"
        trace.started_at = time.perf_counter()
        await queue.put(_event("agent:start", agent=trace.agent, label=trace.label,
                               emoji=agent.emoji, category=agent.category,
                               description=agent.description))
        async with semaphore:
            if offline:
                # Offline: the pre-scan already IS this agent's work. Partition it
                # by dimension rather than re-scanning the concatenated diff,
                # which would duplicate findings and lose per-file attribution.
                outcome = offline_agent_outcome(agent, static_findings)
            else:
                local_ctx = ctx
                extra = ""
                if round_index > 0:
                    extra = second_round_prompt(ctx, round_titles)
                    local_ctx = AgentContext(**{**ctx.__dict__})
                outcome = await _run_with_extra(agent, local_ctx, extra)

        trace.status = "error" if outcome.status == "error" else (
            "skipped" if outcome.status == "skipped" else "done")
        trace.finished_at = time.perf_counter()
        trace.duration_ms = int((trace.finished_at - trace.started_at) * 1000)
        trace.findings = len(outcome.findings)
        trace.model = outcome.model
        trace.provider = outcome.provider
        trace.prompt_tokens = outcome.prompt_tokens
        trace.completion_tokens = outcome.completion_tokens
        trace.attempts = outcome.attempts
        trace.error = outcome.error
        trace.output_preview = (outcome.raw_text or "")[:240]

        if outcome.error:
            session.errors.append(f"{agent.label}: {outcome.error}")
            await queue.put(_event("agent:done", agent=trace.agent, status="error",
                                   error=outcome.error, duration_ms=trace.duration_ms))
        else:
            if not offline:
                # Offline findings are already in the session from the pre-scan;
                # adding them again would double every finding.
                specialist_findings.extend(outcome.findings)
            round_titles.extend(f.title for f in outcome.findings)
            session.usage["prompt_tokens"] += outcome.prompt_tokens
            session.usage["completion_tokens"] += outcome.completion_tokens
            session.usage["calls"] += 1
            await queue.put(_event("agent:done", agent=trace.agent, status="done",
                                   findings=len(outcome.findings),
                                   duration_ms=trace.duration_ms,
                                   model=outcome.model,
                                   summary=_payload_summary(outcome.payload),
                                   tokens=outcome.prompt_tokens + outcome.completion_tokens))
            if not offline:
                await queue.put(_event("findings", agent=trace.agent,
                                       findings=[f.model_dump() for f in outcome.findings[:40]]))

    tasks = [asyncio.create_task(run_agent(key, r))
             for r in range(rounds) for key in agent_keys]

    pending = len(tasks)
    while pending:
        event = await queue.get()
        if event["event"] == "agent:done":
            pending -= 1
        yield event

    await asyncio.gather(*tasks, return_exceptions=True)
    session.findings.extend(specialist_findings)

    # ---- stage 4: synthesis ---------------------------------------------
    synth_trace = session.trace("synthesizer", "Lead reviewer (synthesis)")
    synth_trace.status = "running"
    synth_trace.started_at = time.perf_counter()
    yield _event("agent:start", agent="synthesizer", label="Lead reviewer (synthesis)",
                 emoji=EMOJI["synthesizer"])

    ctx.prior_findings = list(session.findings)
    synthesizer = SynthesizerAgent(provider, model, temperature)
    synth_outcome = await synthesise(ctx, synthesizer, prefer_llm=not offline)

    synth_trace.status = "done"
    synth_trace.finished_at = time.perf_counter()
    synth_trace.duration_ms = int((synth_trace.finished_at - synth_trace.started_at) * 1000)
    synth_trace.model = synth_outcome.model
    synth_trace.provider = synth_outcome.provider
    synth_trace.prompt_tokens = synth_outcome.prompt_tokens
    synth_trace.completion_tokens = synth_outcome.completion_tokens
    synth_trace.findings = len(synth_outcome.findings)
    session.usage["prompt_tokens"] += synth_outcome.prompt_tokens
    session.usage["completion_tokens"] += synth_outcome.completion_tokens
    session.usage["calls"] += 1

    final_findings = _finalise(synth_outcome.findings or session.findings, ctx, request)
    payload = synth_outcome.payload or {}
    score = _int_or(payload.get("score"), _score_from(final_findings))
    verdict = _verdict(payload.get("overall_assessment"), score, final_findings)
    summary = str(payload.get("summary") or "").strip() or _fallback_summary(ctx, final_findings)

    yield _event("agent:done", agent="synthesizer", status="done",
                 findings=len(final_findings), duration_ms=synth_trace.duration_ms,
                 payload={"score": score, "verdict": verdict, "summary": summary,
                          "positives": _string_list(payload.get("positives")),
                          "test_recommendations": _string_list(payload.get("test_recommendations"))})

    # ---- stage 5: walkthrough -------------------------------------------
    walkthrough = ""
    diagram = ""
    checklist: List[str] = []
    risk_areas: List[str] = []
    title = ""
    changelog = ""

    if request.include_summary and request.effort != "quick":
        sum_trace = session.trace("summarizer", "Walkthrough & summary")
        sum_trace.status = "running"
        sum_trace.started_at = time.perf_counter()
        yield _event("agent:start", agent="summarizer", label="Walkthrough & summary",
                     emoji=EMOJI["summarizer"])

        summarizer = SummarizerAgent(provider, model, temperature)
        sum_outcome = await summarise(ctx, summarizer, final_findings, prefer_llm=not offline)

        sum_trace.status = "done"
        sum_trace.finished_at = time.perf_counter()
        sum_trace.duration_ms = int((sum_trace.finished_at - sum_trace.started_at) * 1000)
        sum_trace.model = sum_outcome.model
        session.usage["calls"] += 1
        session.usage["prompt_tokens"] += sum_outcome.prompt_tokens
        session.usage["completion_tokens"] += sum_outcome.completion_tokens

        sp = sum_outcome.payload or {}
        walkthrough = str(sp.get("walkthrough") or "")
        diagram = str(sp.get("sequence_diagram") or "")
        checklist = _string_list(sp.get("checklist"))
        risk_areas = _string_list(sp.get("risk_areas"))
        title = str(sp.get("title") or "")
        changelog = str(sp.get("changelog_entry") or "")
        yield _event("agent:done", agent="summarizer", status="done",
                     duration_ms=sum_trace.duration_ms,
                     payload={"title": title, "walkthrough": walkthrough,
                              "sequence_diagram": diagram, "risk_areas": risk_areas,
                              "checklist": checklist, "changelog_entry": changelog})
    else:
        fallback = deterministic_summary(ctx, final_findings)
        walkthrough, diagram = fallback["walkthrough"], fallback["sequence_diagram"]
        checklist, risk_areas = fallback["checklist"], fallback["risk_areas"]
        title, changelog = fallback["title"], fallback["changelog_entry"]

    # ---- assemble --------------------------------------------------------
    response = ReviewResponse(
        id=session.review_id,
        status="partial" if session.errors else "completed",
        verdict=verdict,
        score=score,
        summary=summary,
        walkthrough=walkthrough,
        overall_assessment=summary,
        findings=final_findings,
        positives=_string_list(payload.get("positives")),
        test_recommendations=_string_list(payload.get("test_recommendations")),
        by_severity=_count_by(final_findings, "severity", SEVERITIES),
        by_category=_count_by(final_findings, "category", CATEGORIES),
        by_file=_count_by_file(final_findings),
        metrics=_metrics_list(scan, ctx),
        trace=session.traces,
        usage=dict(session.usage),
        provider=provider_id,
        model=model,
        elapsed_ms=int((time.perf_counter() - session.started) * 1000),
        errors=list(dict.fromkeys(session.errors)),
        stats={
            "title": title,
            "sequence_diagram": diagram,
            "checklist": checklist,
            "risk_areas": risk_areas,
            "changelog_entry": changelog,
            "intake": intake_report.to_dict(),
            "prescan": {"by_severity": scan.by_severity(), "by_category": scan.by_category()},
            "static_findings": len(static_findings),
            "llm_findings": len(specialist_findings),
            "diff_stats": ({"files": len(ctx.diffset.files), "additions": ctx.diffset.additions,
                            "deletions": ctx.diffset.deletions} if ctx.diffset else None),
        },
    )
    response.review_markdown = render_markdown(response, ctx)

    _remember(response)
    yield _event("done", review=response.model_dump())


async def _run_with_extra(agent, ctx: AgentContext, extra: str):
    """Run an agent, optionally appending a second-round instruction."""
    if not extra:
        return await agent.run(ctx)
    original = agent.user_message

    def patched(c: AgentContext) -> str:
        return original(c) + "\n\n" + extra

    agent.user_message = patched  # type: ignore[method-assign]
    try:
        return await agent.run(ctx)
    finally:
        agent.user_message = original  # type: ignore[method-assign]


def offline_agent_outcome(agent, static_findings: Sequence[Finding]) -> "AgentOutcome":
    """Give a specialist its slice of the pre-scan when no LLM is configured.

    The offline engine's findings are already complete and correctly attributed
    per file, so each agent simply claims the dimension it owns. This keeps the
    pipeline's shape (and the UI's agent cards) honest without re-scanning.
    """
    from .base import AgentOutcome

    owned = [f for f in static_findings if f.category == agent.category] if agent.category else list(static_findings)
    return AgentOutcome(
        agent=agent.key,
        label=agent.label,
        findings=owned,
        payload={
            "summary": (
                f"{len(owned)} {agent.category.replace('_', ' ') if agent.category else ''} "
                f"finding(s) from the static rule engine."
                if owned else "No issues found in this dimension."
            ),
            "findings": [],
        },
        model="rule-engine-v1",
        provider="local",
        status="done",
    )


# ----------------------------------------------------------------------
# Post-processing
# ----------------------------------------------------------------------
def _finalise(findings: Sequence[Finding], ctx: AgentContext, request: ReviewRequest) -> List[Finding]:
    """Dedupe, drop out-of-scope items, filter by severity, cap the list."""
    order = {s: i for i, s in enumerate(SEVERITIES)}
    floor = order.get(request.min_severity, len(SEVERITIES) - 1)
    wanted = set(request.categories)

    by_key: Dict[str, Finding] = {}
    for finding in findings:
        if wanted and finding.category not in wanted:
            continue
        if order.get(finding.severity, 0) > floor:
            continue
        if ctx.is_diff and ctx.focus_lines and finding.line and finding.line not in ctx.focus_lines:
            # A diff-scoped review should not comment on untouched lines.
            if finding.source != "static":
                continue
        key = _dedupe_key(finding)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = finding
            continue
        _absorb(existing, finding)

    result = sorted(
        by_key.values(),
        key=lambda f: (-SEVERITY_WEIGHT.get(f.severity, 0), -f.confidence, f.file, f.line or 0),
    )
    return list(result[: request.max_findings])


def _dedupe_key(finding: Finding) -> str:
    import re

    stem = " ".join(re.sub(r"[^a-z0-9]+", " ", finding.title.lower()).split()[:4])
    return f"{finding.file}|{finding.line}|{finding.category}|{stem}"


def _absorb(target: Finding, source: Finding) -> None:
    if SEVERITY_WEIGHT.get(source.severity, 0) > SEVERITY_WEIGHT.get(target.severity, 0):
        target.severity = source.severity
    target.confidence = max(target.confidence, source.confidence)
    if len(source.description) > len(target.description):
        target.description = source.description
    if source.code_after and not target.code_after:
        target.code_after = source.code_after
        target.suggestion = source.suggestion or target.suggestion
    if source.suggestion and not target.suggestion:
        target.suggestion = source.suggestion
    target.references = list(dict.fromkeys([*target.references, *source.references]))[:6]
    if source.agent and source.agent not in target.agent:
        target.agent = f"{target.agent}+{source.agent}"
    target.source = "merged" if target.source != source.source else target.source
    target.upvotes += 1
    from .base import build_line_comment

    target.line_comment = build_line_comment(target)


def _score_from(findings: Sequence[Finding]) -> int:
    penalty = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    return max(5, min(100, 100 - penalty // 4))


def _verdict(raw: Any, score: int, findings: Sequence[Finding]) -> Verdict:
    valid = {"approve", "approve_with_nits", "request_changes", "block"}
    counts = defaultdict(int)
    for finding in findings:
        counts[finding.severity] += 1
    if isinstance(raw, str) and raw.strip().lower() in valid:
        chosen = raw.strip().lower()
        # never let a model approve over a critical finding
        if counts["critical"] and chosen in {"approve", "approve_with_nits"}:
            return "block"
        return chosen  # type: ignore[return-value]
    if counts["critical"]:
        return "block"
    if counts["high"] >= 3 or score < 55:
        return "request_changes"
    if score < 85:
        return "request_changes" if counts["high"] else "approve_with_nits"
    return "approve"


def _int_or(value: Any, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(0, min(100, number))


def _string_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return [str(v).strip() for v in value if isinstance(v, (str, int, float)) and str(v).strip()][:12]


def _count_by(findings: Sequence[Finding], attr: str, keys: Sequence[str]) -> Dict[str, int]:
    counts = defaultdict(int)
    for finding in findings:
        counts[getattr(finding, attr)] += 1
    return {k: counts.get(k, 0) for k in keys}


def _count_by_file(findings: Sequence[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = defaultdict(int)
    for finding in findings:
        counts[finding.file] += 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1])[:30])


def _metrics_list(scan: ScanResult, ctx: AgentContext) -> List[FileMetrics]:
    out: List[FileMetrics] = []
    for path, metrics in scan.metrics.items():
        data = metrics.to_dict()
        data.pop("classes", None)
        try:
            out.append(FileMetrics(**data))
        except Exception:
            continue
    if not out and ctx.code:
        from ..analysis.heuristics import compute_metrics

        metrics = compute_metrics(ctx.code, ctx.path, ctx.language)
        data = metrics.to_dict()
        data.pop("classes", None)
        out.append(FileMetrics(**data))
    return out


def _payload_summary(payload: Dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        return ""
    for key in ("summary", "purpose", "overall_assessment", "prose"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:300]
    return ""


def _fallback_summary(ctx: AgentContext, findings: Sequence[Finding]) -> str:
    if not findings:
        return (
            f"Reviewed `{ctx.path}` ({ctx.language}). No issues met the reporting bar — "
            "the static engine and the specialist passes both came back clean."
        )
    counts = defaultdict(int)
    for finding in findings:
        counts[finding.severity] += 1
    parts = [f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if counts[s]]
    top = findings[0]
    return (
        f"Reviewed `{ctx.path}` ({ctx.language}). Found {len(findings)} issue(s): {', '.join(parts)}. "
        f"Highest priority: {top.title} at {top.file}:{top.line or '?'}."
    )


def _remember(response: ReviewResponse) -> None:
    REVIEW_STORE[response.id] = response
    if len(REVIEW_STORE) > STORE_LIMIT:
        for stale in list(REVIEW_STORE)[:-STORE_LIMIT]:
            REVIEW_STORE.pop(stale, None)


def get_review(review_id: str) -> Optional[ReviewResponse]:
    return REVIEW_STORE.get(review_id)


# ----------------------------------------------------------------------
# Markdown rendering (for copy / download / posting to GitHub)
# ----------------------------------------------------------------------
SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
VERDICT_LABEL = {
    "approve": "✅ Approve",
    "approve_with_nits": "👍 Approve with nits",
    "request_changes": "🔁 Request changes",
    "block": "⛔ Block",
}


def render_markdown(response: ReviewResponse, ctx: Optional[AgentContext] = None) -> str:
    stats = response.stats or {}
    diff_stats = stats.get("diff_stats")
    lines: List[str] = []

    lines.append(f"# Code review — {stats.get('title') or response.id}")
    lines.append("")
    lines.append(
        f"**Verdict:** {VERDICT_LABEL.get(response.verdict, response.verdict)} · "
        f"**Score:** {response.score}/100 · "
        f"**Findings:** {len(response.findings)} · "
        f"**Model:** `{response.provider}` / `{response.model}` · "
        f"**Time:** {response.elapsed_ms / 1000:.1f}s"
    )
    if diff_stats:
        lines.append(
            f"**Diff:** {diff_stats['files']} files, +{diff_stats['additions']} / -{diff_stats['deletions']}"
        )
    lines.append("")

    if response.summary:
        lines += ["## Summary", "", response.summary, ""]

    if response.walkthrough:
        lines += ["## Walkthrough", "", response.walkthrough, ""]

    if stats.get("sequence_diagram"):
        lines += ["## Flow", "", "```mermaid", stats["sequence_diagram"], "```", ""]

    lines += ["## Findings", ""]
    if not response.findings:
        lines += ["No issues found. 🎉", ""]
    else:
        lines += [
            "| # | Severity | Category | Location | Issue |",
            "|---|----------|----------|----------|-------|",
        ]
        for index, finding in enumerate(response.findings, 1):
            location = f"`{finding.file}`" + (f":{finding.line}" if finding.line else "")
            lines.append(
                f"| {index} | {SEV_ICON.get(finding.severity, '')} {finding.severity} "
                f"| {finding.category.replace('_', ' ')} | {location} "
                f"| {_escape_cell(finding.title)} |"
            )
        lines.append("")

        for index, finding in enumerate(response.findings, 1):
            lines += [
                f"### {index}. {SEV_ICON.get(finding.severity, '')} {finding.title}",
                "",
                f"`{finding.file}`" + (f" line {finding.line}" if finding.line else "") +
                f" · {finding.category.replace('_', ' ')} · confidence {finding.confidence:.0%}" +
                (f" · {', '.join(finding.references)}" if finding.references else ""),
                "",
                finding.description,
                "",
            ]
            if finding.snippet:
                lines += ["```", finding.snippet, "```", ""]
            if finding.suggestion:
                lines += [f"**Suggested fix:** {finding.suggestion}", ""]
            if finding.code_after:
                lines += ["```", finding.code_after, "```", ""]

    if response.positives:
        lines += ["## What's done well", ""] + [f"- {p}" for p in response.positives] + [""]
    if response.test_recommendations:
        lines += ["## Test coverage recommendations", ""] + [f"- {t}" for t in response.test_recommendations] + [""]
    if stats.get("risk_areas"):
        lines += ["## Risk areas", ""] + [f"- {r}" for r in stats["risk_areas"]] + [""]
    if stats.get("checklist"):
        lines += ["## Merge checklist", ""] + [f"- [ ] {c}" for c in stats["checklist"]] + [""]

    if response.errors:
        lines += ["## Notes", ""] + [f"- ⚠️ {e}" for e in response.errors] + [""]

    if response.trace:
        lines += ["## Agent trace", "", "| Agent | Status | Findings | Time | Tokens |",
                  "|-------|--------|----------|------|--------|"]
        for trace in response.trace:
            lines.append(
                f"| {trace.label} | {trace.status} | {trace.findings} "
                f"| {trace.duration_ms} ms | {trace.prompt_tokens + trace.completion_tokens} |"
            )
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def _escape_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")
