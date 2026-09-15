"""Agent base class and shared context.

Every agent follows the same lifecycle:
    build messages -> call provider -> parse JSON -> normalise findings

Findings are validated against the real code before they are accepted, so a
hallucinated line number cannot reach the UI.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from ..analysis.diff import DiffSet, FileDiff, number_source
from ..analysis.heuristics import CATEGORIES, SEVERITIES, ScanResult
from ..analysis.languages import detect_language
from ..models import Finding
from ..providers.base import ChatMessage, CompletionResult, LLMProvider, ProviderError
from ..utils.jsonrepair import coerce_findings, extract_json
from .prompts import (
    CODE_HEADER,
    DIFF_HEADER,
    EXTRA_INSTRUCTIONS,
    PRESCAN_HEADER,
    build_system_prompt,
)

MAX_CODE_CHARS = 90_000          # ~25k tokens, safe for 32k-context free models
TRUNCATION_NOTE = "\n... [input truncated to fit the model context window] ...\n"


@dataclass
class AgentContext:
    """Everything an agent needs to review a submission."""

    code: str = ""
    path: str = "input"
    language: str = "plaintext"
    files: List[Dict[str, str]] = field(default_factory=list)
    diffset: Optional[DiffSet] = None
    diff_text: str = ""
    is_diff: bool = False
    focus_lines: Optional[set] = None
    prescan: Optional[ScanResult] = None
    instructions: str = ""
    effort: str = "standard"
    categories: Sequence[str] = CATEGORIES
    max_findings: int = 40
    prior_findings: List[Finding] = field(default_factory=list)
    max_line_by_file: Dict[str, int] = field(default_factory=dict)

    def numbered_code(self, limit: int = MAX_CODE_CHARS) -> str:
        if self.is_diff:
            trimmed = self.diff_text[:limit]
            return trimmed + (TRUNCATION_NOTE if len(self.diff_text) > limit else "")
        if self.files:
            blocks = []
            for entry in self.files:
                path = entry.get("path", "input")
                content = entry.get("content", "")
                blocks.append(f"### {path}\n{number_source(content)}")
            joined = "\n\n".join(blocks)
            return joined[:limit] + (TRUNCATION_NOTE if len(joined) > limit else "")
        numbered = number_source(self.code)
        return numbered[:limit] + (TRUNCATION_NOTE if len(numbered) > limit else "")

    def scope_note(self) -> str:
        if self.is_diff:
            return (
                "This is a DIFF. Review only added/modified lines; the numbered "
                "listing shows the new-file line numbers."
            )
        if self.focus_lines:
            return "Focus on the changed lines listed below; the rest is context."
        return "Review the whole file."

    def code_block_for_prompt(self) -> str:
        if self.is_diff:
            return DIFF_HEADER.format(
                files_note=f"{len(self.diffset.files) if self.diffset else 1} file(s) in this diff",
                diff=self.numbered_code(),
            )
        return CODE_HEADER.format(
            path=self.path,
            language=self.language,
            scope_note=self.scope_note(),
            numbered_code=self.numbered_code(),
        )

    def prescan_block(self) -> str:
        if not self.prescan or not self.prescan.findings:
            return ""
        from ..analysis.heuristics import summarise_findings

        return PRESCAN_HEADER.format(hints=summarise_findings(self.prescan.findings))

    def instructions_block(self) -> str:
        return EXTRA_INSTRUCTIONS.format(instructions=self.instructions) if self.instructions else ""

    def user_message(self, extra: str = "") -> str:
        parts = [self.code_block_for_prompt()]
        prescan = self.prescan_block()
        if prescan:
            parts.append(prescan)
        if self.instructions:
            parts.append(self.instructions_block())
        if extra:
            parts.append(extra)
        return "\n\n".join(p for p in parts if p)


@dataclass
class AgentOutcome:
    agent: str
    label: str
    findings: List[Finding] = field(default_factory=list)
    payload: Dict[str, Any] = field(default_factory=dict)
    raw_text: str = ""
    model: str = ""
    provider: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    duration_ms: int = 0
    attempts: int = 1
    error: str = ""
    status: str = "done"

    @property
    def ok(self) -> bool:
        return not self.error


class BaseAgent:
    """A single specialist reviewer."""

    key: str = "base"
    label: str = "Base agent"
    category: Optional[str] = None      # if set, findings are forced into it
    emoji: str = "🤖"
    description: str = ""

    def __init__(self, provider: LLMProvider, model: str, temperature: float = 0.2):
        self.provider = provider
        self.model = model
        self.temperature = temperature

    # -- hooks ----------------------------------------------------------
    def is_enabled(self, ctx: AgentContext) -> bool:
        if self.category and self.category not in ctx.categories:
            return False
        return True

    def system_prompt(self, ctx: AgentContext) -> str:
        return build_system_prompt(
            self.key,
            max_findings=ctx.max_findings,
            is_diff=ctx.is_diff,
            has_prescan=bool(ctx.prescan and ctx.prescan.findings),
        )

    def user_message(self, ctx: AgentContext) -> str:
        return ctx.user_message()

    def json_mode(self) -> bool:
        return True

    def max_tokens(self, ctx: AgentContext) -> int:
        return {"quick": 1500, "standard": 3000, "deep": 4500}.get(ctx.effort, 3000)

    def temperature_for(self, ctx: AgentContext) -> float:
        # Deterministic for security/bugs, slightly more open for quality advice.
        base = self.temperature
        if self.key in {"security", "bugs"}:
            base = min(base, 0.15)
        return base

    # -- execution ------------------------------------------------------
    async def run(self, ctx: AgentContext) -> AgentOutcome:
        started = time.perf_counter()
        outcome = AgentOutcome(agent=self.key, label=self.label, model=self.model,
                               provider=getattr(self.provider, "id", "?"))
        if not self.is_enabled(ctx):
            outcome.status = "skipped"
            return outcome

        messages = [
            ChatMessage(role="system", content=self.system_prompt(ctx)),
            ChatMessage(role="user", content=self.user_message(ctx)),
        ]
        try:
            result: CompletionResult = await self.provider.complete(
                messages,
                model=self.model,
                temperature=self.temperature_for(ctx),
                max_tokens=self.max_tokens(ctx),
                json_mode=self.json_mode(),
                context=self._provider_context(ctx),
            )
        except ProviderError as exc:
            outcome.error = str(exc)
            outcome.status = "error"
            outcome.duration_ms = int((time.perf_counter() - started) * 1000)
            return outcome
        except TypeError:
            # providers that do not accept the `context` kwarg (e.g. a custom one)
            try:
                result = await self.provider.complete(
                    messages, model=self.model, temperature=self.temperature_for(ctx),
                    max_tokens=self.max_tokens(ctx), json_mode=self.json_mode(),
                )
            except ProviderError as exc:
                outcome.error = str(exc)
                outcome.status = "error"
                outcome.duration_ms = int((time.perf_counter() - started) * 1000)
                return outcome
        except Exception as exc:  # noqa: BLE001 - surfaced in the UI, never crashes a review
            outcome.error = f"{type(exc).__name__}: {exc}"
            outcome.status = "error"
            outcome.duration_ms = int((time.perf_counter() - started) * 1000)
            return outcome

        outcome.raw_text = result.text
        outcome.model = result.model or self.model
        outcome.provider = result.provider or outcome.provider
        outcome.prompt_tokens = result.prompt_tokens
        outcome.completion_tokens = result.completion_tokens
        outcome.attempts = result.attempts
        outcome.duration_ms = int((time.perf_counter() - started) * 1000)

        payload = self.parse(result.text)
        outcome.payload = payload if isinstance(payload, dict) else {"findings": payload}
        outcome.findings = self.normalise(outcome.payload, ctx)
        return outcome

    def _provider_context(self, ctx: AgentContext) -> Dict[str, Any]:
        """Side-channel for providers that analyse locally (the offline engine).

        `category` tells a local engine which dimension THIS agent owns, so it
        reports only its own findings instead of the whole scan five times over.
        """
        categories = [self.category] if self.category else list(ctx.categories)
        return {
            "task": "review",
            "code": ctx.code if not ctx.is_diff else _diff_as_code(ctx),
            "path": ctx.path,
            "language": ctx.language,
            "focus_lines": sorted(ctx.focus_lines) if ctx.focus_lines else None,
            "categories": categories,
        }

    # -- parsing --------------------------------------------------------
    def parse(self, text: str) -> Any:
        data = extract_json(text)
        if data is None:
            # Not JSON — keep the prose so the synthesizer can still use it.
            return {"findings": [], "prose": text.strip()[:4000]}
        return data

    def normalise(self, payload: Dict[str, Any], ctx: AgentContext) -> List[Finding]:
        raw_items = coerce_findings(payload)
        findings: List[Finding] = []
        seen = set()

        for index, item in enumerate(raw_items):
            finding = _to_finding(item, ctx, agent=self.key, index=index,
                                  forced_category=self.category)
            if finding is None:
                continue
            key = finding.merge_key()
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)

        findings.sort(key=lambda f: (-_sev_rank(f.severity), f.line or 0))
        return findings[: ctx.max_findings]


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _sev_rank(severity: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(severity, 0)


def _diff_as_code(ctx: AgentContext) -> str:
    """Added lines only, so the offline engine can scan a diff like source."""
    if not ctx.diffset:
        return ctx.code
    chunks = []
    for file_diff in ctx.diffset.files:
        added = [text for _, text in file_diff.added]
        if added:
            chunks.append("\n".join(added))
    return "\n".join(chunks)


def _valid_file(path: Optional[str], ctx: AgentContext) -> str:
    """Map a model-supplied path onto a file we actually know about."""
    if not path:
        return ctx.path
    candidates = list(ctx.max_line_by_file)
    if ctx.path not in candidates:
        candidates.append(ctx.path)
    if path in candidates:
        return path
    lowered = path.strip().lstrip("./")
    for candidate in candidates:
        if candidate == lowered or candidate.endswith("/" + lowered) or lowered.endswith("/" + candidate):
            return candidate
    # tolerate a bare filename when only one file is under review
    if len(candidates) == 1:
        return candidates[0]
    return ctx.path


def _clamp_line(value: Any, file_path: str, ctx: AgentContext) -> Optional[int]:
    try:
        line = int(value)
    except (TypeError, ValueError):
        return None
    if line < 1:
        return None
    limit = ctx.max_line_by_file.get(file_path, 0)
    if limit and line > limit + 5:      # small slack for diffs
        return None
    return line


def _to_finding(item: Dict[str, Any], ctx: AgentContext, *, agent: str, index: int,
                forced_category: Optional[str] = None) -> Optional[Finding]:
    title = str(item.get("title") or item.get("issue") or item.get("name") or "").strip()
    description = str(
        item.get("description") or item.get("explanation") or item.get("details")
        or item.get("why") or item.get("message") or ""
    ).strip()
    if not title and not description:
        return None
    if not title:
        title = description.split(".")[0][:70]
    if not description:
        description = title

    file_path = _valid_file(item.get("file") or item.get("filename") or item.get("path"), ctx)
    line = _clamp_line(item.get("line") or item.get("line_number") or item.get("start_line"), file_path, ctx)
    end_line = _clamp_line(item.get("end_line") or item.get("stop_line"), file_path, ctx)
    if end_line and line and end_line < line:
        line, end_line = end_line, line
    if end_line is None:
        end_line = line

    category = str(item.get("category") or item.get("type") or "").strip().lower().replace("-", "_")
    if category in {"bugs", "logic", "correctness", "logic_error"}:
        category = "bug"
    if category in {"security_vulnerability", "vulnerability", "sec"}:
        category = "security"
    if category in {"code_quality", "smell", "maintainability", "style"}:
        category = "quality"
    if category in {"perf", "efficiency", "optimization"}:
        category = "performance"
    if category in {"practices", "conventions", "error_handling", "testing"}:
        category = "best_practices"
    if category not in CATEGORIES:
        category = forced_category or "quality"
    if forced_category:
        category = forced_category

    severity = str(item.get("severity") or item.get("priority") or "").strip().lower()
    if severity in {"blocker", "urgent", "p0", "severe", "critical_issue"}:
        severity = "critical"
    if severity in {"error", "major", "p1", "serious", "warning"}:
        severity = "high"
    if severity in {"warn", "moderate", "p2", "normal"}:
        severity = "medium"
    if severity in {"minor", "nit", "suggestion", "p3", "trivial", "style"}:
        severity = "low"
    if severity in {"note", "information", "fyi", "info_only"}:
        severity = "info"
    if severity not in SEVERITIES:
        severity = "medium"

    try:
        confidence = float(item.get("confidence", 0.8))
    except (TypeError, ValueError):
        confidence = 0.8
    confidence = max(0.0, min(1.0, confidence))

    references = item.get("references") or item.get("cwe") or []
    if isinstance(references, str):
        references = [r.strip() for r in re.split(r"[,\s]+", references) if r.strip()]
    references = [str(r) for r in references if isinstance(r, (str, int))][:6]

    snippet = str(item.get("snippet") or item.get("context") or "").strip()
    code_before = str(item.get("code_before") or item.get("current_code") or item.get("before") or "").strip()
    code_after = str(item.get("code_after") or item.get("suggested_code") or item.get("fix")
                     or item.get("after") or item.get("code_suggestion") or "").strip()
    suggestion = str(item.get("suggestion") or item.get("recommendation") or item.get("how_to_fix") or "").strip()

    if not snippet and line and ctx.code:
        snippet = _grab_snippet(ctx, file_path, line, end_line or line)

    finding = Finding(
        id=_finding_id(agent, file_path, line, title, index),
        category=category,             # type: ignore[arg-type]
        severity=severity,             # type: ignore[arg-type]
        title=title[:120],
        description=description[:2000],
        file=file_path,
        line=line,
        end_line=end_line,
        suggestion=suggestion[:1200],
        snippet=snippet[:1500],
        code_before=_strip_fences(code_before)[:1200],
        code_after=_strip_fences(code_after)[:1500],
        confidence=round(confidence, 2),
        source="llm",
        agent=agent,
        references=[str(r) for r in references],
    )
    finding.line_comment = build_line_comment(finding)
    return finding


def _grab_snippet(ctx: AgentContext, file_path: str, line: int, end_line: int) -> str:
    source = ctx.code
    if ctx.files:
        for entry in ctx.files:
            if entry.get("path") == file_path:
                source = entry.get("content", "")
                break
    elif ctx.diffset:
        file_diff: Optional[FileDiff] = ctx.diffset.file(file_path)
        if file_diff:
            source = "\n".join(text for _, text in file_diff.added)
    if not source:
        return ""
    lines = source.splitlines()
    low = max(0, line - 2)
    high = min(len(lines), (end_line or line) + 1)
    return "\n".join(f"{n + 1:>5} | {lines[n]}" for n in range(low, high))


def _strip_fences(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```[\w+-]*\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    return stripped.strip()


def _finding_id(agent: str, file_path: str, line: Optional[int], title: str, index: int) -> str:
    digest = hashlib.sha1(f"{agent}|{file_path}|{line}|{title}|{index}".encode()).hexdigest()[:10]
    return f"{agent}-{digest}"


def build_line_comment(finding: Finding) -> str:
    """Markdown body for an inline PR comment (GitHub-ready)."""
    badge = {
        "critical": "🔴 CRITICAL", "high": "🟠 HIGH", "medium": "🟡 MEDIUM",
        "low": "🔵 LOW", "info": "⚪ INFO",
    }.get(finding.severity, finding.severity.upper())
    category = finding.category.replace("_", " ").title()

    parts = [f"**{badge} · {category} — {finding.title}**", "", finding.description]
    if finding.suggestion:
        parts += ["", f"**Suggested fix:** {finding.suggestion}"]
    if finding.code_after:
        lang = _lang_hint(finding.file)
        parts += ["", f"```suggestion\n{finding.code_after}\n```" if lang == "" else f"```{lang}\n{finding.code_after}\n```"]
    if finding.references:
        parts += ["", "Refs: " + ", ".join(finding.references)]
    parts += ["", f"<sub>confidence {finding.confidence:.0%} · {finding.agent} agent</sub>"]
    return "\n".join(parts)


def _lang_hint(path: str) -> str:
    from ..analysis.languages import language_for_path

    language = language_for_path(path)
    return "" if language == "plaintext" else language


def json_dumps(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)
