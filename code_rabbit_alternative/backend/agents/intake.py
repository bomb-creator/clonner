"""Intake agent — orients the pipeline before the specialists run.

It produces the facts later passes rely on (language, size, symbols, risk map)
and, importantly, it costs one cheap call. On `quick` effort it is skipped and
replaced by deterministic analysis.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List

from ..analysis.diff import number_source
from ..analysis.languages import detect_language, is_test_file
from .base import AgentContext, BaseAgent

SYMBOL_RE = re.compile(
    r"^\s*(?:export\s+)?(?:public|private|protected|static|async|final|abstract|\s)*"
    r"(?:def|function|func|fn|class|interface|struct|enum|trait|type|const)\s+(\w+)",
    re.MULTILINE,
)


@dataclass
class IntakeReport:
    language: str
    path: str
    lines: int
    symbols: List[str]
    has_tests: bool
    is_test: bool
    risk_areas: List[str]
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


def deterministic_intake(ctx: AgentContext) -> IntakeReport:
    """Zero-cost intake: used for `quick` effort and as a fallback."""
    code = ctx.code or "\n".join(f.get("content", "") for f in ctx.files)
    language = ctx.language or detect_language(code, ctx.path)
    symbols = list(dict.fromkeys(SYMBOL_RE.findall(code)))[:40]

    risk_areas: List[str] = []
    lowered = code.lower()
    if any(token in lowered for token in ("select ", "insert ", "update ", "delete from", "cursor.execute", "query(")):
        risk_areas.append("database access")
    if any(token in lowered for token in ("request.", "req.body", "flask", "fastapi", "@app.route", "express", "http")):
        risk_areas.append("HTTP boundary / untrusted input")
    if any(token in lowered for token in ("password", "token", "secret", "jwt", "session", "auth", "login", "permission")):
        risk_areas.append("authentication & secrets")
    if any(token in lowered for token in ("open(", "os.path", "file", "read(", "write(", "shutil", "fs.")):
        risk_areas.append("filesystem access")
    if any(token in lowered for token in ("subprocess", "os.system", "exec(", "eval(", "spawn", "child_process")):
        risk_areas.append("process/command execution")
    if any(token in lowered for token in ("innerhtml", "document.write", "dangerouslysetinnerhtml", "render(", "template")):
        risk_areas.append("HTML rendering (XSS surface)")
    if any(token in lowered for token in ("thread", "asyncio", "concurrent", "lock", "mutex", "goroutine", "await ")):
        risk_areas.append("concurrency")
    if not risk_areas:
        risk_areas.append("general correctness")

    return IntakeReport(
        language=language,
        path=ctx.path,
        lines=len(code.splitlines()),
        symbols=symbols,
        has_tests=bool(re.search(r"\b(assert|expect|should|pytest|unittest|describe\(|it\()", code)),
        is_test=is_test_file(ctx.path),
        risk_areas=risk_areas[:6],
        notes=f"Static intake: {len(symbols)} symbols, {len(code.splitlines())} lines.",
    )


class IntakeAgent(BaseAgent):
    key = "intake"
    label = "Intake & orientation"
    emoji = "🧭"
    description = "Establishes what the code does, its idioms, and where to look hardest."

    def is_enabled(self, ctx: AgentContext) -> bool:
        return ctx.effort in {"standard", "deep"} and "intake" not in ctx.instructions.lower().split("skip:")[-1]

    def json_mode(self) -> bool:
        return True

    def max_tokens(self, ctx: AgentContext) -> int:
        return 900 if ctx.effort == "quick" else 1400

    def system_prompt(self, ctx: AgentContext) -> str:
        from .prompts import build_system_prompt

        base = build_system_prompt("intake", is_diff=ctx.is_diff, has_prescan=False)
        contract = """
## Output contract for this pass

Respond with ONLY this JSON object:

{
  "purpose": "what this code does, 1-3 sentences",
  "language": "the primary language",
  "framework": "framework/runtime detected, or null",
  "entry_points": ["functions or routes that external callers hit"],
  "public_api": ["symbols that are part of the contract others depend on"],
  "data_flow": "how input becomes output, 1-3 sentences",
  "risk_areas": ["the 2-5 places most likely to hide a defect"],
  "test_surface": ["the cases a test suite must cover"],
  "conventions": ["language/framework conventions this code should follow"],
  "findings": []
}

Be factual. Everything you state must be visible in the code shown.
"""
        return base.split("## Output contract")[0].strip() + "\n\n" + contract.strip()

    def normalise(self, payload, ctx):  # intake never emits findings
        return []
