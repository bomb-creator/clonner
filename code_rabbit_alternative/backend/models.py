"""Pydantic schemas shared by the API, the agents and the frontend."""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
Category = Literal["security", "bug", "quality", "performance", "best_practices"]
Verdict = Literal["approve", "approve_with_nits", "request_changes", "block"]


class FileInput(BaseModel):
    path: str = Field("input", description="File path, used for language detection and comment placement.")
    content: str = Field("", description="Full source of the file.")
    language: Optional[str] = None


class ReviewRequest(BaseModel):
    """One of `code`, `diff`, or `pull_request` must be supplied."""

    code: Optional[str] = Field(None, description="Raw source to review.")
    diff: Optional[str] = Field(None, description="Unified diff / git patch to review.")
    files: List[FileInput] = Field(default_factory=list, description="Multiple files at once.")
    pull_request: Optional[str] = Field(None, description="e.g. owner/repo#123 or a full github PR URL.")

    provider: Optional[str] = Field(None, description="Provider id; falls back to the configured default.")
    model: Optional[str] = None
    api_key: Optional[str] = Field(None, description="Per-request key. Never persisted or logged.")

    effort: Literal["quick", "standard", "deep"] = Field("standard", description="How many agents/rounds to run.")
    categories: List[Category] = Field(
        default_factory=lambda: ["security", "bug", "quality", "performance", "best_practices"],
        description="Which review dimensions to run.",
    )
    focus_changed_lines: bool = Field(True, description="For diffs: only comment on lines the PR touched.")
    include_summary: bool = Field(True, description="Also produce a walkthrough / PR summary.")
    max_findings: int = Field(60, ge=1, le=400)
    min_severity: Severity = Field("info")
    language: Optional[str] = None
    instructions: Optional[str] = Field(None, description="Extra reviewer instructions (style guide, context).")
    stream: bool = Field(True, description="Stream agent progress over SSE.")


class Finding(BaseModel):
    id: str = Field(..., description="Stable id for dedupe/UI keys.")
    category: Category = "quality"
    severity: Severity = "medium"
    title: str
    description: str
    file: str = "input"
    line: Optional[int] = None
    end_line: Optional[int] = None
    suggestion: str = ""
    snippet: str = ""
    code_before: str = ""
    code_after: str = ""
    confidence: float = Field(0.8, ge=0.0, le=1.0)
    source: Literal["llm", "static", "merged"] = "llm"
    agent: str = ""
    references: List[str] = Field(default_factory=list)
    line_comment: str = Field("", description="Markdown ready to post as an inline PR comment.")
    upvotes: int = 0

    def merge_key(self) -> str:
        return f"{self.file}:{self.line}:{self.category}:{self.title.lower()[:40]}"


class AgentTrace(BaseModel):
    agent: str
    label: str
    status: Literal["pending", "running", "done", "error", "skipped"] = "pending"
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    duration_ms: int = 0
    findings: int = 0
    model: str = ""
    provider: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    attempts: int = 1
    error: str = ""
    output_preview: str = ""


class FileMetrics(BaseModel):
    path: str
    language: str = "plaintext"
    lines: int = 0
    code_lines: int = 0
    comment_lines: int = 0
    blank_lines: int = 0
    max_line_length: int = 0
    max_nesting: int = 0
    functions: int = 0
    longest_function: int = 0
    complexity: int = 1
    todo_count: int = 0
    duplicated_blocks: int = 0


class ReviewResponse(BaseModel):
    id: str
    status: Literal["completed", "partial", "failed"] = "completed"
    verdict: Verdict = "request_changes"
    score: int = Field(70, ge=0, le=100)
    summary: str = ""
    walkthrough: str = ""
    overall_assessment: str = ""
    findings: List[Finding] = Field(default_factory=list)
    positives: List[str] = Field(default_factory=list)
    test_recommendations: List[str] = Field(default_factory=list)
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_category: Dict[str, int] = Field(default_factory=dict)
    by_file: Dict[str, int] = Field(default_factory=dict)
    metrics: List[FileMetrics] = Field(default_factory=list)
    trace: List[AgentTrace] = Field(default_factory=list)
    usage: Dict[str, Any] = Field(default_factory=dict)
    provider: str = "demo"
    model: str = ""
    elapsed_ms: int = 0
    errors: List[str] = Field(default_factory=list)
    review_markdown: str = ""
    stats: Dict[str, Any] = Field(default_factory=dict)


class AskRequest(BaseModel):
    question: str
    code: Optional[str] = None
    diff: Optional[str] = None
    path: str = "input"
    review_id: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None


class ConfigUpdate(BaseModel):
    provider: Optional[str] = None
    model: Optional[str] = None
    api_keys: Optional[Dict[str, str]] = None
    effort: Optional[Literal["quick", "standard", "deep"]] = None
    base_urls: Optional[Dict[str, str]] = None
    temperature: Optional[float] = Field(None, ge=0.0, le=1.5)


class HealthResponse(BaseModel):
    status: str
    version: str
    default_provider: str
    default_model: str
    providers_configured: int
    offline_ready: bool
