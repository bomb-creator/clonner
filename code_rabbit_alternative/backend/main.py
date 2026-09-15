"""FastAPI application: review API, follow-up chat, config, and the web UI.

Run with:  uvicorn backend.main:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import config
from .agents.base import AgentContext, build_line_comment
from .agents.orchestrator import (
    build_context,
    get_review,
    prescan_to_findings,
    render_markdown,
    run_prescan,
    run_pipeline,
)
from .agents.prompts import CHAT_HEADER, CORE_SYSTEM_PROMPT, review_context_block
from .analysis.diff import looks_like_diff, number_source, parse_unified_diff
from .analysis.heuristics import scan_code, scan_diff
from .analysis.languages import detect_language, language_for_path
from .integrations.github import fetch_pull_request, parse_pr_ref, post_review, PullRequest
from .models import (
    AskRequest,
    ConfigUpdate,
    Finding,
    HealthResponse,
    ReviewRequest,
)
from .providers.base import ChatMessage, ProviderError
from .providers.registry import build_provider, provider_status
from .utils.jsonrepair import extract_json

logger = logging.getLogger("review-agent")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"

app = FastAPI(
    title="Code Review Agent",
    description="A multi-agent AI code reviewer that runs on free LLM providers.",
    version=config.VERSION,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

# The UI is served from the same origin, so CORS stays locked down by default.
# Set CORS_ORIGINS="*" only if you host the frontend separately.
import os

_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins or ["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "OPTIONS"],
    allow_headers=["*"],
)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _resolve_provider(request_provider: Optional[str], request_model: Optional[str], api_key: Optional[str]):
    provider_id = request_provider or config.get_provider_id()
    model = request_model or config.get_model(provider_id)
    provider = build_provider(
        provider_id,
        api_key=api_key or config.get_api_key(provider_id),
        base_url=config.get_base_url(provider_id),
    )
    if provider.requires_key and not provider.is_configured():
        raise HTTPException(
            status_code=400,
            detail=(
                f"{provider_id} has no API key configured. Add one in Settings, or use the "
                "'demo' provider which runs offline."
            ),
        )
    return provider, provider_id, model


def _sse(event: Dict[str, Any]) -> str:
    name = event.pop("event", "message")
    return f"event: {name}\ndata: {json.dumps(event, default=str)}\n\n"


def _public_pr(pr: PullRequest) -> Dict[str, Any]:
    return {
        "owner": pr.owner, "repo": pr.repo, "number": pr.number,
        "title": pr.title, "author": pr.author, "state": pr.state,
        "base": pr.base, "head": pr.head, "url": pr.url,
        "additions": pr.additions, "deletions": pr.deletions,
        "changed_files": pr.changed_files,
        "files": [
            {"filename": f["filename"], "status": f["status"], "additions": f["additions"],
             "deletions": f["deletions"], "language": f["language"],
             "has_patch": bool(f.get("patch"))}
            for f in pr.files
        ],
        "diff_preview": pr.diff[:4000],
        "diff_chars": len(pr.diff),
    }


# ----------------------------------------------------------------------
# UI
# ----------------------------------------------------------------------
@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    index_file = FRONTEND / "index.html"
    if not index_file.exists():
        return JSONResponse({"detail": "frontend not built"}, status_code=404)
    return FileResponse(index_file)


@app.get("/api/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    statuses = provider_status(runtime_keys=config.runtime_api_keys())
    configured = sum(1 for s in statuses if s["configured"])
    provider_id = config.get_provider_id()
    return HealthResponse(
        status="ok",
        version=config.VERSION,
        default_provider=provider_id,
        default_model=config.get_model(provider_id),
        providers_configured=configured,
        offline_ready=True,
    )


@app.get("/api/providers")
async def providers() -> Dict[str, Any]:
    return {
        "providers": provider_status(runtime_keys=config.runtime_api_keys()),
        "active": {"provider": config.get_provider_id(), "model": config.get_model()},
    }


@app.get("/api/config")
async def get_config() -> Dict[str, Any]:
    return config.snapshot()


@app.post("/api/config")
async def update_config(update: ConfigUpdate) -> Dict[str, Any]:
    try:
        return config.update(
            provider=update.provider,
            model=update.model,
            api_keys=update.api_keys,
            base_urls=update.base_urls,
            effort=update.effort,
            temperature=update.temperature,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/system-prompt")
async def system_prompt() -> Dict[str, Any]:
    """Expose the exact reviewer system prompt so it is auditable in the UI."""
    from .agents.prompts import AGENT_FOCUS

    return {
        "core": CORE_SYSTEM_PROMPT,
        "agents": {key: value.strip() for key, value in AGENT_FOCUS.items()},
    }


# ----------------------------------------------------------------------
# Review
# ----------------------------------------------------------------------
@app.post("/api/review")
async def review(request: ReviewRequest, raw: Request) -> Any:
    """Run a review. Streams SSE progress when `stream=true`, else returns JSON."""
    if not (request.code or request.diff or request.files or request.pull_request):
        raise HTTPException(
            status_code=400,
            detail="Provide `code`, `diff`, `files`, or `pull_request` to review.",
        )

    if not request.stream:
        result: Optional[Dict[str, Any]] = None

        async def consume() -> None:
            nonlocal result
            async for event in run_pipeline(request):
                if event.get("event") == "done":
                    result = event["review"]
                elif event.get("event") == "error":
                    raise HTTPException(status_code=400, detail=event.get("message", "review failed"))

        await consume()
        return JSONResponse(result or {"detail": "no result"})

    async def generator() -> AsyncIterator[str]:
        yield _sse({"event": "ping", "at": time.time()})
        try:
            async for event in run_pipeline(request):
                yield _sse(dict(event))
        except asyncio.CancelledError:
            logger.info("client disconnected mid-review")
            raise
        except ProviderError as exc:
            yield _sse({"event": "error", "message": str(exc)})
        except Exception as exc:  # noqa: BLE001
            logger.exception("review failed")
            yield _sse({"event": "error", "message": f"{type(exc).__name__}: {exc}"})
        finally:
            yield _sse({"event": "end"})

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/reviews/{review_id}")
async def fetch_review(review_id: str, fmt: str = Query("json", pattern="^(json|markdown)$")) -> Any:
    stored = get_review(review_id)
    if not stored:
        raise HTTPException(status_code=404, detail=f"No review '{review_id}' in memory (last {25} are kept).")
    if fmt == "markdown":
        return JSONResponse({"review_id": review_id, "markdown": stored.review_markdown})
    return stored


@app.get("/api/reviews/{review_id}/markdown")
async def review_markdown(review_id: str) -> Dict[str, Any]:
    stored = get_review(review_id)
    if not stored:
        raise HTTPException(status_code=404, detail="review not found")
    return {"review_id": review_id, "markdown": stored.review_markdown}


@app.get("/api/reviews/{review_id}/comments")
async def review_comments(review_id: str, min_severity: str = Query("medium")) -> Dict[str, Any]:
    """GitHub-ready inline comments for a stored review."""
    stored = get_review(review_id)
    if not stored:
        raise HTTPException(status_code=404, detail="review not found")
    order = ["critical", "high", "medium", "low", "info"]
    floor = order.index(min_severity) if min_severity in order else 2
    comments = [
        {"path": f.file, "line": f.line, "body": f.line_comment or build_line_comment(f),
         "severity": f.severity, "category": f.category, "title": f.title}
        for f in stored.findings
        if f.line and order.index(f.severity) <= floor
    ]
    return {
        "review_id": review_id,
        "body": stored.summary,
        "event": {"block": "REQUEST_CHANGES", "request_changes": "REQUEST_CHANGES"}.get(stored.verdict, "COMMENT"),
        "comments": comments,
    }


@app.post("/api/reviews/{review_id}/publish")
async def publish_review(review_id: str, payload: Dict[str, Any] = Body(default={})) -> Dict[str, Any]:
    stored = get_review(review_id)
    if not stored:
        raise HTTPException(status_code=404, detail="review not found")
    ref = parse_pr_ref(str(payload.get("pull_request") or stored.stats.get("pull_request") or ""))
    if not ref:
        raise HTTPException(
            status_code=400,
            detail="This review is not tied to a pull request. Pass `pull_request` (owner/repo#123).",
        )
    data = await review_comments(review_id, payload.get("min_severity", "high"))
    pr = PullRequest(owner=ref["owner"], repo=ref["repo"], number=ref["number"])
    try:
        result = await post_review(pr, data["body"], data["comments"], event=data["event"])
        return {"posted": True, "html_url": result.get("html_url"), "comments": len(data["comments"])}
    except ProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


# ----------------------------------------------------------------------
# Follow-up chat
# ----------------------------------------------------------------------
@app.post("/api/ask")
async def ask(request: AskRequest) -> Dict[str, Any]:
    if not request.question.strip():
        raise HTTPException(status_code=400, detail="question is required")

    provider, provider_id, model = _resolve_provider(request.provider, request.model, request.api_key)

    code = request.code or ""
    review_findings: List[Finding] = []
    if not code and request.review_id:
        stored = get_review(request.review_id)
        if stored:
            review_findings = stored.findings
            code = stored.walkthrough or ""
    if not code:
        raise HTTPException(status_code=400, detail="Provide `code` or a `review_id` to ask about.")

    language = detect_language(code, request.path)
    prompt = CHAT_HEADER.format(
        question=request.question.strip(),
        path=request.path,
        language=language,
        numbered_code=number_source(code)[:60_000],
        review_context=review_context_block(review_findings),
    )

    started = time.perf_counter()
    try:
        result = await provider.complete(
            [
                ChatMessage(role="system", content=CORE_SYSTEM_PROMPT),
                ChatMessage(role="user", content=prompt),
            ],
            model=model,
            temperature=config.get_temperature(),
            max_tokens=1600,
            json_mode=False,
            context={"task": "chat", "code": code, "path": request.path,
                     "question": request.question, "focus_lines": None},
        )
    except TypeError:
        result = await provider.complete(
            [ChatMessage(role="system", content=CORE_SYSTEM_PROMPT),
             ChatMessage(role="user", content=prompt)],
            model=model, temperature=config.get_temperature(), max_tokens=1600, json_mode=False,
        )
    except ProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "answer": result.text,
        "provider": provider_id,
        "model": result.model,
        "tokens": {"prompt": result.prompt_tokens, "completion": result.completion_tokens},
        "elapsed_ms": int((time.perf_counter() - started) * 1000),
    }


# ----------------------------------------------------------------------
# Static analysis only (no LLM) — fast, free, useful in CI
# ----------------------------------------------------------------------
@app.post("/api/scan")
async def scan(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    code = str(payload.get("code") or "")
    diff = str(payload.get("diff") or "")
    path = str(payload.get("path") or "input")
    if not code and not diff:
        raise HTTPException(status_code=400, detail="provide `code` or `diff`")

    if diff or looks_like_diff(code):
        diffset = parse_unified_diff(diff or code)
        result = scan_diff(diffset)
        findings = prescan_to_findings(result, AgentContext(diffset=diffset, is_diff=True, path=path))
    else:
        result = scan_code(code, path=path)
        findings = prescan_to_findings(result, AgentContext(code=code, path=path))

    return {
        "findings": [f.model_dump() for f in findings],
        "by_severity": result.by_severity(),
        "by_category": result.by_category(),
        "metrics": {k: v.to_dict() for k, v in result.metrics.items()},
        "language": detect_language(code, path),
    }


@app.post("/api/detect")
async def detect(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """What will this input be treated as? Handy for debugging uploads."""
    code = str(payload.get("code") or "")
    path = str(payload.get("path") or "")
    language = detect_language(code, path)
    return {
        "language": language,
        "is_diff": looks_like_diff(code),
        "lines": len(code.splitlines()),
        "chars": len(code),
        "path_kind": language_for_path(path) if path else None,
    }


@app.post("/api/github/pr")
async def github_pr(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Fetch a PR so the UI can preview it before reviewing."""
    ref = parse_pr_ref(str(payload.get("pull_request") or ""))
    if not ref:
        raise HTTPException(
            status_code=400,
            detail="Use `owner/repo#123` or a full GitHub pull request URL.",
        )
    try:
        pr = await fetch_pull_request(ref["owner"], ref["repo"], ref["number"],
                                      token=payload.get("token") or None)
    except ProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return _public_pr(pr)


# ----------------------------------------------------------------------
# Examples
# ----------------------------------------------------------------------
@app.get("/api/examples")
async def examples() -> Dict[str, Any]:
    folder = ROOT / "examples"
    out: List[Dict[str, Any]] = []
    if folder.exists():
        for entry in sorted(folder.iterdir()):
            if entry.is_file() and entry.suffix in {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".diff", ".patch", ".sql", ".php"}:
                try:
                    content = entry.read_text(encoding="utf-8")
                except Exception:
                    continue
                out.append({
                    "id": entry.stem,
                    "name": entry.name,
                    "kind": "diff" if entry.suffix in {".diff", ".patch"} or looks_like_diff(content) else "code",
                    "language": language_for_path(entry.name),
                    "content": content,
                })
    return {"examples": out}


# ----------------------------------------------------------------------
# Errors
# ----------------------------------------------------------------------
@app.exception_handler(ProviderError)
async def provider_error_handler(_: Request, exc: ProviderError) -> JSONResponse:
    return JSONResponse(status_code=502, detail={"message": str(exc), "status": exc.status})


if FRONTEND.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND), html=True), name="frontend")


def main() -> None:
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run("backend.main:app", host=host, port=port, reload=False, log_level="info")


if __name__ == "__main__":
    main()
