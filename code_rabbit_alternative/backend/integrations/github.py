"""GitHub integration: fetch a public PR and turn it into a reviewable diff.

Read-only by default (no token required for public repos, 60 req/h). With a
`GITHUB_TOKEN` it can also post the review as inline PR comments.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from ..providers.base import ProviderError

API = "https://api.github.com"
_PR_URL_RE = re.compile(r"github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)/pull/(?P<number>\d+)")
_PR_SHORT_RE = re.compile(r"^(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)#(?P<number>\d+)$")


@dataclass
class PullRequest:
    owner: str
    repo: str
    number: int
    title: str = ""
    body: str = ""
    author: str = ""
    base: str = ""
    head: str = ""
    state: str = ""
    url: str = ""
    files: List[Dict[str, Any]] = field(default_factory=list)
    diff: str = ""
    additions: int = 0
    deletions: int = 0
    changed_files: int = 0

    def to_dict(self) -> Dict[str, Any]:
        data = self.__dict__.copy()
        data["files"] = [
            {k: v for k, v in f.items() if k in {"filename", "status", "additions", "deletions", "language"}}
            for f in self.files
        ]
        return data


def parse_pr_ref(text: str) -> Optional[Dict[str, Any]]:
    """Accept `owner/repo#123`, a PR URL, or a bare `owner/repo/pull/123`."""
    if not text:
        return None
    text = text.strip()
    match = _PR_URL_RE.search(text)
    if match:
        return {"owner": match.group("owner"), "repo": match.group("repo"),
                "number": int(match.group("number"))}
    match = _PR_SHORT_RE.match(text)
    if match:
        return {"owner": match.group("owner"), "repo": match.group("repo"),
                "number": int(match.group("number"))}
    match = re.match(r"^([\w.-]+)/([\w.-]+)/pull/(\d+)/?$", text)
    if match:
        return {"owner": match.group(1), "repo": match.group(2), "number": int(match.group(3))}
    return None


def _headers(token: Optional[str], diff: bool = False) -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github.diff" if diff else "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "code-review-agent/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _error(response: httpx.Response, what: str) -> ProviderError:
    try:
        message = response.json().get("message", response.text[:200])
    except Exception:
        message = response.text[:200]
    hint = ""
    if response.status_code == 403 and "rate limit" in message.lower():
        hint = " Unauthenticated GitHub allows 60 requests/hour — set GITHUB_TOKEN for 5000/hour."
    elif response.status_code == 404:
        hint = " The repository may be private; set GITHUB_TOKEN with repo access."
    return ProviderError(f"GitHub {what} failed (HTTP {response.status_code}): {message}{hint}",
                         status=response.status_code, retryable=response.status_code in {403, 429, 502, 503})


async def fetch_pull_request(
    owner: str,
    repo: str,
    number: int,
    *,
    token: Optional[str] = None,
    timeout: float = 40.0,
    max_files: int = 60,
) -> PullRequest:
    token = token or os.getenv("GITHUB_TOKEN")
    pr = PullRequest(owner=owner, repo=repo, number=number,
                     url=f"https://github.com/{owner}/{repo}/pull/{number}")

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        meta = await client.get(f"{API}/repos/{owner}/{repo}/pulls/{number}", headers=_headers(token))
        if meta.status_code >= 400:
            raise _error(meta, f"PR {owner}/{repo}#{number}")
        data = meta.json()
        pr.title = data.get("title", "")
        pr.body = (data.get("body") or "")[:4000]
        pr.author = (data.get("user") or {}).get("login", "")
        pr.state = data.get("state", "")
        pr.base = (data.get("base") or {}).get("ref", "")
        pr.head = (data.get("head") or {}).get("ref", "")
        pr.additions = data.get("additions", 0)
        pr.deletions = data.get("deletions", 0)
        pr.changed_files = data.get("changed_files", 0)

        files_resp = await client.get(
            f"{API}/repos/{owner}/{repo}/pulls/{number}/files",
            headers=_headers(token),
            params={"per_page": min(max_files, 100)},
        )
        if files_resp.status_code >= 400:
            raise _error(files_resp, "PR file list")
        raw_files = files_resp.json()

    from ..analysis.languages import is_binary_or_ignorable, language_for_path

    kept: List[Dict[str, Any]] = []
    patches: List[str] = []
    for item in raw_files:
        filename = item.get("filename", "")
        if not filename or is_binary_or_ignorable(filename):
            continue
        patch = item.get("patch")
        entry = {
            "filename": filename,
            "status": item.get("status", "modified"),
            "additions": item.get("additions", 0),
            "deletions": item.get("deletions", 0),
            "language": language_for_path(filename),
            "patch": patch or "",
        }
        kept.append(entry)
        if patch:
            patches.append(f"diff --git a/{filename} b/{filename}\n--- a/{filename}\n+++ b/{filename}\n{patch}")

    pr.files = kept
    pr.diff = "\n".join(patches)
    return pr


async def post_review(
    pr: PullRequest,
    body: str,
    comments: List[Dict[str, Any]],
    event: str = "COMMENT",
    token: Optional[str] = None,
    timeout: float = 40.0,
) -> Dict[str, Any]:
    """Submit a PR review with inline comments. Requires a token with write access."""
    token = token or os.getenv("GITHUB_TOKEN")
    if not token:
        raise ProviderError(
            "Posting to GitHub needs GITHUB_TOKEN with repo write access. "
            "The review was generated; only the posting step is blocked."
        )

    payload: Dict[str, Any] = {"body": body, "event": event}
    inline = [
        {
            "path": c["path"],
            "line": c.get("line"),
            "side": "RIGHT",
            "body": c["body"],
        }
        for c in comments if c.get("path") and c.get("line")
    ]
    if inline:
        payload["comments"] = inline[:50]

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(
            f"{API}/repos/{pr.owner}/{pr.repo}/pulls/{pr.number}/reviews",
            headers={**_headers(token), "Content-Type": "application/json"},
            json=payload,
        )
        if response.status_code >= 400:
            raise _error(response, "review submission")
        return response.json()
