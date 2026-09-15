# Code Review Agent

A **multi-agent AI code reviewer** that runs on **free LLM providers** — or with
**no API key at all**, on a built-in offline engine.

Paste code, a `git diff`, or a GitHub PR reference. Five specialist agents review
it in parallel, a lead reviewer merges and verifies their findings, and a
summarizer writes the walkthrough. Findings come back with real line numbers,
severity, confidence, and paste-ready fixes.

```
                     ┌─────────────────────────────────────────────┐
   code / diff /     │  1. intake      language, symbols, risk map │
   GitHub PR  ──────▶│  2. pre-scan    60+ deterministic rules     │
                     │  3. specialists quality · bugs · security   │
                     │                 performance · practices     │
                     │  4. synthesizer dedupe · verify · rank      │
                     │  5. summarizer  walkthrough · diagram       │
                     └─────────────────────────────────────────────┘
```

---

## Quick start

```bash
cd code_rabbit_alternative
./run.sh                       # creates a venv, installs deps, serves on :8000
```

Open **http://localhost:8000**. It works immediately — no key required.

Or manually:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

`make help` lists the other targets (`make test`, `make scan FILE=...`, `make dev`).

---

## Getting full AI review (free)

The offline engine catches a lot, but it cannot judge *logic*. For that, add one
free key — **any single one is enough**:

| Provider | Free tier | Get a key |
|---|---|---|
| **Groq** | No card needed, fastest (~500 tok/s) | https://console.groq.com/keys |
| **Google Gemini** | Generous quota, 1M-token context | https://aistudio.google.com/app/apikey |
| **OpenRouter** | `:free` model variants | https://openrouter.ai/keys |
| **Cerebras** | Free inference tier | https://cloud.cerebras.ai/ |
| **Together AI** | Free credits on signup | https://api.together.xyz/settings/api-keys |
| **Mistral / DeepInfra / SambaNova / xAI** | Free tiers or credits | see Settings panel |
| **Ollama / LM Studio** | 100% local, free forever | `ollama pull qwen2.5-coder:7b` |

Two ways to configure:

```bash
cp .env.example .env           # then paste your key
```

…or open **Settings** in the UI and paste it there. Keys go to server memory and
`config.local.json` (gitignored, `chmod 600`). They are sent only to the provider
you select, and never logged.

**Recommendation:** Groq + `llama-3.3-70b-versatile` for speed, or Gemini +
`gemini-2.0-flash` when reviewing large diffs (1M-token window).

---

## The system prompt

Every agent receives this verbatim as its `system` message. Click **System
prompt** in the UI to read it back from the running server.

```
You are an expert AI code reviewer. When I share code with you, analyze it
thoroughly and provide:

## Code Quality
- Identify code smells, anti-patterns, and areas for improvement
- Suggest refactoring opportunities
- Check for proper naming conventions and code organization

## Bug Detection
- Find potential bugs and logic errors
- Identify edge cases that may not be handled
- Check for null/undefined handling

## Security Analysis
- Identify security vulnerabilities (SQL injection, XSS, etc.)
- Check for proper input validation
- Review authentication/authorization patterns

## Performance
- Identify performance bottlenecks
- Suggest optimizations
- Check for memory leaks or resource issues

## Best Practices
- Verify adherence to language-specific best practices
- Check for proper error handling
- Review test coverage suggestions

Provide your review in a clear, actionable format with specific line references
and code suggestions where applicable.
```

Each of the five sections maps to one specialist agent. The core prompt is never
rewritten — a specialist only *appends* a narrow focus block and a JSON output
contract. See [`backend/agents/prompts.py`](backend/agents/prompts.py).

---

## How the agents work

| Agent | Owns | Notes |
|---|---|---|
| **Intake** | orientation | language, symbols, entry points, risk map. Skipped on `quick`. |
| **Pre-scan** | deterministic rules | 60+ rules across all five dimensions. Always runs, always free. |
| **Quality** | `quality` | smells, naming, organisation, refactoring. |
| **Bug hunter** | `bug` | logic errors, edge cases, null/undefined, concurrency. |
| **Security** | `security` | injection, XSS, authz, secrets, crypto, validation. Cites CWEs. |
| **Performance** | `performance` | complexity, N+1, blocking I/O, leaks, unbounded sets. |
| **Best practices** | `best_practices` | idioms, error handling, resources, test coverage. |
| **Synthesizer** | merge | dedupes, **verifies line numbers against real source**, re-ranks, verdicts. |
| **Summarizer** | prose | walkthrough, mermaid diagram, merge checklist. |

Three design decisions worth calling out:

**The pre-scan grounds the models.** Static hits are passed to the specialists as
*leads, not conclusions* — they're told to confirm, discard, or go beyond them.
This cuts hallucinated line numbers sharply, because the model is anchored to
lines that provably exist.

**Findings are verified, not trusted.** Every finding's line number is checked
against the actual file length, its path against the files that were really
submitted, and its category/severity against a fixed vocabulary. A finding that
cannot be grounded is dropped. Diff reviews additionally discard comments on
lines the PR did not touch.

**Everything degrades gracefully.** No key → offline engine. Unknown provider →
offline engine plus a visible warning. LLM synthesis fails → deterministic merge.
Rate-limited → exponential-backoff retry, then a per-agent error that doesn't
kill the run. A review always completes.

---

## Using it

### Web UI

- **Code** tab — paste source, or drop a file. Language auto-detects.
- **Diff / patch** tab — paste `git diff` output. Only changed lines get comments.
- **GitHub PR** tab — `owner/repo#123` or a full PR URL. Public repos need no token.

Effort levels: **quick** (2 agents) · **standard** (5 agents) · **deep** (5 agents,
2 rounds — the second round is explicitly told not to repeat the first).

Findings can be filtered by severity, category, file, and free text; each expands
to the offending snippet, a suggested fix, paste-ready replacement code, CWE
references, and a confidence score. There's also a **follow-up chat** that keeps
the code and the findings in context.

### API

```bash
# Full review (streams agent progress as SSE)
curl -N -X POST http://localhost:8000/api/review \
  -H 'Content-Type: application/json' \
  -d '{"code": "import os\nos.system(\"rm -rf \" + p)\n", "provider": "demo"}'

# Same, but a single JSON response
curl -X POST http://localhost:8000/api/review \
  -H 'Content-Type: application/json' \
  -d '{"code": "...", "stream": false}'

# Review a pull request
curl -N -X POST http://localhost:8000/api/review \
  -H 'Content-Type: application/json' \
  -d '{"pull_request": "owner/repo#123"}'

# Static analysis only — no LLM, instant, free (great in CI)
curl -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"code": "...", "path": "app.py"}'
```

| Endpoint | Purpose |
|---|---|
| `POST /api/review` | Run the full pipeline (SSE stream or JSON) |
| `POST /api/scan` | Deterministic static analysis only |
| `POST /api/ask` | Follow-up question about code or a past review |
| `GET  /api/reviews/{id}` | Retrieve a stored review (`?fmt=markdown`) |
| `GET  /api/reviews/{id}/comments` | GitHub-shaped inline comments |
| `POST /api/reviews/{id}/publish` | Post the review to a PR (needs `GITHUB_TOKEN`) |
| `POST /api/github/pr` | Fetch a PR for preview |
| `GET  /api/providers` | Provider catalogue + key status |
| `GET/POST /api/config` | Runtime provider/model/key config |
| `GET  /api/system-prompt` | The exact prompt in use |
| `GET  /api/examples` | Bundled sample inputs |
| `GET  /api/docs` | Interactive OpenAPI docs |

### CI

`/api/scan` needs no key and no network, so it fails fast and free:

```yaml
- name: Static review gate
  run: |
    curl -sf -X POST http://localhost:8000/api/scan \
      -H 'Content-Type: application/json' \
      -d "{\"diff\": $(git diff origin/main...HEAD | jq -Rs .)}" \
    | jq -e '.by_severity.critical == 0'
```

---

## Output shape

```json
{
  "verdict": "request_changes",
  "score": 62,
  "summary": "…",
  "walkthrough": "…markdown…",
  "findings": [{
    "id": "security-a1b2c3d4e5",
    "category": "security",
    "severity": "critical",
    "title": "SQL built by string concatenation",
    "file": "backend/services/payment.py",
    "line": 20,
    "description": "…",
    "suggestion": "Use parameterised queries…",
    "code_before": "query = \"SELECT * FROM orders WHERE id = \" + str(order.id)",
    "code_after": "row = db.execute(\"SELECT * FROM orders WHERE id = ?\", (order.id,))",
    "confidence": 0.9,
    "references": ["CWE-89", "OWASP A03:2021"],
    "line_comment": "**🔴 CRITICAL · Security — …**  (GitHub-ready markdown)"
  }],
  "positives": ["…"],
  "test_recommendations": ["…"],
  "by_severity": {"critical": 1, "high": 4, "medium": 6, "low": 3, "info": 0},
  "metrics": [{"path": "…", "complexity": 18, "max_nesting": 4, "…": "…"}],
  "trace": [{"agent": "security", "status": "done", "findings": 5, "duration_ms": 812}],
  "review_markdown": "# Code review — …"
}
```

---

## Layout

```
backend/
  main.py                 FastAPI app: review, ask, config, static UI
  config.py               env + runtime config; keys masked, never logged
  models.py               pydantic schemas
  agents/
    prompts.py            the system prompt + per-agent focus blocks
    base.py               agent lifecycle, JSON parsing, finding validation
    intake.py             deterministic orientation
    specialists.py        quality · bugs · security · performance · practices
    synthesizer.py        merge, verify, rank, verdict (+ deterministic fallback)
    summarizer.py         walkthrough, mermaid, checklist (+ fallback)
    orchestrator.py       pipeline runner, SSE events, markdown rendering
  providers/
    base.py               LLMProvider interface
    openai_compat.py      Groq, OpenRouter, Together, Cerebras, Ollama, …
    gemini.py             Google AI Studio
    demo.py               offline static engine (no key, no network)
    registry.py           provider catalogue + key resolution
  analysis/
    languages.py          detection + per-language metadata
    diff.py               unified-diff parser, line mapping
    heuristics.py         the static rule engine
  integrations/github.py  fetch PRs, post reviews
  utils/jsonrepair.py     tolerant JSON extraction from model output
frontend/                 no build step, no CDN — vanilla JS + vendored
  vendor/markdown.js      markdown renderer (XSS-safe)
  vendor/highlight.js     syntax highlighter for ~18 languages
tests/                    250 tests
examples/                 deliberately flawed samples for demoing
```

### No build step, no CDN

The frontend is plain HTML/CSS/JS served by FastAPI. The markdown renderer and
syntax highlighter are vendored (~15 KB total) because the app must work on a
machine with no internet access — which is also exactly when you're running
Ollama locally. Markdown output is HTML-escaped before insertion, so a model
cannot inject markup into your browser.

---

## Tests

```bash
make test          # 250 tests, ~3 seconds
```

Coverage includes the diff parser (renames, deletions, `\ No newline` markers,
CRLF), the rule engine (each rule plus false-positive guards), JSON repair,
provider resolution and key precedence, merge/dedupe semantics, pipeline
fallbacks, and the HTTP API end-to-end.

Several tests are **regression guards** for bugs found during development:

- offline specialists once re-labelled the whole scan into their own category,
  quintupling every finding;
- diff findings were once attributed to a bogus `"3 files changed"` path;
- a 20,000-line file of repeated lines once produced ~20,000 duplicate findings
  and took **77 seconds** to scan (an O(n²) context lookup). It now takes
  **0.23 seconds** and reports nothing, correctly.

---

## Notes and limits

- **Findings are AI-generated.** Verify before acting. Every finding carries a
  confidence score and, where applicable, a CWE reference.
- The static engine is deliberately conservative — a false positive in an
  authoritative-looking review is worse than a miss.
- Free tiers rate-limit. Specialists run with a concurrency cap of 3 and retry
  with exponential backoff on 429/5xx.
- Reviews are kept in memory (last 25) for follow-up questions; nothing is
  persisted to a database and no code leaves your machine unless you pick a
  cloud provider.
- The GitHub publisher needs a token with repo write access; without one the
  review still generates and you can copy the markdown.

## License

See [`../LICENSE`](../LICENSE).
