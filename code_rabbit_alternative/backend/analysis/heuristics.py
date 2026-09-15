"""Static rule engine.

Two jobs:
1. Power the offline `demo` provider so the app is fully functional with no API key.
2. Give the LLM agents grounded, line-accurate "pre-scan hints" so their
   findings reference real lines instead of hallucinated ones.

Rules are intentionally conservative: a false positive is worse than a miss
when the output is shown to a developer as an authoritative review.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

_PATTERN_CACHE: Dict[Tuple[str, int], "re.Pattern"] = {}

from .languages import detect_language, is_test_file, profile_for

CATEGORIES = ("security", "bug", "quality", "performance", "best_practices")
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_WEIGHT = {"critical": 100, "high": 60, "medium": 30, "low": 12, "info": 4}

# Bounds that keep a pathological input (generated code, minified bundle,
# highly repetitive file) from producing tens of thousands of findings.
MAX_FINDINGS_PER_SCAN = 300
MAX_DUPLICATE_FINDINGS = 20
MAX_REPEATS_PER_BLOCK = 3
MAX_HINTS_IN_PROMPT = 60


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    title: str
    pattern: str
    message: str
    suggestion: str
    languages: Tuple[str, ...] = ()
    references: Tuple[str, ...] = ()
    flags: int = 0
    skip_in_tests: bool = False
    code_after: str = ""

    @property
    def compiled(self) -> "re.Pattern":
        """Cached compile — the same pattern is reused across every scan."""
        key = (self.pattern, self.flags)
        pattern = _PATTERN_CACHE.get(key)
        if pattern is None:
            pattern = re.compile(self.pattern, self.flags)
            _PATTERN_CACHE[key] = pattern
        return pattern


def _r(*args, **kwargs) -> Rule:
    return Rule(*args, **kwargs)


# --------------------------------------------------------------------------
# SECURITY
# --------------------------------------------------------------------------
SECURITY_RULES: List[Rule] = [
    _r("SEC-SQLI-CONCAT", "security", "critical",
       "SQL built by string concatenation",
       r"""(?:execute|executemany|cursor\.execute|query|raw|exec)\s*\(\s*["'].*?(?:SELECT|INSERT|UPDATE|DELETE)\b.*?["']\s*(?:%|\+|\.format|f["'])""",
       "SQL is assembled from string interpolation, which allows SQL injection if any part of the string is user controlled.",
       "Use parameterised queries / prepared statements and pass user input as bound parameters.",
       languages=("python", "java", "php", "ruby", "javascript", "typescript", "csharp", "go"),
       references=("CWE-89", "OWASP A03:2021"),
       flags=re.IGNORECASE,
       code_after='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'),
    _r("SEC-SQLI-FSTRING", "security", "critical",
       "f-string / template literal inside a SQL statement",
       r"""(?:execute|query|raw)\s*\(\s*(?:f["']|`).*?\b(?:SELECT|INSERT|UPDATE|DELETE)\b""",
       "A formatted string is passed directly to a SQL execution call.",
       "Replace interpolation with bound parameters so the driver escapes values.",
       languages=("python", "javascript", "typescript"),
       references=("CWE-89",), flags=re.IGNORECASE,
       code_after='cursor.execute("SELECT * FROM users WHERE email = %s", (email,))'),
    _r("SEC-SQLI-BUILD", "security", "critical",
       "SQL statement assembled before execution",
       r"""["'](?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^"']*["']\s*(?:\+|%(?!\(?\w+\)?s)|\.format\s*\()""",
       "A SQL string is concatenated or formatted with a variable. Even when the "
       "execution happens on a later line, this is SQL injection if any part is user controlled.",
       "Build the statement with placeholders and pass values as bound parameters.",
       languages=("python", "java", "php", "ruby", "javascript", "typescript", "csharp", "go"),
       references=("CWE-89", "OWASP A03:2021"), flags=re.IGNORECASE,
       code_after='query = "SELECT id, name FROM users WHERE id = ?"\nrow = cur.execute(query, (user_id,)).fetchone()'),
    _r("SEC-SQLI-TEMPLATE", "security", "critical",
       "Interpolated SQL via f-string or template literal",
       r"""\bf["'](?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{|`(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{""",
       "An f-string or template literal embeds a variable straight into SQL, which is injectable.",
       "Use bound parameters instead of interpolation.",
       languages=("python", "javascript", "typescript"),
       references=("CWE-89",), flags=re.IGNORECASE,
       code_after='cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))'),
    _r("SEC-CMD-INJECTION", "security", "critical",
       "Shell command built from a variable",
       r"""(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output)|exec|shell_exec|Runtime\.getRuntime\(\)\.exec|child_process\.(?:exec|execSync))\s*\(""",
       "Invoking a shell with interpolated input allows arbitrary command execution.",
       "Prefer an argv list without shell=True, and validate or avoid user input entirely.",
       languages=("python", "javascript", "typescript", "php", "java"),
       references=("CWE-78",),
       code_after='subprocess.run(["git", "status"], check=True)  # no shell=True'),
    _r("SEC-SHELL-TRUE", "security", "high",
       "subprocess called with shell=True",
       r"""subprocess\.\w+\([^)]*shell\s*=\s*True""",
       "shell=True routes the command through /bin/sh, enabling shell metacharacter injection.",
       "Pass a list of arguments and drop shell=True.",
       languages=("python",), references=("CWE-78",),
       code_after='subprocess.run(["ls", "-la"], check=True)'),
    _r("SEC-EVAL", "security", "critical",
       "Use of eval/exec on dynamic input",
       r"""\b(?:eval|exec|Function)\s*\(\s*[^\s)]""",
       "eval-family calls execute arbitrary code and are almost never safe with dynamic input.",
       "Use a data-driven dispatch table, ast.literal_eval, or JSON parsing instead.",
       languages=("python", "javascript", "typescript", "php", "ruby"),
       references=("CWE-95",),
       code_after='import ast\nvalue = ast.literal_eval(user_input)'),
    _r("SEC-XSS-INNERHTML", "security", "high",
       "Untrusted HTML assigned via innerHTML",
       r"""\.innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|\$\(.*\)\.html\(""",
       "Writing raw HTML into the DOM executes embedded script, enabling cross-site scripting.",
       "Use textContent, or sanitise with DOMPurify before injecting HTML.",
       languages=("javascript", "typescript", "html", "vue"),
       references=("CWE-79", "OWASP A03:2021"),
       code_after='el.textContent = userInput;\n// or: el.innerHTML = DOMPurify.sanitize(userInput);'),
    _r("SEC-SECRET-HARDCODED", "security", "critical",
       "Hardcoded credential or API key",
       r"""(?i)\b(?:api[_-]?key|apikey|secret|password|passwd|pwd|token|auth[_-]?token|access[_-]?key|private[_-]?key)\b\s*[:=]\s*["'][^"']{6,}["']""",
       "A secret literal is committed to source control; anyone with repo access obtains it.",
       "Load secrets from the environment or a secret manager, and rotate this credential now.",
       references=("CWE-798", "OWASP A02:2021"),
       code_after='API_KEY = os.environ["API_KEY"]  # never commit the literal'),
    _r("SEC-AWS-KEY", "security", "critical",
       "AWS-style access key literal",
       r"""\b(?:AKIA|ASIA)[0-9A-Z]{16}\b""",
       "This looks like a real cloud access key id.",
       "Remove it, rotate it in the cloud console, and add secret scanning to CI.",
       references=("CWE-798",)),
    _r("SEC-WEAK-HASH", "security", "high",
       "Weak hashing algorithm",
       r"""\b(?:md5|sha1)\s*\(|hashlib\.(?:md5|sha1)\b|MessageDigest\.getInstance\(\s*"(?:MD5|SHA-1)"|crypto\.createHash\(\s*['"](md5|sha1)""",
       "MD5 and SHA-1 are broken for collision resistance and must not be used for security purposes.",
       "Use SHA-256 or better; for passwords use bcrypt/scrypt/argon2.",
       languages=("python", "java", "javascript", "typescript", "php", "go", "csharp"),
       references=("CWE-327", "CWE-916"),
       code_after='hashlib.sha256(data).hexdigest()'),
    _r("SEC-WEAK-RANDOM", "security", "medium",
       "Non-cryptographic randomness for a security value",
       r"""\brandom\.(?:random|randint|choice|choices|sample)\s*\(.*(?:token|secret|password|salt|otp|nonce|session)|(?:token|secret|password|salt|otp|nonce).*=.*\brandom\.""",
       "The random module is not cryptographically secure and its output is predictable.",
       "Use secrets.token_urlsafe()/secrets.randbelow() for security-sensitive values.",
       languages=("python",), references=("CWE-330",),
       code_after='import secrets\ntoken = secrets.token_urlsafe(32)'),
    _r("SEC-INSECURE-DESER", "security", "critical",
       "Unsafe deserialization",
       r"""\bpickle\.loads?\b|\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)|\bmarshal\.loads?\b|ObjectInputStream""",
       "Deserialising untrusted data with these APIs leads to remote code execution.",
       "Use yaml.safe_load, JSON, or a schema-validated format.",
       languages=("python", "java"), references=("CWE-502",),
       code_after='data = yaml.safe_load(stream)'),
    _r("SEC-CORS-WILDCARD", "security", "medium",
       "CORS allows every origin",
       r"""Access-Control-Allow-Origin["'\s:,*]+["']?\*|allow_origins\s*=\s*\[\s*["']\*["']|origin\s*:\s*["']?\*|cors\(\s*\{\s*origin\s*:\s*true""",
       "A wildcard CORS policy lets any website call this API from a victim's browser.",
       "Allowlist specific origins, and never combine '*' with credentials.",
       languages=("python", "javascript", "typescript", "java", "php"),
       references=("CWE-942",),
       code_after='CORSMiddleware(app, allow_origins=["https://app.example.com"], allow_credentials=True)'),
    _r("SEC-SSL-DISABLED", "security", "high",
       "TLS certificate verification disabled",
       r"""verify\s*=\s*False|rejectUnauthorized\s*:\s*false|setHostnameVerifier|ALLOW_ALL_HOSTNAME|InsecureRequestWarning|ssl\._create_unverified_context|curl_setopt.*SSL_VERIFYPEER.*0""",
       "Disabling verification permits trivial man-in-the-middle attacks.",
       "Keep verification on and install the correct CA bundle instead.",
       references=("CWE-295",),
       code_after='requests.get(url, verify=True, timeout=10)'),
    _r("SEC-DEBUG-ON", "security", "medium",
       "Debug mode enabled in shipped config",
       r"""\bDEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|FLASK_DEBUG\s*=\s*1|NODE_ENV\s*=\s*['"]?development""",
       "Debug mode exposes stack traces and often an interactive console to attackers.",
       "Drive it from an environment variable that defaults to False in production.",
       languages=("python", "javascript", "typescript"), references=("CWE-489",),
       code_after='app.run(debug=os.getenv("FLASK_DEBUG") == "1")'),
    _r("SEC-JWT-NONE", "security", "high",
       "JWT signature verification weakened",
       r"""algorithms?\s*=\s*\[?\s*["']none["']|verify_signature\s*[:=]\s*False|jwt\.decode\([^)]*options\s*=\s*\{[^}]*verify""",
       "Accepting unsigned tokens or skipping verification defeats JWT authentication entirely.",
       "Pin the algorithm to a strong one and always verify the signature and expiry.",
       references=("CWE-347",),
       code_after='jwt.decode(token, key, algorithms=["HS256"], options={"verify_exp": True})'),
    _r("SEC-PATH-TRAVERSAL", "security", "high",
       "File path built from user input",
       r"""\bopen\s*\(\s*(?:request|req|params|args|query|input|user)\w*\b.*\)|send_file\s*\(.*(request|params|args)|\b(?:os\.path\.join|Path)\s*\([^)]*(?:request|req\.|params|query)\w*""",
       "Concatenating request data into a path allows ../ traversal outside the intended directory.",
       "Resolve the path and assert it stays inside an allowed root (os.path.realpath).",
       languages=("python", "javascript", "typescript", "php"), references=("CWE-22",),
       code_after='root = os.path.realpath(BASE)\ntarget = os.path.realpath(os.path.join(BASE, name))\nif not target.startswith(root):\n    raise PermissionError("outside sandbox")'),
    _r("SEC-HARDCODED-IP", "security", "info",
       "Hardcoded host/IP in source",
       r"""["']https?://(?:\d{1,3}\.){3}\d{1,3}[:/]|["'](?:localhost|127\.0\.0\.1)(?::\d+)?["']""",
       "Hardcoded endpoints make environments (dev/staging/prod) impossible to separate safely.",
       "Move the base URL into configuration.",
       references=("CWE-1104",)),
]

# --------------------------------------------------------------------------
# BUGS
# --------------------------------------------------------------------------
BUG_RULES: List[Rule] = [
    _r("BUG-LOOSE-EQUALITY", "bug", "medium",
       "Loose equality comparison",
       r"""[^=!<>+\-*/%&|^]\s*==\s*(?:null|undefined|true|false|0|""|'')|\bif\s*\(\s*\w+\s*==\s*\w+\s*\)""",
       "== performs type coercion (0 == '' == false), which hides real mismatches.",
       "Use === / !== for strict comparison, or an explicit null check.",
       languages=("javascript", "typescript", "php"), references=("CWE-697",),
       code_after='if (value === null || value === undefined) { return; }'),
    _r("BUG-ASSIGNMENT-IN-COND", "bug", "high",
       "Assignment inside a condition",
       r"""\bif\s*\(\s*(?:[a-zA-Z_]\w*(?:\.\w+)*)\s*=\s*[^=]""",
       "A single '=' assigns instead of comparing, so the branch is almost always taken.",
       "Use == / === , or move the assignment out of the condition.",
       languages=("javascript", "typescript", "c", "cpp", "java", "csharp", "php"),
       references=("CWE-481",)),
    _r("BUG-EXCEPT-PASS", "bug", "high",
       "Exception swallowed silently",
       r"""except\s*(?:\w*(?:Error|Exception))?\s*(?:as\s+\w+)?\s*:\s*$""",
       "An except clause with no re-raise or logging hides failures; state becomes undefined downstream.",
       "Log the exception and either handle it or re-raise; never use a bare `except: pass`.",
       languages=("python",), references=("CWE-390",),
       code_after='except ValueError as exc:\n    logger.warning("bad input: %s", exc)\n    raise'),
    _r("BUG-BARE-EXCEPT", "bug", "medium",
       "Bare except clause",
       r"""^\s*except\s*:\s*$""",
       "A bare except also catches KeyboardInterrupt and SystemExit, breaking shutdown and debugging.",
       "Catch the specific exception type you can actually handle.",
       languages=("python",), references=("CWE-396",),
       code_after='except (ValueError, KeyError) as exc:\n    ...'),
    _r("BUG-EMPTY-CATCH", "bug", "high",
       "Empty catch block",
       r"""\bcatch\s*\([^)]*\)\s*\{\s*\}""",
       "An empty catch discards the error, leaving the failure invisible in production.",
       "Log with context and decide explicitly: recover, wrap, or rethrow.",
       languages=("javascript", "typescript", "java", "csharp", "php", "kotlin"),
       references=("CWE-390",),
       code_after='catch (err) {\n  logger.error("payment failed", { err, orderId });\n  throw err;\n}'),
    _r("BUG-MUTABLE-DEFAULT", "bug", "high",
       "Mutable default argument",
       r"""\bdef\s+\w+\s*\([^)]*=\s*(?:\[\]|\{\}|set\(\)|dict\(\)|list\(\))""",
       "The default object is created once and shared across all calls, so mutations leak between invocations.",
       "Default to None and construct the collection inside the function.",
       languages=("python",), references=("CWE-665",),
       code_after='def add(item, bucket=None):\n    bucket = [] if bucket is None else bucket\n    bucket.append(item)\n    return bucket'),
    _r("BUG-OFF-BY-ONE-RANGE", "bug", "medium",
       "Loop bound includes the end index",
       r"""for\s+\w+\s+in\s+range\s*\(\s*len\([^)]+\)\s*\+\s*1|<=\s*(?:len\([^)]+\)|\w+\.length)\s*[;)]|for\s*\(.*<=\s*\w+\.length\s*;""",
       "Iterating to len()/length inclusive reads one element past the end.",
       "Use range(len(x)) or enumerate(x); in JS use i < arr.length.",
       languages=("python", "javascript", "typescript", "java", "c", "cpp"),
       references=("CWE-193",)),
    _r("BUG-UNCHECKED-NONE", "bug", "medium",
       "Possible None/undefined dereference",
       r"""\.get\([^)]*\)\.\w+|\bJSON\.parse\([^)]*\)\.\w+|\w+\s*=\s*re\.(?:search|match)\([^)]*\)\s*$""",
       "The expression can return None/undefined, and the immediate attribute access will raise.",
       "Check for the empty case (or use optional chaining / walrus) before dereferencing.",
       languages=("python", "javascript", "typescript"), references=("CWE-476",),
       code_after='match = re.search(pattern, text)\nif match is None:\n    return None\nreturn match.group(1)'),
    _r("BUG-FLOAT-MONEY", "bug", "medium",
       "Floating point used for currency",
       r"""(?i)\b(?:price|amount|total|cost|balance|fee|tax|money|revenue)\w*\s*(?:=|\+=|-=|\*)\s*\d+\.\d+|float\s*\(\s*(?:price|amount|total)""",
       "Binary floating point cannot represent most decimal fractions, so money arithmetic drifts.",
       "Use Decimal (or integer cents) for all currency calculations.",
       languages=("python", "java", "javascript", "typescript", "csharp"),
       references=("CWE-682", "CWE-1339"),
       code_after='from decimal import Decimal\ntotal = Decimal("19.99") * qty'),
    _r("BUG-ASYNC-MISSING-AWAIT", "bug", "high",
       "Coroutine call not awaited",
       r"""(?<!await\s)(?<!\.)(?:^|\s)(?:\w+_?async\w*|\w*(?:fetch|save|load|get|post|send|connect|sleep|query)\w*)\s*\([^)]*\)\s*;\s*$""",
       "Calling a coroutine without await does nothing and usually logs 'never awaited'.",
       "Add await (and make the enclosing function async).",
       languages=("javascript", "typescript"), references=("CWE-662",)),
    _r("BUG-PY-MISSING-AWAIT", "bug", "high",
       "await missing in async Python",
       r"""(?<!await )(?:asyncio\.sleep|asyncio\.gather)\s*\(""",
       "asyncio.sleep/gather return coroutines; without await the work never happens.",
       "Prefix the call with await.",
       languages=("python",), references=("CWE-662",),
       code_after='await asyncio.sleep(1)'),
    _r("BUG-RETURN-IN-FINALLY", "bug", "high",
       "return/continue inside finally",
       r"""\bfinally\s*:\s*$""",
       "A return or break inside finally silently swallows exceptions raised in try/except.",
       "Keep finally limited to cleanup and move the return out.",
       languages=("python", "java", "javascript"), references=("CWE-584",)),
    _r("BUG-TIMEOUT-MISSING", "bug", "medium",
       "Network call without a timeout",
       r"""\brequests\.(?:get|post|put|delete|patch|head)\s*\((?![^)]*timeout)|\bhttpx\.(?:get|post|AsyncClient)\s*\((?![^)]*timeout)|fetch\s*\(\s*[^)]*\)(?!\s*,\s*\{[^}]*signal)""",
       "Without a timeout a hung peer blocks the worker forever and can exhaust the pool.",
       "Always pass an explicit timeout (and consider retry/backoff).",
       languages=("python", "javascript", "typescript"), references=("CWE-400",),
       code_after='requests.get(url, timeout=(3.05, 10))'),
    _r("BUG-RESOURCE-LEAK", "bug", "medium",
       "Resource opened without a context manager",
       r"""(?<!with )\bopen\s*\([^)]*\)\s*(?:\.read\(\)|\.write\(|\s*$)""",
       "The file handle is only closed when GC runs, leaking descriptors under load.",
       "Use `with open(...) as f:` so the handle is always released.",
       languages=("python",), references=("CWE-404",),
       code_after='with open(path, "r", encoding="utf-8") as fh:\n    data = fh.read()'),
    _r("BUG-SWALLOWED-PROMISE", "bug", "medium",
       "Unhandled promise / missing catch",
       r"""\.then\s*\([^)]*\)\s*(?:;|$)(?!.*\.catch)""",
       "A promise chain without .catch produces an unhandled rejection and lost errors.",
       "Append .catch(...) or use try/await with try-catch.",
       languages=("javascript", "typescript"), references=("CWE-755",)),
    _r("BUG-INT-OVERFLOW-DIV", "bug", "low",
       "Integer division used where a float is expected",
       r"""\b(?:average|avg|mean|ratio|percent\w*|rate)\s*=\s*[^=].*\b\w+\s*//\s*\w+""",
       "// truncates to an integer, so averages and ratios silently lose precision.",
       "Use true division (/) and round only at presentation time.",
       languages=("python",), references=("CWE-682",)),
    _r("BUG-COMPARE-IS-NAN", "bug", "medium",
       "NaN compared with ==",
       r"""==\s*NaN|NaN\s*==""",
       "NaN is never equal to anything, including itself, so this test is always false.",
       "Use Number.isNaN(value) / math.isnan(value).",
       languages=("javascript", "typescript", "python"), references=("CWE-697",),
       code_after='if (Number.isNaN(value)) { ... }'),
    _r("BUG-LOOP-VAR-CLOSURE", "bug", "medium",
       "var declared inside a loop",
       r"""\bfor\s*\(\s*var\s+\w+""",
       "`var` is function-scoped, so closures created in the loop all capture the final value.",
       "Use let (block-scoped) in loops.",
       languages=("javascript",), references=("CWE-665",),
       code_after='for (let i = 0; i < items.length; i++) { ... }'),
]

# --------------------------------------------------------------------------
# PERFORMANCE
# --------------------------------------------------------------------------
PERF_RULES: List[Rule] = [
    _r("PERF-N-PLUS-1", "performance", "high",
       "Database query inside a loop (N+1)",
       r"""for\s+.*:?\s*$""",
       "Issuing one query per iteration produces N+1 round trips and collapses under load.",
       "Batch the query (IN clause / join / select_related / preloading) and index the result.",
       languages=("python", "javascript", "typescript", "java", "ruby", "go"),
       references=("CWE-1079",)),
    _r("PERF-SELECT-STAR", "performance", "low",
       "SELECT * in application code",
       r"""(?i)SELECT\s+\*\s+FROM""",
       "Fetching every column wastes bandwidth and breaks when the schema grows.",
       "Select only the columns you use; this also enables covering indexes.",
       languages=("python", "sql", "javascript", "java", "php"),
       code_after='SELECT id, email, created_at FROM users WHERE id = %s'),
    _r("PERF-STRING-CONCAT-LOOP", "performance", "medium",
       "String concatenation inside a loop",
       r"""\w+\s*\+=\s*["'`]""",
       "Strings are immutable, so += in a loop copies the whole buffer each pass (O(n^2)).",
       "Collect parts in a list and join once, or use io.StringIO / a builder.",
       languages=("python", "java", "javascript"),
       code_after='parts.append(chunk)\nresult = "".join(parts)'),
    _r("PERF-SLEEP-RETRY", "performance", "low",
       "Fixed sleep used as a retry/backoff",
       r"""\btime\.sleep\s*\(\s*\d{2,}|setTimeout\([^)]*,\s*\d{5,}\)|Thread\.sleep\(\s*\d{4,}""",
       "A long fixed sleep blocks a worker thread and does not adapt to load.",
       "Use exponential backoff with jitter, and prefer async waits where available.",
       languages=("python", "javascript", "java")),
    _r("PERF-REGEX-IN-LOOP", "performance", "medium",
       "Regex compiled inside a hot path",
       r"""\bre\.compile\s*\(|new\s+RegExp\s*\(""",
       "Compiling the same pattern repeatedly wastes CPU.",
       "Compile the pattern once at module scope and reuse it.",
       languages=("python", "javascript", "typescript"),
       code_after='_PATTERN = re.compile(r"^\\d+$")  # module level'),
    _r("PERF-KEYSET-IN-LOOP", "performance", "low",
       "Repeated len()/count inside a loop condition",
       r"""for\s*\(.*;\s*\w+\s*<\s*\w+\.length\s*;""",
       "The length property is re-read on every iteration.",
       "Hoist it into a local (or use for..of / forEach).",
       languages=("javascript", "typescript", "java")),
    _r("PERF-UNBOUNDED-CACHE", "performance", "medium",
       "Unbounded in-memory cache",
       r"""(?:lru_cache\(\s*maxsize\s*=\s*None|@cache\b|_cache\s*=\s*\{\})""",
       "An unbounded cache grows without limit and can exhaust process memory.",
       "Set maxsize, or use a TTL/LRU store (cachetools, Redis) with eviction.",
       languages=("python", "javascript"), references=("CWE-400",),
       code_after='@functools.lru_cache(maxsize=1024)'),
    _r("PERF-SYNC-IO-IN-ASYNC", "performance", "high",
       "Blocking I/O inside an async function",
       r"""\brequests\.(?:get|post)|\bopen\s*\(|\btime\.sleep\s*\(""",
       "Blocking calls inside an async def stall the whole event loop, killing concurrency.",
       "Use httpx.AsyncClient / aiofiles / asyncio.sleep, or offload via run_in_executor.",
       languages=("python",),
       code_after='async with httpx.AsyncClient(timeout=10) as client:\n    resp = await client.get(url)'),
    _r("PERF-READ-WHOLE-FILE", "performance", "low",
       "Whole file loaded into memory",
       r"""\.readlines\(\)|\.read\(\)\s*\.split|readAllBytes|fs\.readFileSync""",
       "Loading an entire file fails for large inputs and spikes memory.",
       "Stream line by line (iterate the handle / BufferedReader).",
       languages=("python", "java", "javascript"),
       code_after='with open(path, encoding="utf-8") as fh:\n    for line in fh:\n        process(line)'),
    _r("PERF-MISSING-PAGINATION", "performance", "medium",
       "Unbounded result set returned to a caller",
       r"""(?i)(?:\.all\(\)|findMany\s*\(\s*\)|\.find\s*\(\s*\{\s*\}\s*\)|SELECT\b(?!\s+DISTINCT\b)[^;\n]*\bFROM\b(?![^;\n]*\b(?:LIMIT|WHERE|OFFSET)\b))""",
       "Returning every row makes latency and memory grow with the table.",
       "Add pagination (LIMIT/OFFSET or keyset) and a sane page-size cap.",
       languages=("python", "javascript", "typescript", "sql", "ruby"),
       code_after='query.limit(page_size).offset((page - 1) * page_size)'),
]

# --------------------------------------------------------------------------
# QUALITY
# --------------------------------------------------------------------------
QUALITY_RULES: List[Rule] = [
    _r("QUA-DEBUG-LOG", "quality", "low",
       "Debug logging left in code",
       r"""\bconsole\.log\s*\(|^\s*print\s*\(|\bprint_r\s*\(|\bvar_dump\s*\(|System\.out\.print(?:ln)?\s*\(|fmt\.Println\(""",
       "Debug output shipped to production leaks internals and pollutes stdout.",
       "Use a real logger with levels, or delete the statement.",
       skip_in_tests=True,
       code_after='logger.info("order processed", extra={"order_id": order.id})'),
    _r("QUA-TODO", "quality", "info",
       "Unresolved TODO/FIXME/HACK marker",
       r"""\b(TODO|FIXME|HACK|XXX|BUG)\b\s*:?.*""",
       "A marker without an owner or ticket tends to outlive the problem it describes.",
       "Link it to a tracking issue, or resolve it now.",
       flags=re.IGNORECASE),
    _r("QUA-COMMENTED-CODE", "quality", "low",
       "Commented-out code block",
       r"""^\s*(?://|#)\s*(?:if|for|while|return|def|function|class|import|from|const|let|var|self\.|\w+\s*=)\b.*""",
       "Dead code in comments rots and confuses readers; version control already keeps it.",
       "Delete it and reference the commit in the PR description if needed."),
    _r("QUA-MAGIC-NUMBER", "quality", "low",
       "Magic number in logic",
       r"""(?<![\w.])(?:if|while|return|==|>=|<=|>|<)[^#\n]*\b(?:86400|3600|1024|60000|1000|300|500|100)\b""",
       "A bare numeric literal hides intent and makes the value hard to change safely.",
       "Extract it into a named constant (MAX_RETRIES, TIMEOUT_SECONDS).",
       languages=("python", "javascript", "typescript", "java", "go", "c", "cpp"),
       code_after='TIMEOUT_SECONDS = 30\nif elapsed > TIMEOUT_SECONDS:'),
    _r("QUA-GOD-LINE", "quality", "low",
       "Overly long line",
       r""".{121,}""",
       "Lines beyond ~120 characters hurt readability and diff review.",
       "Wrap arguments or extract a local variable."),
    _r("QUA-VAR-DECL", "quality", "low",
       "Legacy `var` declaration",
       r"""\bvar\s+\w+\s*=""",
       "`var` is function-scoped and hoisted, which causes subtle bugs.",
       "Use const by default, let when reassignment is needed.",
       languages=("javascript",),
       code_after='const total = items.reduce((a, b) => a + b, 0);'),
    _r("QUA-NESTED-IF", "quality", "medium",
       "Deeply nested conditional",
       r"""^\s{20,}(?:if|elif|else|for|while)\b""",
       "Indentation depth of 5+ makes the control flow hard to verify.",
       "Use guard clauses / early returns to flatten the nesting.",
       languages=("python",)),
    _r("QUA-DUPLICATE-LITERAL", "quality", "info",
       "Repeated string literal",
       r"""["'][A-Za-z_][\w\-]{2,}["']""",
       "The same literal repeated in several places should be a single named constant.",
       "Hoist it to a constant or an enum.",
       languages=("python", "javascript", "typescript", "java")),
    _r("QUA-LONG-PARAM-LIST", "quality", "medium",
       "Function with too many parameters",
       r"""\b(?:def|function|func|fn)\s+\w+\s*\((?:[^,)]*,){6,}""",
       "Seven-plus parameters signal a function doing too much and are easy to mis-order.",
       "Group related values into a dataclass/struct/options object.",
       languages=("python", "javascript", "typescript", "go", "rust", "java"),
       code_after='@dataclass\nclass RetryPolicy:\n    attempts: int = 3\n    backoff: float = 0.5\n\ndef fetch(url, policy: RetryPolicy): ...'),
    _r("QUA-NEGATIVE-LOGIC", "quality", "low",
       "Double negative in a condition",
       r"""\bnot\s+\w*(?:is|has|can|should)?_?not\b|\bif\s*\(\s*!\s*!\s*""",
       "Double negatives force the reader to invert twice and hide off-by-one logic errors.",
       "Rename to a positive predicate (is_valid instead of not_invalid).",
       languages=("python", "javascript", "typescript")),
    _r("QUA-BOOLEAN-PARAM", "quality", "low",
       "Boolean flag argument controlling behaviour",
       r"""\w+\(\s*[^)]*\b(?:True|False|true|false)\s*[,)]""",
       "A boolean flag parameter means the caller can't tell what it does and the function probably branches into two jobs.",
       "Split into two well-named functions, or use an enum/options object.",
       languages=("python", "javascript", "typescript", "java")),
]

# --------------------------------------------------------------------------
# BEST PRACTICES
# --------------------------------------------------------------------------
PRACTICE_RULES: List[Rule] = [
    _r("BP-NO-TYPE-HINTS", "best_practices", "low",
       "Public function without type hints",
       r"""^\s*(?:async\s+)?def\s+(?!_)\w+\s*\([^)]*\)\s*(?::\s*)?\w*[^:>]*:\s*$""",
       "Missing annotations weaken static analysis and IDE support.",
       "Annotate parameters and the return type (mypy --strict will then help you).",
       languages=("python",),
       code_after='def total_price(items: Sequence[Item]) -> Decimal:'),
    _r("BP-PRINT-NOT-LOGGER", "best_practices", "low",
       "print() used for operational output",
       r"""^\s*print\s*\(""",
       "print has no levels, timestamps or routing, so it is unusable in production logs.",
       "Use the logging module and configure handlers at the app boundary.",
       languages=("python",), skip_in_tests=True,
       code_after='logger = logging.getLogger(__name__)\nlogger.error("sync failed: %s", err)'),
    _r("BP-NO-DOCSTRING", "best_practices", "info",
       "Public API without a docstring",
       r"""^\s*(?:async\s+)?def\s+(?!_)\w+\s*\(""",
       "Public entry points should document arguments, return values and raised errors.",
       "Add a short docstring describing the contract, not the implementation.",
       languages=("python",)),
    _r("BP-GENERIC-EXCEPTION", "best_practices", "medium",
       "Raising or catching an overly generic exception",
       r"""\braise\s+Exception\s*\(|\bthrow\s+new\s+Error\s*\(\s*["'][a-z ]+["']\s*\)|catch\s*\(\s*Exception\s""",
       "Generic exceptions prevent callers from distinguishing recoverable failures.",
       "Define domain-specific exception types (ValidationError, NotFoundError).",
       languages=("python", "javascript", "typescript", "java"),
       code_after='raise ValidationError(f"invalid email: {email!r}")'),
    _r("BP-LOST-CONTEXT", "best_practices", "medium",
       "Exception re-raised without chaining",
       r"""\braise\s+\w+(?:Error|Exception)\s*\([^)]*\)\s*$""",
       "Re-raising without `from exc` discards the original traceback.",
       "Use `raise NewError(...) from exc` to preserve the cause chain.",
       languages=("python",),
       code_after='raise ServiceError("upstream failed") from exc'),
    _r("BP-NO-INPUT-VALIDATION", "best_practices", "medium",
       "Request data used without validation",
       r"""(?:request\.(?:json|form|args|GET|POST)|req\.(?:body|query|params))\s*(?:\[|\.get\(|\))""",
       "Reading request payloads straight into business logic skips validation and typing.",
       "Parse into a schema (pydantic, zod, marshmallow) at the boundary.",
       languages=("python", "javascript", "typescript", "php", "java"),
       references=("CWE-20",),
       code_after='class SignupIn(BaseModel):\n    email: EmailStr\n    age: int = Field(ge=0, le=130)\n\npayload = SignupIn.model_validate(request.json())'),
    _r("BP-HARDCODED-CONFIG", "best_practices", "low",
       "Configuration value hardcoded",
       r"""(?i)\b(?:port|host|database_url|db_url|redis_url|bucket|endpoint)\b\s*[:=]\s*["'][^"']+["']""",
       "Environment-specific values baked into source force a redeploy per environment.",
       "Read from environment variables with a validated default.",
       languages=("python", "javascript", "typescript", "java", "go"),
       code_after='PORT = int(os.getenv("PORT", "8000"))'),
    _r("BP-ASSERT-IN-PROD", "best_practices", "medium",
       "assert used for runtime validation",
       r"""^\s*assert\s+\w""",
       "Asserts are stripped under `python -O` / NODE_ENV production, so the check silently disappears.",
       "Raise an explicit exception for input that must be validated at runtime.",
       languages=("python",), skip_in_tests=True,
       code_after='if not user_id:\n    raise ValueError("user_id is required")'),
    _r("BP-NO-IDEMPOTENCY", "best_practices", "info",
       "State-changing GET-style handler",
       r"""@app\.(?:get|route)[^)]*\)\s*\ndef\s+\w*(?:delete|remove|create|update|save)\w*""",
       "Mutating state from a GET breaks caching, prefetchers and CSRF assumptions.",
       "Use POST/PUT/DELETE for mutations.",
       languages=("python",), references=("CWE-650",)),
]

ALL_RULES: List[Rule] = SECURITY_RULES + BUG_RULES + PERF_RULES + QUALITY_RULES + PRACTICE_RULES

# Rules that need file-level context rather than a single-line match.
_N_PLUS_1_QUERY = re.compile(
    r"""\b(?:execute|query|all\(\)|first\(\)|get\(|filter\(|find|findOne|select|fetch|save|update|delete)\s*\(""",
)
_LOOP_START = re.compile(r"^\s*(?:for|while)\b.*:\s*$|^\s*(?:for|while)\s*\(.*\)\s*\{?\s*$")


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    title: str
    file: str
    line: int
    end_line: int
    description: str
    suggestion: str
    snippet: str = ""
    code_after: str = ""
    confidence: float = 0.75
    source: str = "static"
    references: Tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "description": self.description,
            "suggestion": self.suggestion,
            "snippet": self.snippet,
            "code_after": self.code_after,
            "confidence": self.confidence,
            "source": self.source,
            "references": list(self.references),
        }


@dataclass
class FileMetrics:
    path: str
    language: str
    lines: int = 0
    code_lines: int = 0
    blank_lines: int = 0
    comment_lines: int = 0
    max_line_length: int = 0
    max_nesting: int = 0
    functions: int = 0
    longest_function: int = 0
    todo_count: int = 0
    duplicated_blocks: int = 0
    classes: int = 0
    complexity: int = 1

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    metrics: Dict[str, FileMetrics] = field(default_factory=dict)

    def by_severity(self) -> Dict[str, int]:
        counter = Counter(f.severity for f in self.findings)
        return {s: counter.get(s, 0) for s in SEVERITIES}

    def by_category(self) -> Dict[str, int]:
        counter = Counter(f.category for f in self.findings)
        return {c: counter.get(c, 0) for c in CATEGORIES}


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------
@lru_cache(maxsize=None)
def _comment_prefixes(language: str) -> Tuple[str, ...]:
    profile = profile_for(language)
    prefixes = []
    if profile.line_comment:
        prefixes.append(profile.line_comment)
    if language == "sql":
        prefixes.append("--")
    return tuple(prefixes)


def _is_comment(line: str, language: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if language in {"python", "javascript", "typescript"} and stripped.startswith(("*", '"""', "'''")):
        return True
    for prefix in _comment_prefixes(language):
        if stripped.startswith(prefix):
            return True
    return False


def _indent_unit(lines: Sequence[str]) -> int:
    """Detect the file's indent width so nesting depth is not understated.

    A 2-space-indented JS file would otherwise report half its real depth.
    """
    indents = set()
    for raw in lines:
        if not raw.strip():
            continue
        leading = len(raw) - len(raw.lstrip(" "))
        if leading and raw.lstrip(" ")[0:1] not in {"\t"}:
            indents.add(leading)
    if not indents:
        return 4
    smallest = min(indents)
    return smallest if smallest in {2, 3, 4, 8} else 4


def _nesting_depth(line: str, unit: int = 4) -> int:
    stripped = line.rstrip()
    if not stripped:
        return 0
    if stripped.lstrip().startswith("\t"):
        return len(stripped) - len(stripped.lstrip("\t"))
    indent = len(stripped) - len(stripped.lstrip())
    return indent // max(1, unit)


def compute_metrics(code: str, path: str, language: str) -> FileMetrics:
    lines = code.splitlines()
    metrics = FileMetrics(path=path, language=language, lines=len(lines))
    indent_unit = _indent_unit(lines)
    longest = 0
    current_fn_len = 0
    in_fn = False
    fn_indent = 0

    for raw in lines:
        stripped = raw.strip()
        metrics.max_line_length = max(metrics.max_line_length, len(raw.rstrip()))
        # TODO markers live in comments, so count them before the comment skip.
        if re.search(r"\b(?:TODO|FIXME|HACK|XXX)\b", stripped, re.IGNORECASE):
            metrics.todo_count += 1
        if not stripped:
            metrics.blank_lines += 1
            if in_fn:
                current_fn_len += 1
            continue
        if _is_comment(raw, language):
            metrics.comment_lines += 1
            continue
        metrics.code_lines += 1
        metrics.max_nesting = max(metrics.max_nesting, _nesting_depth(raw, indent_unit))
        if re.match(r"^\s*(?:class|interface)\s+\w+", raw):
            metrics.classes += 1
        if re.match(r"^\s*(?:async\s+)?(?:def|function|func|fn)\s+\w+|^[\w<>\[\], ]*\b\w+\s*\([^)]*\)\s*(?:->\s*[\w\[\], ]+\s*)?\{\s*$", raw):
            metrics.functions += 1
        metrics.complexity += len(re.findall(
            r"""\b(?:if|elif|else|for|while|case|when|catch|except|&&|\|\||\?|\bunless\b)\b""", raw))

        # crude function-length tracking via indentation (python-ish) / braces
        if re.match(r"^\s*(?:async\s+)?def\s+\w+|^\s*(?:export\s+)?(?:async\s+)?function\s+\w+", raw):
            if in_fn:
                metrics.longest_function = max(metrics.longest_function, current_fn_len)
            in_fn = True
            current_fn_len = 0
            fn_indent = len(raw) - len(raw.lstrip())
        elif in_fn:
            indent = len(raw) - len(raw.lstrip())
            if indent <= fn_indent and stripped:
                metrics.longest_function = max(metrics.longest_function, current_fn_len)
                in_fn = False
                current_fn_len = 0
            else:
                current_fn_len += 1
        longest = max(longest, len(raw))

    if in_fn:
        metrics.longest_function = max(metrics.longest_function, current_fn_len)
    metrics.duplicated_blocks = _duplicate_block_count(lines)
    return metrics


def _duplicate_block_count(lines: Sequence[str], window: int = 4) -> int:
    """Hash sliding windows of normalised code lines to spot copy-paste."""
    normalized = [re.sub(r"\s+", " ", ln.strip()) for ln in lines if ln.strip() and not ln.strip().startswith("#")]
    seen: Dict[str, int] = defaultdict(int)
    for i in range(len(normalized) - window + 1):
        block = "\n".join(normalized[i : i + window])
        if len(block) < 40:
            continue
        digest = hashlib.md5(block.encode("utf-8")).hexdigest()
        seen[digest] += 1
    return sum(count - 1 for count in seen.values() if count > 1)


def _context_snippet(lines: Sequence[str], index: int, radius: int = 2) -> str:
    low = max(0, index - radius)
    high = min(len(lines), index + radius + 1)
    return "\n".join(f"{n + 1:>{5}} | {lines[n]}" for n in range(low, high))


def scan_code(
    code: str,
    path: str = "input",
    language: Optional[str] = None,
    focus_lines: Optional[Iterable[int]] = None,
    include_categories: Optional[Iterable[str]] = None,
) -> ScanResult:
    """Run every applicable rule against a single source file."""
    language = language or detect_language(code, path)
    result = ScanResult()
    result.metrics[path] = compute_metrics(code, path, language)

    lines = code.splitlines()
    focus = set(focus_lines) if focus_lines is not None else None
    wanted = set(include_categories) if include_categories else set(CATEGORIES)
    in_tests = is_test_file(path)

    # Precomputed once per file so the rule loop stays linear:
    #   comment_flags — which lines are comments (avoids re-testing per rule)
    #   def_index     — enclosing-function lookup for async/indentation checks
    comment_flags = [_is_comment(raw, language) for raw in lines]
    def_index = _build_def_index(lines)

    for rule in ALL_RULES:
        if rule.category not in wanted:
            continue
        # When the language is unknown, the rule's own pattern is the only
        # evidence we have — apply every rule rather than silently skipping.
        if rule.languages and language not in rule.languages and language != "plaintext":
            continue
        if rule.skip_in_tests and in_tests:
            continue
        try:
            matcher = rule.compiled
        except re.error:
            continue
        if rule.id in _STRUCTURAL_RULE_IDS:
            continue  # handled by _scan_structural / _scan_duplicates below

        # Hoisted out of the line loop: these were previously re-derived per line.
        skips_comment = rule.category in _COMMENT_BLIND_CATEGORIES
        for index, raw in enumerate(lines):
            line_no = index + 1
            if focus is not None and line_no not in focus:
                continue
            # Cheap checks first. The regex match gates every expensive
            # structural predicate below it — running those unconditionally was
            # O(n^2) on large files.
            if not matcher.search(raw):
                continue
            if skips_comment and comment_flags[index]:
                continue
            if not _rule_context_ok(rule, lines, index, raw, language, def_index):
                continue

            result.findings.append(Finding(
                rule_id=rule.id,
                category=rule.category,
                severity=rule.severity,
                title=rule.title,
                file=path,
                line=line_no,
                end_line=line_no,
                description=rule.message,
                suggestion=rule.suggestion,
                snippet=_context_snippet(lines, index),
                code_after=rule.code_after,
                confidence=_confidence_for(rule, raw),
                references=rule.references,
            ))

    _scan_structural(lines, path, language, result, focus)
    _scan_duplicates(lines, path, language, result, focus)
    result.findings = _collapse_rule_families(result.findings)
    result.findings.sort(key=lambda f: (-SEVERITY_WEIGHT.get(f.severity, 0), f.line))
    # Keep the highest-severity findings if a pathological file floods the scan.
    if len(result.findings) > MAX_FINDINGS_PER_SCAN:
        result.findings = result.findings[:MAX_FINDINGS_PER_SCAN]
    return result


def _rule_family(rule_id: str) -> str:
    """`SEC-SQLI-CONCAT` and `SEC-SQLI-BUILD` are the same underlying problem."""
    parts = rule_id.split("-")
    return "-".join(parts[:2]) if len(parts) > 2 else rule_id


def _collapse_rule_families(findings: List[Finding]) -> List[Finding]:
    """Keep one finding per (line, rule family).

    Several rules describe variants of one problem (SQL built by concatenation
    vs. assembled before execution). Reporting all of them is noise, so the
    strongest one wins and absorbs the others' references.
    """
    best: Dict[Tuple[str, int, str], Finding] = {}
    for finding in findings:
        key = (finding.file, finding.line, _rule_family(finding.rule_id))
        current = best.get(key)
        if current is None:
            best[key] = finding
            continue
        stronger = (
            SEVERITY_WEIGHT.get(finding.severity, 0) > SEVERITY_WEIGHT.get(current.severity, 0)
            or (finding.severity == current.severity and finding.confidence > current.confidence)
        )
        winner, loser = (finding, current) if stronger else (current, finding)
        winner.references = tuple(dict.fromkeys([*winner.references, *loser.references]))
        best[key] = winner
    return list(best.values())


#: Rules evaluated by the structural passes rather than the line loop.
_STRUCTURAL_RULE_IDS = {"PERF-N-PLUS-1", "QUA-DUPLICATE-LITERAL"}

#: Categories whose rules must not fire on comment lines.
_COMMENT_BLIND_CATEGORIES = {"bug", "performance", "security"}

_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+\w+|^\s*(?:export\s+)?(?:async\s+)?function\s+\w+")
_FINALLY_RETURN_RE = re.compile(r"finally\s*:\s*\n\s*(?:return|break|continue)")
_JS_ASYNC_HINT_RE = re.compile(r"\b(?:async|await|Promise)\b")
_DOCSTRING_STARTS = ('"""', "'''", "#", "//")


def _indent_of(raw: str) -> int:
    return len(raw) - len(raw.lstrip())


def _build_def_index(lines: Sequence[str]) -> List[Tuple[int, int, bool]]:
    """(line index, indent, is_async) for every function definition.

    Lets `_inside_async` scan a handful of entries instead of the whole file.
    """
    entries: List[Tuple[int, int, bool]] = []
    for index, raw in enumerate(lines):
        if _DEF_RE.match(raw):
            entries.append((index, _indent_of(raw), raw.lstrip().startswith("async")))
    return entries


def _rule_context_ok(
    rule: Rule,
    lines: Sequence[str],
    index: int,
    raw: str,
    language: str,
    def_index: List[Tuple[int, int, bool]],
) -> bool:
    """Expensive, match-gated predicates. Only called after the regex matched."""
    if rule.id == "BP-NO-TYPE-HINTS":
        # A `->` or `:` annotation after the parameter list means it is typed.
        if ")" in raw and ":" in raw.split(")")[-1]:
            return False
        return True

    if rule.id == "BP-NO-DOCSTRING":
        nxt = lines[index + 1].strip() if index + 1 < len(lines) else ""
        return not nxt.startswith(_DOCSTRING_STARTS)

    if rule.id == "BUG-RETURN-IN-FINALLY":
        return bool(_FINALLY_RETURN_RE.search("\n".join(lines[index : index + 4])))

    if rule.id == "PERF-SYNC-IO-IN-ASYNC":
        return _inside_async(lines, index, def_index)

    if rule.id == "BUG-ASYNC-MISSING-AWAIT" and language in {"javascript", "typescript"}:
        return bool(_JS_ASYNC_HINT_RE.search("\n".join(lines[max(0, index - 30) : index])))

    return True


def _inside_async(lines: Sequence[str], index: int,
                  def_index: Optional[List[Tuple[int, int, bool]]] = None) -> bool:
    """Is `index` lexically inside an `async def`?"""
    target_indent = _indent_of(lines[index])
    entries = def_index if def_index is not None else _build_def_index(lines)
    for def_line, def_indent, is_async in reversed(entries):
        if def_line >= index:
            continue
        if def_indent < target_indent:
            return is_async
    return False


def _confidence_for(rule: Rule, line: str) -> float:
    """Downgrade rules that fire on ambiguous text."""
    base = {"critical": 0.9, "high": 0.85, "medium": 0.75, "low": 0.65, "info": 0.55}[rule.severity]
    if rule.id == "QUA-BOOLEAN-PARAM" and re.search(r"(?i)\b(is|has|enable|allow|force|verbose|debug)\w*\s*=", line):
        return 0.35  # named boolean config is usually fine
    if rule.id == "QUA-TODO":
        return 0.95
    if rule.id == "BP-ASSERT-IN-PROD":
        return 0.6
    return base


def _scan_structural(lines: Sequence[str], path: str, language: str, result: ScanResult, focus: Optional[set]) -> None:
    """Loop-carried query detection (N+1) — needs two-line context."""
    if language in {"markdown", "json", "yaml", "html", "css", "plaintext"}:
        return
    loop_stack: List[Tuple[int, int]] = []
    for index, raw in enumerate(lines):
        line_no = index + 1
        indent = len(raw) - len(raw.lstrip()) if language == "python" else 0
        if _LOOP_START.match(raw):
            loop_stack.append((line_no, indent))
            continue
        if loop_stack and _N_PLUS_1_QUERY.search(raw) and not _is_comment(raw, language):
            opener, opener_indent = loop_stack[-1]
            if language != "python" or indent > opener_indent:
                if focus is None or line_no in focus:
                    result.findings.append(Finding(
                        rule_id="PERF-N-PLUS-1",
                        category="performance",
                        severity="high",
                        title="Database/IO query inside a loop (N+1)",
                        file=path,
                        line=line_no,
                        end_line=line_no,
                        description=(
                            f"This call sits inside the loop that starts at line {opener}, so it runs once "
                            "per iteration. With N rows that is N+1 round trips and latency that grows linearly."
                        ),
                        suggestion=(
                            "Fetch everything in one query before the loop (WHERE id IN (...) / join / "
                            "select_related / includes), build a dict keyed by id, then look up in memory."
                        ),
                        snippet=_context_snippet(lines, index, radius=3),
                        code_after="rows = Model.objects.filter(id__in=[o.id for o in orders]).in_bulk()\nfor order in orders:\n    item = rows.get(order.id)",
                        confidence=0.7,
                        references=("CWE-1079",),
                    ))
        if loop_stack and raw.strip() in {"}", "});", "end"}:
            loop_stack.pop()


def _scan_duplicates(lines: Sequence[str], path: str, language: str, result: ScanResult, focus: Optional[set]) -> None:
    window = 5
    normalized = [(re.sub(r"\s+", " ", ln.strip()), i) for i, ln in enumerate(lines) if ln.strip()]
    if len(normalized) < window * 2:
        return
    seen: Dict[str, int] = {}
    reported_per_digest: Counter = Counter()
    total_reported = 0

    for start in range(len(normalized) - window + 1):
        # Hard caps: a pathological file (e.g. generated or highly repetitive
        # code) can match thousands of windows. Emitting thousands of identical
        # findings is useless to a reviewer and quadratic in cost, so collapse
        # repeats and stop early.
        if total_reported >= MAX_DUPLICATE_FINDINGS:
            break
        block = "\n".join(text for text, _ in normalized[start : start + window])
        if len(block) < 60 or block.lstrip().startswith(("#", "//")):
            continue
        digest = hashlib.md5(block.encode()).hexdigest()
        line_no = normalized[start][1] + 1
        if digest in seen:
            first = seen[digest]
            if abs(first - line_no) < window:
                continue
            if reported_per_digest[digest] >= MAX_REPEATS_PER_BLOCK:
                continue
            if focus is not None and line_no not in focus:
                continue
            reported_per_digest[digest] += 1
            total_reported += 1
            result.findings.append(Finding(
                rule_id="QUA-DUPLICATE-BLOCK",
                category="quality",
                severity="medium",
                title="Duplicated code block",
                file=path,
                line=line_no,
                end_line=normalized[start + window - 1][1] + 1,
                description=(
                    f"These {window} lines are identical to lines {first}-{first + window - 1} in this file."
                    + (
                        " This block repeats many times — the duplication is systemic, not incidental."
                        if reported_per_digest[digest] >= MAX_REPEATS_PER_BLOCK else ""
                    )
                ),
                suggestion="Extract a shared helper function so the copies cannot drift apart.",
                snippet=_context_snippet(lines, normalized[start][1], radius=window // 2),
                confidence=0.8,
            ))
        else:
            seen[digest] = line_no


def scan_diff(diffset, include_categories: Optional[Iterable[str]] = None) -> ScanResult:
    """Scan only the lines a diff touched."""
    combined = ScanResult()
    for file_diff in diffset.files:
        added = file_diff.added
        if not added:
            continue
        code = "\n".join(text for _, text in added)
        numbers = [n for n, _ in added]
        sub = scan_code(
            code,
            path=file_diff.path,
            focus_lines=set(range(1, len(numbers) + 1)),
            include_categories=include_categories,
        )
        # remap relative line numbers back to absolute new-file numbers
        for finding in sub.findings:
            offset = finding.line - 1
            if 0 <= offset < len(numbers):
                finding.line = numbers[offset]
                end_offset = min(finding.end_line - 1, len(numbers) - 1)
                finding.end_line = numbers[end_offset]
            else:
                continue
            combined.findings.append(finding)
        combined.metrics[file_diff.path] = sub.metrics.get("input") or list(sub.metrics.values())[0]
        combined.metrics[file_diff.path].path = file_diff.path
    combined.findings.sort(key=lambda f: (-SEVERITY_WEIGHT.get(f.severity, 0), f.file, f.line))
    return combined


def summarise_findings(findings: Iterable[Finding]) -> str:
    """Compact text form used as pre-scan hints in the LLM prompt."""
    items = list(findings)
    by_file: Dict[str, List[Finding]] = defaultdict(list)
    for finding in items:
        by_file[finding.file].append(finding)
    chunks = []
    shown = 0
    for path, file_findings in by_file.items():
        chunks.append(f"### {path}")
        for item in sorted(file_findings, key=lambda f: f.line):
            if shown >= MAX_HINTS_IN_PROMPT:
                break
            refs = f" [{', '.join(item.references)}]" if item.references else ""
            chunks.append(
                f"- L{item.line} ({item.category}/{item.severity}) {item.title}{refs}"
            )
            shown += 1
        if shown >= MAX_HINTS_IN_PROMPT:
            remaining = len(items) - shown
            if remaining > 0:
                chunks.append(f"- …and {remaining} more (truncated to keep the prompt small)")
            break
    return "\n".join(chunks)
