"""Google Gemini (AI Studio) provider — generous free tier, no credit card.

Uses the `generateContent` REST endpoint directly so no SDK is required.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from .base import ChatMessage, CompletionResult, LLMProvider, ModelSpec, ProviderError, elapsed_ms

BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

MODELS = [
    ModelSpec("gemini-2.0-flash", "Gemini 2.0 Flash", 1_000_000, True, True, True, 8192),
    ModelSpec("gemini-2.0-flash-lite", "Gemini 2.0 Flash-Lite", 1_000_000, True, False, True, 8192),
    ModelSpec("gemini-1.5-flash", "Gemini 1.5 Flash", 1_000_000, True, False, True, 8192),
    ModelSpec("gemini-1.5-flash-8b", "Gemini 1.5 Flash-8B", 1_000_000, True, False, True, 4096),
    ModelSpec("gemini-1.5-pro", "Gemini 1.5 Pro", 2_000_000, True, False, True, 8192),
]


class GeminiProvider(LLMProvider):
    id = "gemini"
    label = "Google Gemini"
    docs_url = "https://aistudio.google.com/app/apikey"
    requires_key = True
    models = MODELS

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None, timeout: float = 90.0):
        super().__init__(api_key=api_key, base_url=base_url or BASE_URL, timeout=timeout)

    def _payload(
        self,
        messages: List[ChatMessage],
        temperature: float,
        max_tokens: int,
        json_mode: bool,
    ) -> Dict[str, Any]:
        system = [m.content for m in messages if m.role == "system"]
        turns: List[Dict[str, Any]] = []
        for message in messages:
            if message.role == "system":
                continue
            role = "model" if message.role == "assistant" else "user"
            turns.append({"role": role, "parts": [{"text": message.content}]})
        if not turns:
            turns = [{"role": "user", "parts": [{"text": ""}]}]

        generation: Dict[str, Any] = {
            "temperature": temperature,
            "maxOutputTokens": max_tokens,
            "topP": 0.95,
        }
        if json_mode:
            generation["responseMimeType"] = "application/json"

        payload: Dict[str, Any] = {"contents": turns, "generationConfig": generation}
        if system:
            payload["systemInstruction"] = {"parts": [{"text": "\n\n".join(system)}]}
        # Grounded, deterministic reviews: turn off creative grounding tools.
        payload["safetySettings"] = [
            {"category": cat, "threshold": "BLOCK_NONE"}
            for cat in ("HARM_CATEGORY_HARASSMENT", "HARM_CATEGORY_HATE_SPEECH",
                        "HARM_CATEGORY_SEXUALLY_EXPLICIT", "HARM_CATEGORY_DANGEROUS_CONTENT")
        ]
        return payload

    async def complete(
        self,
        messages: List[ChatMessage],
        *,
        model: str,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        json_mode: bool = False,
        max_retries: int = 2,
    ) -> CompletionResult:
        if not self.api_key:
            raise ProviderError("Google Gemini needs an API key (free at aistudio.google.com/app/apikey).")

        url = f"{self.base_url.rstrip('/')}/models/{model}:generateContent?key={self.api_key}"
        payload = self._payload(messages, temperature, max_tokens, json_mode)
        start = time.perf_counter()
        attempt = 0
        last_error: Optional[ProviderError] = None

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            while attempt <= max_retries:
                attempt += 1
                try:
                    response = await client.post(url, json=payload, headers={"Content-Type": "application/json"})
                    if response.status_code >= 400:
                        raise self._error(response)
                    data = response.json()
                    text = self._extract_text(data)
                    if not text:
                        raise ProviderError(
                            "Gemini returned no text. The response may have been blocked: "
                            f"{json.dumps(data.get('promptFeedback', {}))[:200]}"
                        )
                    usage = data.get("usageMetadata") or {}
                    return CompletionResult(
                        text=text,
                        model=data.get("modelVersion", model),
                        provider=self.id,
                        prompt_tokens=usage.get("promptTokenCount", 0),
                        completion_tokens=usage.get("candidatesTokenCount", 0),
                        latency_ms=elapsed_ms(start),
                        attempts=attempt,
                        raw=data,
                    )
                except ProviderError as exc:
                    last_error = exc
                    if not exc.retryable or attempt > max_retries:
                        raise
                except httpx.TimeoutException as exc:
                    last_error = ProviderError(f"Gemini timed out after {self.timeout}s", retryable=True, detail=str(exc))
                    if attempt > max_retries:
                        raise last_error from exc
                except httpx.HTTPError as exc:
                    raise ProviderError(f"Gemini network error: {exc}") from exc
                await asyncio.sleep(min(2 ** attempt * 0.5, 5))

        raise last_error or ProviderError("Gemini failed")

    @staticmethod
    def _extract_text(data: Dict[str, Any]) -> str:
        parts: List[str] = []
        for candidate in data.get("candidates") or []:
            for part in (candidate.get("content") or {}).get("parts") or []:
                if isinstance(part, dict) and part.get("text"):
                    parts.append(part["text"])
        return "".join(parts)

    def _error(self, response: httpx.Response) -> ProviderError:
        try:
            body = response.json()
            message = body.get("error", {}).get("message", json.dumps(body)[:300])
        except Exception:
            message = response.text[:300]
        retryable = response.status_code in {429, 500, 503}
        hint = ""
        if response.status_code == 429:
            hint = " Free-tier quota reached — wait for the per-minute reset or switch provider."
        elif response.status_code in {400, 403} and "API key" in message:
            hint = " Check the key at aistudio.google.com/app/apikey."
        return ProviderError(f"Gemini HTTP {response.status_code}: {message}{hint}",
                             status=response.status_code, retryable=retryable, detail=message)

    async def stream(
        self,
        messages: List[ChatMessage],
        *,
        model: str,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        json_mode: bool = False,
    ) -> AsyncIterator[str]:
        if not self.api_key:
            raise ProviderError("Google Gemini needs an API key.")
        url = f"{self.base_url.rstrip('/')}/models/{model}:streamGenerateContent?alt=sse&key={self.api_key}"
        payload = self._payload(messages, temperature, max_tokens, json_mode)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            async with client.stream("POST", url, json=payload, headers={"Content-Type": "application/json"}) as response:
                if response.status_code >= 400:
                    body = await response.aread()
                    raise ProviderError(f"Gemini stream HTTP {response.status_code}: {body.decode(errors='ignore')[:300]}")
                async for line in response.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    try:
                        chunk = json.loads(line[len("data:") :].strip())
                    except json.JSONDecodeError:
                        continue
                    text = self._extract_text(chunk)
                    if text:
                        yield text
