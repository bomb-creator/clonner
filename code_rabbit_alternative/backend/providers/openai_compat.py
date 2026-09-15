"""OpenAI-compatible chat completions client.

One implementation covers every free-tier host that speaks the OpenAI wire
format: Groq, OpenRouter, Together, Cerebras, DeepInfra, Mistral, SambaNova,
xAI, and local Ollama / LM Studio.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from .base import ChatMessage, CompletionResult, LLMProvider, ModelSpec, ProviderError, elapsed_ms


class OpenAICompatProvider(LLMProvider):
    id = "openai-compat"
    label = "OpenAI-compatible"
    requires_key = True

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 90.0,
        *,
        provider_id: Optional[str] = None,
        label: Optional[str] = None,
        models: Optional[List[ModelSpec]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        docs_url: str = "",
        requires_key: bool = True,
    ):
        super().__init__(api_key=api_key, base_url=base_url, timeout=timeout)
        if provider_id:
            self.id = provider_id
        if label:
            self.label = label
        if models:
            self.models = models
        if docs_url:
            self.docs_url = docs_url
        self.requires_key = requires_key
        self.extra_headers = extra_headers or {}

    # ------------------------------------------------------------------
    def _headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self.extra_headers,
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _payload(
        self,
        messages: List[ChatMessage],
        model: str,
        temperature: float,
        max_tokens: int,
        json_mode: bool,
        stream: bool = False,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": model,
            "messages": [m.to_openai() for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        if stream:
            payload["stream"] = True
        # Ollama/LM Studio reject unknown fields; Groq ignores them. Keep it plain.
        if self.id == "groq":
            payload.pop("stream_options", None)
        return payload

    async def _post(self, client: httpx.AsyncClient, payload: Dict[str, Any]) -> httpx.Response:
        url = f"{(self.base_url or '').rstrip('/')}/chat/completions"
        response = await client.post(url, headers=self._headers(), json=payload)
        if response.status_code >= 400:
            raise self._error(response)
        return response

    def _error(self, response: httpx.Response) -> ProviderError:
        try:
            body = response.json()
            message = body.get("error", {}).get("message") or json.dumps(body)[:400]
        except Exception:
            message = response.text[:400]
        retryable = response.status_code in {408, 409, 425, 429, 500, 502, 503, 504}
        hint = ""
        if response.status_code == 429:
            hint = " Rate limited — the free tier quota is exhausted or the request rate is too high."
        elif response.status_code == 401:
            hint = " The API key was rejected."
        elif response.status_code == 400 and "context" in message.lower():
            hint = " The prompt exceeds the model's context window — reduce the input or pick a larger model."
        return ProviderError(
            f"{self.label} returned HTTP {response.status_code}: {message}{hint}",
            status=response.status_code,
            retryable=retryable,
            detail=message,
        )

    # ------------------------------------------------------------------
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
        if self.requires_key and not self.api_key:
            raise ProviderError(f"{self.label} needs an API key. Add it in Settings or set the env var.")

        payload = self._payload(messages, model, temperature, max_tokens, json_mode)
        start = time.perf_counter()
        attempt = 0
        last_error: Optional[ProviderError] = None

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            while attempt <= max_retries:
                attempt += 1
                try:
                    response = await self._post(client, payload)
                    data = response.json()
                    choices = data.get("choices") or []
                    if not choices:
                        raise ProviderError(f"{self.label} returned no choices: {json.dumps(data)[:200]}")
                    text = choices[0].get("message", {}).get("content") or ""
                    usage = data.get("usage") or {}
                    return CompletionResult(
                        text=text,
                        model=data.get("model", model),
                        provider=self.id,
                        prompt_tokens=usage.get("prompt_tokens", 0),
                        completion_tokens=usage.get("completion_tokens", 0),
                        latency_ms=elapsed_ms(start),
                        attempts=attempt,
                        raw=data,
                    )
                except ProviderError as exc:
                    last_error = exc
                    if not exc.retryable or attempt > max_retries:
                        raise
                except httpx.TimeoutException as exc:
                    last_error = ProviderError(f"{self.label} timed out after {self.timeout}s", retryable=True, detail=str(exc))
                    if attempt > max_retries:
                        raise last_error from exc
                except httpx.HTTPError as exc:
                    raise ProviderError(f"{self.label} network error: {exc}", retryable=False) from exc
                await asyncio.sleep(min(2 ** attempt * 0.4, 4))

        raise last_error or ProviderError(f"{self.label} failed")

    async def stream(
        self,
        messages: List[ChatMessage],
        *,
        model: str,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        json_mode: bool = False,
    ) -> AsyncIterator[str]:
        payload = self._payload(messages, model, temperature, max_tokens, json_mode, stream=True)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            url = f"{(self.base_url or '').rstrip('/')}/chat/completions"
            async with client.stream("POST", url, headers=self._headers(), json=payload) as response:
                if response.status_code >= 400:
                    body = await response.aread()
                    raise ProviderError(
                        f"{self.label} stream failed HTTP {response.status_code}: {body.decode(errors='ignore')[:300]}",
                        status=response.status_code,
                    )
                async for line in response.aiter_lines():
                    if not line or not line.startswith("data:"):
                        continue
                    data = line[len("data:") :].strip()
                    if data == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    delta = (chunk.get("choices") or [{}])[0].get("delta", {})
                    piece = delta.get("content")
                    if piece:
                        yield piece
