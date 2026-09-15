"""Provider abstraction.

Every backend (Groq, Gemini, OpenRouter, local Ollama, offline demo) implements
`LLMProvider`, so agents never care which one is active.
"""
from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional


class ProviderError(RuntimeError):
    """Raised when a provider call fails in a way the caller should surface."""

    def __init__(self, message: str, *, status: Optional[int] = None, retryable: bool = False, detail: Any = None):
        super().__init__(message)
        self.status = status
        self.retryable = retryable
        self.detail = detail


@dataclass
class ChatMessage:
    role: str  # system | user | assistant
    content: str

    def to_openai(self) -> Dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass
class CompletionResult:
    text: str
    model: str
    provider: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: int = 0
    attempts: int = 1
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


@dataclass
class ModelSpec:
    id: str
    label: str
    context_window: int = 32_000
    free: bool = True
    recommended: bool = False
    supports_json: bool = True
    max_output_tokens: int = 4096


class LLMProvider(abc.ABC):
    """Minimal interface every backend implements."""

    id: str = "base"
    label: str = "Base"
    docs_url: str = ""
    requires_key: bool = True
    models: List[ModelSpec] = []

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None, timeout: float = 90.0):
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout

    @abc.abstractmethod
    async def complete(
        self,
        messages: List[ChatMessage],
        *,
        model: str,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        json_mode: bool = False,
    ) -> CompletionResult:
        """Single-shot completion."""

    async def stream(
        self,
        messages: List[ChatMessage],
        *,
        model: str,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        json_mode: bool = False,
    ) -> AsyncIterator[str]:
        """Optional token streaming; defaults to a single chunk."""
        result = await self.complete(
            messages, model=model, temperature=temperature,
            max_tokens=max_tokens, json_mode=json_mode,
        )
        yield result.text

    def is_configured(self) -> bool:
        return bool(self.api_key) if self.requires_key else True

    def describe(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "docs_url": self.docs_url,
            "requires_key": self.requires_key,
            "configured": self.is_configured(),
            "base_url": self.base_url,
            "models": [m.__dict__ for m in self.models],
        }


def elapsed_ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)
