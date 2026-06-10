from __future__ import annotations

import uuid
import logging
from typing import Optional

import httpx
from openai import AsyncOpenAI, APIConnectionError, APITimeoutError, BadRequestError, RateLimitError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

from ..config import LlmConfig
from ..contracts.enums import Role
from .usage import TokenUsage, UsageLedger


# The minimax/ollama proxy intermittently returns a 400 that is actually a transient
# throttle (e.g. '...does not support image input ... reset after 11s' even though no
# image is sent). Treat these — and rate-limit/overload signals — as retryable so a
# single flaky response doesn't crash the whole pipeline run.
_TRANSIENT_400_HINTS = ("image input", "reset after", "rate limit", "ratelimit",
                        "overloaded", "too many", "try again", "temporarily")


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, (APIConnectionError, APITimeoutError, RateLimitError, httpx.TransportError)):
        return True
    if isinstance(exc, BadRequestError):
        msg = str(getattr(exc, "message", "") or exc).lower()
        return any(h in msg for h in _TRANSIENT_400_HINTS)
    return False

log = logging.getLogger("marl3.llm")


class EmptyLLMResponse(RuntimeError):
    """Raised when the model yields no usable visible content after all retries.

    Returning "" here would silently corrupt the agent chain (hunter→0 bugs,
    Blue→default REVISE, exec→0 requests). Callers should fail the bug/run loudly.
    """


class LLMClient:
    """Single OpenAI-compatible client used by all agents.

    - One instance per run, shared across all roles.
    - Model selected per-role from config.
    - All calls logged to UsageLedger.
    """

    def __init__(self, config: LlmConfig, ledger: Optional[UsageLedger] = None) -> None:
        self._cfg = config
        self._ledger = ledger or UsageLedger()
        self._client = AsyncOpenAI(
            base_url=config.base_url,
            api_key=config.api_key,
            timeout=config.timeout_s,
        )

    def model_for(self, role: Role | str) -> str:
        role_str = role.value if isinstance(role, Role) else role
        return getattr(self._cfg.models, role_str, "gpt-4.1")

    async def chat(
        self,
        messages: list[dict],
        role: Role | str,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        call_id: Optional[str] = None,
    ) -> str:
        """Send a chat completion and return text. Retries on error AND on empty content.

        Empty-but-successful responses (reasoning model burned the whole budget on
        hidden reasoning) are a silent failure mode — we retry them with a larger
        budget instead of returning "" downstream.
        """
        model = self.model_for(role)
        cid = call_id or str(uuid.uuid4())[:8]
        for attempt in range(3):
            content, finish_reason = await self._one_call(
                messages, role, model, temperature,
                max_tokens * (attempt + 1),  # grow budget if reasoning starved/truncated content
                cid,
            )
            truncated = finish_reason == "length"
            if content.strip() and not truncated:
                return content
            why = "truncated (finish=length)" if truncated else "empty"
            log.warning(f"LLM {why} from model={model} (attempt {attempt+1}/3) — retrying with larger budget")
        # Never return "" silently — that corrupts every downstream parser.
        raise EmptyLLMResponse(f"No usable content from model={model} role={role} after 3 attempts")

    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=1, min=3, max=30),
        retry=retry_if_exception(_is_retryable),
        reraise=True,
    )
    async def _one_call(
        self, messages: list[dict], role, model: str, temperature: float, max_tokens: int, cid: str
    ) -> tuple[str, Optional[str]]:
        log.debug(f"LLM call role={role} model={model} id={cid} msgs={len(messages)} max_tokens={max_tokens}")

        # Stream and accumulate. Many OpenAI-compatible proxies (and reasoning
        # models like minimax/deepseek) force SSE streaming; a non-stream call
        # then fails to parse. Streaming handles both, and lets us capture
        # `reasoning_content` as a fallback when `content` stays empty.
        stream = await self._client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
            stream_options={"include_usage": True},
        )

        content_parts: list[str] = []
        reasoning_parts: list[str] = []
        usage = None
        finish_reason = None
        async for chunk in stream:
            if getattr(chunk, "usage", None):
                usage = chunk.usage
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            if getattr(delta, "content", None):
                content_parts.append(delta.content)
            if getattr(delta, "reasoning_content", None):
                reasoning_parts.append(delta.reasoning_content)
            if chunk.choices[0].finish_reason:
                finish_reason = chunk.choices[0].finish_reason

        content = "".join(content_parts).strip()
        if not content:
            # Last-resort fallback: some proxies/reasoning models emit the actual answer
            # ONLY in reasoning_content when content stays empty. Use it but flag via the
            # caller's empty/length retry — it is not a clean structured channel.
            reasoning = "".join(reasoning_parts).strip()
            if reasoning:
                log.debug(f"Using reasoning_content fallback ({len(reasoning)} chars) for {model}")
                content = reasoning

        if usage and self._ledger:
            self._ledger.record(TokenUsage(
                prompt_tokens=getattr(usage, "prompt_tokens", 0),
                completion_tokens=getattr(usage, "completion_tokens", 0),
                role=str(role),
                model=model,
                call_id=cid,
            ))

        return content, finish_reason

    async def close(self) -> None:
        await self._client.close()
