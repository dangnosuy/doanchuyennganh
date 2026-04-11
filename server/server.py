#!/usr/bin/env python3
"""
MARL Copilot Proxy — OpenAI-Compatible API Server (Local)
==========================================================
Copy logic từ bản production (OrchestraAPI), bỏ auth/DB/billing/rate-limit.
Chỉ chạy local, dùng GitHub token trực tiếp qua Authorization header.

Usage:
  curl http://localhost:5000/v1/chat/completions \\
    -H "Authorization: Bearer gho_xxxYOUR_TOKEN" \\
    -H "Content-Type: application/json" \\
    -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}'
"""

import json
import time
import uuid
import os
import asyncio
import logging
import threading
from typing import Optional, Dict, Tuple

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx

# ═══════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════
logger = logging.getLogger("marl-proxy")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s",
                                           datefmt="%Y-%m-%dT%H:%M:%S"))
    logger.addHandler(handler)
logger.propagate = False

# ═══════════════════════════════════════════════════════════════
# CONSTANTS — Copilot CLI identity (dựa trên traffic capture CLI v1.0.10)
# ═══════════════════════════════════════════════════════════════
GITHUB_API = "https://api.github.com"
COPILOT_API = "https://api.individual.githubcopilot.com"
GITHUB_API_VERSION = "2025-05-01"
CLI_VERSION = "1.0.10"
USER_AGENT = f"copilot/{CLI_VERSION} (linux v24.11.1) term/unknown"
USER_AGENT_CHAT = f"copilot/{CLI_VERSION} (client/github/cli linux v24.11.1) term/unknown"

# Retry constants
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2.0  # exponential: 2s → 4s → 8s
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

# Timeouts
UPSTREAM_TIMEOUT = httpx.Timeout(connect=15.0, read=300.0, write=15.0, pool=15.0)
STREAM_TIMEOUT = httpx.Timeout(connect=15.0, read=300.0, write=15.0, pool=15.0)

# Persistent IDs for billing bypass
SESSION_ID = str(uuid.uuid4())
MACHINE_ID = uuid.uuid4().hex

# Token pool — populated via --token flags at startup
# Round-robin index for load balancing across multiple tokens
TOKEN_POOL: list[str] = []
_token_index = 0
_token_lock = threading.Lock()


def _next_pool_token() -> str:
    """Lấy token tiếp theo từ pool (round-robin, thread-safe)."""
    global _token_index
    if not TOKEN_POOL:
        return ""
    with _token_lock:
        token = TOKEN_POOL[_token_index % len(TOKEN_POOL)]
        _token_index += 1
    return token


# GPT Codex models use Responses API (POST /responses) instead of Chat Completions
GPT_CODEX_RESPONSES_MODELS = {
    "gpt-5.1-codex-mini", "gpt-5.1-codex", "gpt-5.2-codex", "gpt-5.3-codex",
    "gpt-5.1-codex-max", "gpt-5.4",
}


def _is_responses_model(model: str) -> bool:
    """Check if model requires Responses API. Supports exact match + prefix matching
    (e.g. 'gpt-5.4-2026-03-05' matches 'gpt-5.4')."""
    if model in GPT_CODEX_RESPONSES_MODELS:
        return True
    return any(model.startswith(m + "-") for m in GPT_CODEX_RESPONSES_MODELS)


# ═══════════════════════════════════════════════════════════════
# TOKEN VALIDATION (CLI dùng gho_ trực tiếp, chỉ validate 1 lần)
# ═══════════════════════════════════════════════════════════════
_validated_tokens: Dict[str, float] = {}  # gho_token -> validated_at timestamp
_VALIDATE_TTL = 3600  # cache 1 giờ


async def validate_token(github_token: str) -> bool:
    """Validate gho_ token bằng GET /copilot_internal/user.
    Cache kết quả trong 1 giờ. Raise 401 nếu token không hợp lệ."""
    now = time.time()
    cached_at = _validated_tokens.get(github_token)
    if cached_at and now - cached_at < _VALIDATE_TTL:
        return True

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{GITHUB_API}/copilot_internal/user",
                headers={
                    "Authorization": f"Bearer {github_token}",
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                },
                timeout=15,
            )
        if resp.status_code == 200:
            _validated_tokens[github_token] = now
            logger.info(f"Token validated OK: {github_token[:12]}...")
            return True
        logger.error(f"Token validation failed: HTTP {resp.status_code} for {github_token[:12]}...")
        raise HTTPException(status_code=401, detail={
            "error": {"message": f"GitHub token validation failed (HTTP {resp.status_code}). Token may be expired or invalid."}
        })
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Token validation error: {type(exc).__name__}: {exc}")
        raise HTTPException(status_code=502, detail={
            "error": {"message": f"Cannot reach GitHub API to validate token: {exc}"}
        })


# ═══════════════════════════════════════════════════════════════
# INPUT VALIDATION
# ═══════════════════════════════════════════════════════════════

def _validate_chat_body(body: dict):
    """Validate Chat Completions request body per OpenAI API spec."""
    model = body.get("model")
    if not model or not isinstance(model, str) or not model.strip():
        raise HTTPException(status_code=400, detail={
            "error": {"message": "'model' is required and must be a non-empty string.", "type": "invalid_request_error"}
        })

    messages = body.get("messages")
    if messages is None or not isinstance(messages, list) or len(messages) == 0:
        raise HTTPException(status_code=400, detail={
            "error": {"message": "'messages' is required and must be a non-empty list.", "type": "invalid_request_error"}
        })

    max_tokens = body.get("max_tokens")
    if max_tokens is not None:
        if not isinstance(max_tokens, int) or max_tokens <= 0:
            raise HTTPException(status_code=400, detail={
                "error": {"message": "'max_tokens' must be a positive integer.", "type": "invalid_request_error"}
            })
        if max_tokens > 128000:
            body["max_tokens"] = 128000

    temperature = body.get("temperature")
    if temperature is not None:
        if not isinstance(temperature, (int, float)) or temperature < 0 or temperature > 2:
            raise HTTPException(status_code=400, detail={
                "error": {"message": "'temperature' must be between 0 and 2.", "type": "invalid_request_error"}
            })

    stream = body.get("stream")
    if stream is not None and not isinstance(stream, bool):
        raise HTTPException(status_code=400, detail={
            "error": {"message": "'stream' must be a boolean.", "type": "invalid_request_error"}
        })



# ═══════════════════════════════════════════════════════════════
# COPILOT HEADERS — CLI identity (dùng gho_ trực tiếp)
# ═══════════════════════════════════════════════════════════════

def copilot_headers(github_token: str) -> dict:
    """Build headers giả dạng Copilot CLI chính chủ.
    Dùng gho_ token trực tiếp, không qua JWT.
    Headers khớp chính xác với copilot_cli.py đã chạy ổn."""
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {github_token}",
        "User-Agent": USER_AGENT_CHAT,
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "Copilot-Integration-Id": "copilot-developer-cli",
        "OpenAI-Intent": "conversation-agent",
        "X-Initiator": "agent",
        "X-Interaction-Id": str(uuid.uuid4()),
        "X-Interaction-Type": "conversation-user",
        "X-Agent-Task-Id": str(uuid.uuid4()),
        "X-Client-Session-Id": SESSION_ID,
        "X-Client-Machine-Id": MACHINE_ID,
    }


# ═══════════════════════════════════════════════════════════════
# RETRY HELPER — shared by streaming & non-streaming paths
# ═══════════════════════════════════════════════════════════════

async def _request_with_retry(method: str, url: str, headers: dict,
                              json_body: dict, timeout: httpx.Timeout,
                              github_token: str, stream: bool = False):
    """Execute an HTTP request with exponential backoff retry.
    For non-streaming: returns httpx.Response.
    For streaming: returns (client, response, status_code).
    Retries on RETRYABLE_STATUS_CODES and connection/timeout errors.
    Refreshes Copilot token between retries."""
    last_exc = None
    for attempt in range(MAX_RETRIES):
        try:
            if stream:
                client = httpx.AsyncClient()
                resp_cm = client.stream(method, url, headers=headers, json=json_body, timeout=timeout)
                resp = await resp_cm.__aenter__()
                if resp.status_code in RETRYABLE_STATUS_CODES:
                    await resp.aclose()
                    await client.aclose()
                    if attempt < MAX_RETRIES - 1:
                        delay = RETRY_BASE_DELAY * (2 ** attempt)
                        logger.warning(f"Retry {attempt+1}/{MAX_RETRIES}: upstream {resp.status_code}, sleeping {delay}s")
                        await asyncio.sleep(delay)
                        # CLI dùng gho_ trực tiếp, không cần refresh token
                        continue
                    # Last attempt — return error response
                    return None, None, resp.status_code
                return client, resp, resp.status_code
            else:
                async with httpx.AsyncClient() as client:
                    resp = await client.request(method, url, headers=headers, json=json_body, timeout=timeout)
                if resp.status_code in RETRYABLE_STATUS_CODES:
                    if attempt < MAX_RETRIES - 1:
                        delay = RETRY_BASE_DELAY * (2 ** attempt)
                        logger.warning(f"Retry {attempt+1}/{MAX_RETRIES}: upstream {resp.status_code}, sleeping {delay}s")
                        await asyncio.sleep(delay)
                        continue
                return resp
        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.ReadError, httpx.ConnectError, httpx.PoolTimeout) as exc:
            last_exc = exc
            if attempt < MAX_RETRIES - 1:
                delay = RETRY_BASE_DELAY * (2 ** attempt)
                logger.warning(f"Retry {attempt+1}/{MAX_RETRIES}: {type(exc).__name__}, sleeping {delay}s")
                await asyncio.sleep(delay)
                continue

    # All retries exhausted
    if stream:
        return None, None, 504
    raise HTTPException(status_code=504, detail={
        "error": {
            "message": f"Upstream request failed after {MAX_RETRIES} retries: {type(last_exc).__name__}",
            "type": "server_error",
        }
    })


# ═══════════════════════════════════════════════════════════════
# RESPONSE CLEANING (strip Copilot-specific metadata)
# ═══════════════════════════════════════════════════════════════

def _clean_delta(delta: dict) -> dict:
    """Keep only standard OpenAI fields in delta."""
    clean = {}
    if "role" in delta:
        clean["role"] = delta["role"]
    if "content" in delta:
        clean["content"] = delta["content"]
    if "tool_calls" in delta:
        clean["tool_calls"] = delta["tool_calls"]
    if "function_call" in delta:
        clean["function_call"] = delta["function_call"]
    if "refusal" in delta:
        clean["refusal"] = delta["refusal"]
    if "reasoning_text" in delta:
        clean["reasoning_text"] = delta["reasoning_text"]
    return clean


def clean_sse_chunk(raw: dict) -> Optional[dict]:
    """Clean 1 SSE chunk: strip Copilot-specific metadata,
    keep standard OpenAI SDK format."""
    choices = raw.get("choices", [])
    if not choices:
        return None

    clean_choices = []
    for c in choices:
        delta = c.get("delta", {})
        finish = c.get("finish_reason")

        has_useful = (
            delta.get("content") is not None
            or delta.get("role") is not None
            or "tool_calls" in delta
            or "function_call" in delta
            or delta.get("reasoning_text") is not None
            or finish is not None
        )
        if not has_useful:
            continue

        out = {
            "index": c.get("index", 0),
            "delta": _clean_delta(delta),
            "logprobs": c.get("logprobs", None),
            "finish_reason": finish,
        }
        clean_choices.append(out)

    if not clean_choices:
        return None

    result = {
        "id": raw.get("id", ""),
        "object": "chat.completion.chunk",
        "created": raw.get("created", int(time.time())),
        "model": raw.get("model", ""),
        "system_fingerprint": raw.get("system_fingerprint", None),
        "choices": clean_choices,
    }
    if "usage" in raw:
        result["usage"] = raw["usage"]
    return result


def _clean_message(msg: dict) -> dict:
    """Keep only standard OpenAI fields in message."""
    clean = {
        "role": msg.get("role", "assistant"),
        "content": msg.get("content"),
    }
    if msg.get("tool_calls"):
        clean["tool_calls"] = msg["tool_calls"]
    if msg.get("function_call"):
        clean["function_call"] = msg["function_call"]
    if msg.get("refusal") is not None:
        clean["refusal"] = msg["refusal"]
    else:
        clean["refusal"] = None
    return clean


def clean_response(raw: dict) -> dict:
    """Clean non-streaming response: strip Copilot metadata, keep standard OpenAI SDK format."""
    clean_choices = []
    for c in raw.get("choices", []):
        msg = c.get("message", {})
        finish = c.get("finish_reason", "stop")

        clean_choices.append({
            "index": c.get("index", 0),
            "message": _clean_message(msg),
            "logprobs": c.get("logprobs", None),
            "finish_reason": finish,
        })
    return {
        "id": raw.get("id", f"chatcmpl-{uuid.uuid4().hex[:12]}"),
        "object": "chat.completion",
        "created": raw.get("created", int(time.time())),
        "model": raw.get("model", ""),
        "system_fingerprint": raw.get("system_fingerprint", None),
        "choices": clean_choices,
        "usage": raw.get("usage", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}),
    }


# ═══════════════════════════════════════════════════════════════
# RESPONSES API CONVERSION (GPT Codex models)
# ═══════════════════════════════════════════════════════════════

def convert_messages_to_responses_input(body: dict) -> dict:
    """Convert Chat Completions request body to Responses API format.
    messages → input, tools format conversion, parameter mapping."""
    messages = body.get("messages", [])
    input_items = []

    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content")

        if role == "system":
            input_items.append({
                "role": "system",
                "content": [{"type": "input_text", "text": content or ""}],
            })
        elif role == "user":
            input_items.append({
                "role": "user",
                "content": [{"type": "input_text", "text": content or ""}],
            })
        elif role == "assistant":
            tool_calls = msg.get("tool_calls")
            if tool_calls:
                if content:
                    input_items.append({
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": content}],
                    })
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    input_items.append({
                        "type": "function_call",
                        "name": fn.get("name", ""),
                        "arguments": fn.get("arguments", "{}"),
                        "call_id": tc.get("id", f"call_{uuid.uuid4().hex[:24]}"),
                    })
            else:
                input_items.append({
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": content or ""}],
                })
        elif role == "tool":
            input_items.append({
                "type": "function_call_output",
                "call_id": msg.get("tool_call_id", ""),
                "output": content or "",
            })

    resp_body: dict = {
        "model": body.get("model", ""),
        "input": input_items,
        "stream": body.get("stream", False),
        "store": False,
        "truncation": "disabled",
        "reasoning": {"summary": "detailed"},
        "include": ["reasoning.encrypted_content"],
        "max_output_tokens": body.get("max_tokens", 128000),
    }

    if body.get("tools"):
        resp_tools = []
        for t in body["tools"]:
            if t.get("type") == "function":
                fn = t.get("function", {})
                resp_tools.append({
                    "type": "function",
                    "name": fn.get("name", ""),
                    "description": fn.get("description", ""),
                    "parameters": fn.get("parameters", {}),
                    "strict": False,
                })
        if resp_tools:
            resp_body["tools"] = resp_tools

    if body.get("temperature") is not None:
        resp_body["temperature"] = body["temperature"]
    if body.get("top_p") is not None:
        resp_body["top_p"] = body["top_p"]

    return resp_body


def convert_responses_sse_to_chat(event_data: dict, model: str,
                                  response_id: str = "",
                                  _tc_index: dict = None) -> Optional[dict]:
    """Convert a single Responses API SSE event to a Chat Completions SSE chunk.
    Returns None for events that should be skipped."""
    event_type = event_data.get("type", "")
    created = int(time.time())

    if not response_id:
        response_id = event_data.get("response_id", f"chatcmpl-{uuid.uuid4().hex[:12]}")

    def _make_chunk(delta: dict, finish_reason: Optional[str] = None) -> dict:
        return {
            "id": response_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "system_fingerprint": None,
            "choices": [{
                "index": 0,
                "delta": delta,
                "logprobs": None,
                "finish_reason": finish_reason,
            }],
        }

    if event_type == "response.output_text.delta":
        return _make_chunk({"content": event_data.get("delta", "")})

    elif event_type == "response.output_item.added":
        item = event_data.get("item", {})
        if item.get("type") == "function_call":
            if _tc_index is not None:
                idx = _tc_index.get("next", 0)
                _tc_index["next"] = idx + 1
                _tc_index[item.get("call_id", "")] = idx
            else:
                idx = 0
            return _make_chunk({
                "role": "assistant",
                "tool_calls": [{
                    "index": idx,
                    "id": item.get("call_id", f"call_{uuid.uuid4().hex[:24]}"),
                    "type": "function",
                    "function": {"name": item.get("name", ""), "arguments": ""},
                }],
            })

    elif event_type == "response.function_call_arguments.delta":
        call_id = event_data.get("call_id", "")
        idx = 0
        if _tc_index is not None and call_id in _tc_index:
            idx = _tc_index[call_id]
        return _make_chunk({
            "tool_calls": [{
                "index": idx,
                "function": {"arguments": event_data.get("delta", "")},
            }],
        })

    elif event_type == "response.completed":
        resp = event_data.get("response", {})
        output = resp.get("output", [])
        has_function_call = any(item.get("type") == "function_call" for item in output)
        finish_reason = "tool_calls" if has_function_call else "stop"
        chunk = _make_chunk({}, finish_reason)
        usage = resp.get("usage", {})
        if usage:
            chunk["usage"] = {
                "prompt_tokens": usage.get("input_tokens", 0),
                "completion_tokens": usage.get("output_tokens", 0),
                "total_tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
            }
        return chunk

    return None


def convert_responses_full_to_chat(resp_data: dict, model: str) -> dict:
    """Convert Responses API non-streaming response to Chat Completions format."""
    output = resp_data.get("output", [])
    content_parts = []
    tool_calls = []
    tc_idx = 0

    for item in output:
        item_type = item.get("type", "")
        if item_type == "message":
            for c in item.get("content", []):
                if c.get("type") == "output_text":
                    content_parts.append(c.get("text", ""))
        elif item_type == "function_call":
            tool_calls.append({
                "id": item.get("call_id", f"call_{uuid.uuid4().hex[:24]}"),
                "type": "function",
                "function": {
                    "name": item.get("name", ""),
                    "arguments": item.get("arguments", "{}"),
                },
            })
            tc_idx += 1

    message: dict = {
        "role": "assistant",
        "content": "\n".join(content_parts) if content_parts else None,
        "refusal": None,
    }
    if tool_calls:
        message["tool_calls"] = tool_calls

    finish_reason = "tool_calls" if tool_calls else "stop"

    usage = resp_data.get("usage", {})
    return {
        "id": resp_data.get("id", f"chatcmpl-{uuid.uuid4().hex[:12]}"),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "system_fingerprint": None,
        "choices": [{
            "index": 0,
            "message": message,
            "logprobs": None,
            "finish_reason": finish_reason,
        }],
        "usage": {
            "prompt_tokens": usage.get("input_tokens", 0),
            "completion_tokens": usage.get("output_tokens", 0),
            "total_tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
        },
    }


# ═══════════════════════════════════════════════════════════════
# APP
# ═══════════════════════════════════════════════════════════════
app = FastAPI(title="MARL Copilot Proxy", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/")
def root():
    return {"status": "running", "service": "MARL Copilot Proxy"}


@app.get("/health")
def health():
    return {"status": "ok"}


# ═══════════════════════════════════════════════════════════════
# GET /v1/models
# ═══════════════════════════════════════════════════════════════

@app.get("/v1/models")
async def list_models(request: Request):
    github_token = _extract_github_token(request)
    await validate_token(github_token)

    headers = copilot_headers(github_token)
    headers["X-Interaction-Type"] = "model-access"
    headers["OpenAI-Intent"] = "model-access"

    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{COPILOT_API}/models", headers=headers, timeout=15)
    if resp.status_code != 200:
        return JSONResponse(status_code=resp.status_code, content={"error": {"message": resp.text[:500]}})

    raw = resp.json()
    models = []
    for m in raw.get("data", []):
        models.append({
            "id": m.get("id", ""),
            "object": "model",
            "created": m.get("created", int(time.time())),
            "owned_by": m.get("vendor", "github-copilot"),
        })
    return JSONResponse(content={"object": "list", "data": models})


# ═══════════════════════════════════════════════════════════════
# POST /v1/chat/completions
# ═══════════════════════════════════════════════════════════════

def _extract_github_token(request: Request) -> str:
    """Extract GitHub token — ưu tiên header gho_, fallback sang token pool."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
        # Chỉ chấp nhận nếu là gho_ token thật (>= 20 chars, không phải placeholder)
        if token.startswith("gho_") and len(token) >= 20:
            return token
        # Client gửi token giả (sk-xxx, gho_token, dummy, etc) → bỏ qua, dùng pool
        logger.debug(f"Ignoring invalid/placeholder token from header: {token[:10]}...")

    # Fallback: lấy từ pool (round-robin)
    pool_token = _next_pool_token()
    if pool_token:
        logger.debug(f"Using pool token: {pool_token[:12]}...")
        return pool_token

    raise HTTPException(status_code=401, detail={
        "error": {"message": "No token available. Either send Authorization: Bearer gho_xxx header, or start server with --token gho_xxx"}
    })


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    request_id = uuid.uuid4().hex[:8]

    # 1. Extract GitHub token from header
    github_token = _extract_github_token(request)

    # 2. Parse request body
    try:
        body = await request.json()
    except Exception:
        logger.warning(f"[{request_id}] Invalid JSON body")
        raise HTTPException(status_code=400, detail={"error": {"message": "Invalid JSON body"}})

    # 3. Validate input
    _validate_chat_body(body)

    model_id = body.get("model", "")
    is_stream = body.get("stream", False)
    msg_count = len(body.get("messages", []))
    logger.info(f"[{request_id}] >>> {model_id} | stream={is_stream} | messages={msg_count} | max_tokens={body.get('max_tokens', 'default')}")

    # Default max_tokens to 32000 if not specified
    if "max_tokens" not in body and "max_completion_tokens" not in body:
        body["max_tokens"] = 32000

    # 4. CLI dùng gho_ trực tiếp (không exchange token)
    await validate_token(github_token)

    # 5. Build headers
    headers = copilot_headers(github_token)

    # ── GPT Codex models → Responses API ──────────────────────
    if _is_responses_model(model_id):
        resp_body = convert_messages_to_responses_input(body)
        url = f"{COPILOT_API}/responses"
        logger.info(f"[{request_id}] Route: Responses API -> {url}")

        if is_stream:
            async def generate_responses():
                tc_index: dict = {"next": 0}
                response_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"

                # Connect with retry
                s_client, s_resp, status = await _request_with_retry(
                    "POST", url, headers, resp_body, STREAM_TIMEOUT,
                    github_token, stream=True
                )
                if s_client is None:
                    logger.error(f"[{request_id}] Responses stream FAILED: upstream returned {status} after {MAX_RETRIES} retries")
                    chunk = {
                        "id": response_id,
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": model_id,
                        "choices": [{"index": 0, "delta": {"content": f"[Error {status}] Upstream unavailable after {MAX_RETRIES} retries"}, "finish_reason": "stop"}],
                    }
                    yield f"data: {json.dumps(chunk)}\n\n"
                    yield "data: [DONE]\n\n"
                    return

                # Send initial role chunk
                yield f'data: {json.dumps({"id": response_id, "object": "chat.completion.chunk", "created": int(time.time()), "model": model_id, "choices": [{"index": 0, "delta": {"role": "assistant"}, "logprobs": None, "finish_reason": None}]})}\n\n'

                try:
                    buf = ""
                    async for raw_bytes in s_resp.aiter_bytes():
                        if not raw_bytes:
                            continue
                        buf += raw_bytes.decode("utf-8", errors="replace")
                        while "\n" in buf:
                            line, buf = buf.split("\n", 1)
                            line = line.strip()
                            if not line:
                                continue
                            if line.startswith("event:"):
                                continue
                            if not line.startswith("data: "):
                                continue
                            payload = line[6:]
                            if payload.strip() == "[DONE]":
                                yield "data: [DONE]\n\n"
                                return
                            try:
                                event_data = json.loads(payload)
                            except json.JSONDecodeError:
                                continue
                            converted = convert_responses_sse_to_chat(
                                event_data, model_id, response_id, tc_index
                            )
                            if converted:
                                yield f"data: {json.dumps(converted, ensure_ascii=False)}\n\n"

                    # Flush remaining buffer
                    for leftover in buf.split("\n"):
                        leftover = leftover.strip()
                        if leftover.startswith("data: "):
                            p = leftover[6:]
                            if p.strip() == "[DONE]":
                                yield "data: [DONE]\n\n"
                                return
                            try:
                                event_data = json.loads(p)
                                converted = convert_responses_sse_to_chat(
                                    event_data, model_id, response_id, tc_index
                                )
                                if converted:
                                    yield f"data: {json.dumps(converted, ensure_ascii=False)}\n\n"
                            except json.JSONDecodeError:
                                pass

                    # Stream ended without [DONE]
                    yield "data: [DONE]\n\n"
                except httpx.ReadTimeout:
                    logger.warning(f"[{request_id}] Responses stream TIMEOUT")
                    yield f'data: {{"error":"timeout"}}\n\n'
                    yield "data: [DONE]\n\n"
                except Exception as exc:
                    logger.warning(f"[{request_id}] Responses stream interrupted: {type(exc).__name__}: {exc}")
                    yield "data: [DONE]\n\n"
                finally:
                    await s_resp.aclose()
                    await s_client.aclose()

            return StreamingResponse(generate_responses(), media_type="text/event-stream",
                                     headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

        else:
            # Non-streaming Responses API with retry
            resp = await _request_with_retry("POST", url, headers, resp_body, UPSTREAM_TIMEOUT, github_token)

            if resp.status_code != 200:
                try:
                    err = resp.json()
                except Exception:
                    err = {"error": {"message": resp.text[:500]}}
                logger.error(f"[{request_id}] Responses API error {resp.status_code}: {json.dumps(err, ensure_ascii=False)[:300]}")
                return JSONResponse(status_code=resp.status_code, content=err)

            raw_data = resp.json()
            cleaned = convert_responses_full_to_chat(raw_data, model_id)
            usage = cleaned.get("usage", {})
            logger.info(f"[{request_id}] <<< OK | tokens: {usage.get('prompt_tokens', 0)}+{usage.get('completion_tokens', 0)}={usage.get('total_tokens', 0)}")
            return JSONResponse(content=cleaned)

    # ── Standard models → Chat Completions API ────────────────
    url = f"{COPILOT_API}/chat/completions"
    is_stream = body.get("stream", False)
    logger.info(f"[{request_id}] Route: Chat Completions -> {url} | stream={is_stream}")

    if is_stream:
        async def generate():
            # Connect with retry
            s_client, s_resp, status = await _request_with_retry(
                "POST", url, headers, body, STREAM_TIMEOUT,
                github_token, stream=True
            )
            if s_client is None:
                logger.error(f"[{request_id}] Chat stream FAILED: upstream returned {status} after {MAX_RETRIES} retries")
                chunk = {
                    "id": "error",
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": model_id,
                    "choices": [{"index": 0, "delta": {"content": f"[Error {status}] Upstream unavailable after {MAX_RETRIES} retries"}, "finish_reason": "stop"}],
                }
                yield f"data: {json.dumps(chunk)}\n\n"
                yield "data: [DONE]\n\n"
                return

            try:
                buf = ""
                async for raw_bytes in s_resp.aiter_bytes():
                    if not raw_bytes:
                        continue
                    buf += raw_bytes.decode("utf-8", errors="replace")
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        line = line.strip()
                        if not line or not line.startswith("data: "):
                            continue
                        payload = line[6:]
                        if payload.strip() == "[DONE]":
                            yield "data: [DONE]\n\n"
                            return
                        try:
                            raw = json.loads(payload)
                        except json.JSONDecodeError:
                            continue

                        cleaned = clean_sse_chunk(raw)
                        if cleaned:
                            yield f"data: {json.dumps(cleaned, ensure_ascii=False)}\n\n"

                # Flush remaining buffer
                for leftover in buf.split("\n"):
                    leftover = leftover.strip()
                    if leftover.startswith("data: "):
                        p = leftover[6:]
                        if p.strip() == "[DONE]":
                            yield "data: [DONE]\n\n"
                            return
                        try:
                            raw = json.loads(p)
                            cleaned = clean_sse_chunk(raw)
                            if cleaned:
                                yield f"data: {json.dumps(cleaned, ensure_ascii=False)}\n\n"
                        except json.JSONDecodeError:
                            pass

                # Stream ended without [DONE]
                yield "data: [DONE]\n\n"
            except httpx.ReadTimeout:
                logger.warning(f"[{request_id}] Chat stream TIMEOUT")
                yield f'data: {{"error":"timeout"}}\n\n'
                yield "data: [DONE]\n\n"
            except Exception as exc:
                logger.warning(f"[{request_id}] Chat stream interrupted: {type(exc).__name__}: {exc}")
                yield "data: [DONE]\n\n"
            finally:
                await s_resp.aclose()
                await s_client.aclose()

        return StreamingResponse(generate(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    else:
        # Non-streaming with retry
        resp = await _request_with_retry("POST", url, headers, body, UPSTREAM_TIMEOUT, github_token)

        if resp.status_code != 200:
            try:
                err = resp.json()
            except Exception:
                err = {"error": {"message": resp.text[:500]}}
            logger.error(f"[{request_id}] Chat non-stream ERROR {resp.status_code}: {json.dumps(err, ensure_ascii=False)[:300]}")
            return JSONResponse(status_code=resp.status_code, content=err)

        raw_data = resp.json()
        cleaned = clean_response(raw_data)
        logger.info(f"[{request_id}] Chat non-stream OK | usage={cleaned.get('usage', {})}")
        return JSONResponse(content=cleaned)


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(
        description="MARL Copilot Proxy — OpenAI-Compatible API Server (CLI Identity)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1 token:
  python3 server.py --token gho_abc123

  # Nhieu token (round-robin load balance):
  python3 server.py --token gho_abc123 --token gho_def456 --token gho_ghi789

  # Doi port:
  python3 server.py --token gho_abc123 --port 8080

  # Khong truyen token (client phai gui qua Authorization header):
  python3 server.py
        """,
    )
    parser.add_argument(
        "--token", "-t",
        action="append",
        dest="tokens",
        metavar="gho_xxx",
        help="GitHub token (gho_xxx). Co the dung nhieu lan de them nhieu token.",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=int(os.environ.get("PORT", 5000)),
        help="Port (default: 5000)",
    )
    args = parser.parse_args()

    PORT = args.port

    # Load tokens vao pool
    if args.tokens:
        for t in args.tokens:
            t = t.strip()
            if t and t not in TOKEN_POOL:
                TOKEN_POOL.append(t)

    # Banner
    token_info = f"{len(TOKEN_POOL)} token(s) loaded (round-robin)" if TOKEN_POOL else "No tokens - client must send Authorization header"
    masked = [f"{t[:8]}...{t[-4:]}" for t in TOKEN_POOL] if TOKEN_POOL else []

    print(f"""
+======================================================+
|  MARL Copilot Proxy Server (CLI Identity)            |
|  http://127.0.0.1:{PORT}/v1                              |
+------------------------------------------------------+
|  GET  /v1/models            - List models            |
|  POST /v1/chat/completions  - Chat (stream & sync)   |
|  GET  /health               - Health check           |
+------------------------------------------------------+
|  Identity: copilot-developer-cli v{CLI_VERSION}            |
|  Tokens:   {token_info:<42s}|
+======================================================+""")
    if masked:
        for m in masked:
            print(f"  + {m}")
        print()

    uvicorn.run(app, host="0.0.0.0", port=PORT)
