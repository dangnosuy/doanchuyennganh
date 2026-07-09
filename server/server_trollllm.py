#!/usr/bin/env python3
"""
MARL TrollLLM Proxy — OpenAI-Compatible API Server (Local)
===========================================================
Proxy server chuyen tiep request tu local den TrollLLM API (chat.trollllm.xyz).
Tuong thich voi OpenAI SDK, ho tro ca streaming va non-streaming.

Usage:
  python server/server_trollllm.py
  # Mac dinh chay tren http://127.0.0.1:5001

  curl http://localhost:5001/v1/chat/completions \\
    -H "Content-Type: application/json" \\
    -d '{"model":"claude-opus-4.6","messages":[{"role":"user","content":"Hi"}]}'

Environment variables:
  TROLLLLM_API_KEY  - API key cho TrollLLM (bat buoc)
  TROLLLLM_BASE_URL - Base URL (default: https://chat.trollllm.xyz/v1)
  PORT              - Port chay server (default: 5001)
"""

import json
import time
import uuid
import os
import asyncio
import logging
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx

# ═══════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════
logger = logging.getLogger("marl-trollllm-proxy")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    ))
    logger.addHandler(handler)
logger.propagate = False

# ═══════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════
TROLLLLM_BASE_URL = os.getenv("TROLLLLM_BASE_URL", "https://chat.trollllm.xyz/v1")
TROLLLLM_API_KEY = os.getenv("TROLLLLM_API_KEY", "")  # Bat buoc set qua env

# Retry constants
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2.0  # exponential: 2s → 4s → 8s
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

# Timeouts
UPSTREAM_TIMEOUT = httpx.Timeout(connect=15.0, read=300.0, write=15.0, pool=15.0)
STREAM_TIMEOUT = httpx.Timeout(connect=15.0, read=300.0, write=15.0, pool=15.0)

# Available models on TrollLLM (can be extended)
TROLLLLM_MODELS = [
    "gpt-5-mini",
    "gpt-5",
    "claude-opus-4.6",
    "claude-sonnet-4",
    "claude-3.5-sonnet",
    "claude-3-opus",
    "gpt-4o",
    "gpt-4-turbo",
    "gpt-3.5-turbo",
]


# ═══════════════════════════════════════════════════════════════
# INPUT VALIDATION
# ═══════════════════════════════════════════════════════════════

def _validate_chat_body(body: dict):
    """Validate Chat Completions request body per OpenAI API spec."""
    model = body.get("model")
    if not model or not isinstance(model, str) or not model.strip():
        raise HTTPException(status_code=400, detail={
            "error": {
                "message": "'model' is required and must be a non-empty string.",
                "type": "invalid_request_error"
            }
        })

    messages = body.get("messages")
    if messages is None or not isinstance(messages, list) or len(messages) == 0:
        raise HTTPException(status_code=400, detail={
            "error": {
                "message": "'messages' is required and must be a non-empty list.",
                "type": "invalid_request_error"
            }
        })

    max_tokens = body.get("max_tokens")
    if max_tokens is not None:
        if not isinstance(max_tokens, int) or max_tokens <= 0:
            raise HTTPException(status_code=400, detail={
                "error": {
                    "message": "'max_tokens' must be a positive integer.",
                    "type": "invalid_request_error"
                }
            })
        if max_tokens > 128000:
            body["max_tokens"] = 128000

    temperature = body.get("temperature")
    if temperature is not None:
        if not isinstance(temperature, (int, float)) or temperature < 0 or temperature > 2:
            raise HTTPException(status_code=400, detail={
                "error": {
                    "message": "'temperature' must be between 0 and 2.",
                    "type": "invalid_request_error"
                }
            })

    stream = body.get("stream")
    if stream is not None and not isinstance(stream, bool):
        raise HTTPException(status_code=400, detail={
            "error": {
                "message": "'stream' must be a boolean.",
                "type": "invalid_request_error"
            }
        })


# ═══════════════════════════════════════════════════════════════
# TROLLLLM HEADERS
# ═══════════════════════════════════════════════════════════════

def trollllm_headers(api_key: str) -> dict:
    """Build headers cho request toi TrollLLM upstream."""
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "MARL-TrollLLM-Proxy/1.0",
    }


# ═══════════════════════════════════════════════════════════════
# RETRY HELPER
# ═══════════════════════════════════════════════════════════════

async def _request_with_retry(
    method: str,
    url: str,
    headers: dict,
    json_body: dict,
    timeout: httpx.Timeout,
    stream: bool = False
):
    """Execute an HTTP request with exponential backoff retry.
    For non-streaming: returns httpx.Response.
    For streaming: returns (client, response, status_code).
    Retries on RETRYABLE_STATUS_CODES and connection/timeout errors."""
    last_exc = None
    for attempt in range(MAX_RETRIES):
        try:
            if stream:
                client = httpx.AsyncClient()
                resp_cm = client.stream(
                    method, url, headers=headers, json=json_body, timeout=timeout
                )
                resp = await resp_cm.__aenter__()
                if resp.status_code in RETRYABLE_STATUS_CODES:
                    await resp.aclose()
                    await client.aclose()
                    if attempt < MAX_RETRIES - 1:
                        delay = RETRY_BASE_DELAY * (2 ** attempt)
                        logger.warning(
                            f"Retry {attempt+1}/{MAX_RETRIES}: "
                            f"upstream {resp.status_code}, sleeping {delay}s"
                        )
                        await asyncio.sleep(delay)
                        continue
                    # Last attempt — return error response
                    return None, None, resp.status_code
                return client, resp, resp.status_code
            else:
                async with httpx.AsyncClient() as client:
                    resp = await client.request(
                        method, url, headers=headers, json=json_body, timeout=timeout
                    )
                if resp.status_code in RETRYABLE_STATUS_CODES:
                    if attempt < MAX_RETRIES - 1:
                        delay = RETRY_BASE_DELAY * (2 ** attempt)
                        logger.warning(
                            f"Retry {attempt+1}/{MAX_RETRIES}: "
                            f"upstream {resp.status_code}, sleeping {delay}s"
                        )
                        await asyncio.sleep(delay)
                        continue
                return resp
        except (
            httpx.ConnectTimeout, httpx.ReadTimeout,
            httpx.ReadError, httpx.ConnectError, httpx.PoolTimeout
        ) as exc:
            last_exc = exc
            if attempt < MAX_RETRIES - 1:
                delay = RETRY_BASE_DELAY * (2 ** attempt)
                logger.warning(
                    f"Retry {attempt+1}/{MAX_RETRIES}: "
                    f"{type(exc).__name__}, sleeping {delay}s"
                )
                await asyncio.sleep(delay)
                continue

    # All retries exhausted
    if stream:
        return None, None, 504
    raise HTTPException(status_code=504, detail={
        "error": {
            "message": f"Upstream request failed after {MAX_RETRIES} retries: "
                       f"{type(last_exc).__name__}",
            "type": "server_error",
        }
    })


# ═══════════════════════════════════════════════════════════════
# RESPONSE CLEANING (standard OpenAI format)
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
    return clean


def clean_sse_chunk(raw: dict) -> Optional[dict]:
    """Clean 1 SSE chunk: keep standard OpenAI SDK format."""
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
    """Clean non-streaming response: keep standard OpenAI SDK format."""
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
        "usage": raw.get("usage", {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0
        }),
    }


# ═══════════════════════════════════════════════════════════════
# APP
# ═══════════════════════════════════════════════════════════════
app = FastAPI(title="MARL TrollLLM Proxy", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.get("/")
def root():
    return {"status": "running", "service": "MARL TrollLLM Proxy"}


@app.get("/health")
def health():
    return {"status": "ok"}


# ═══════════════════════════════════════════════════════════════
# GET /v1/models
# ═══════════════════════════════════════════════════════════════

@app.get("/v1/models")
async def list_models():
    """Return list of available models on TrollLLM."""
    models = []
    for model_id in TROLLLLM_MODELS:
        models.append({
            "id": model_id,
            "object": "model",
            "created": int(time.time()),
            "owned_by": "trollllm",
        })
    return JSONResponse(content={"object": "list", "data": models})


# ═══════════════════════════════════════════════════════════════
# POST /v1/chat/completions
# ═══════════════════════════════════════════════════════════════

def _get_api_key(request: Request) -> str:
    """Get API key from Authorization header or env var."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    # Fallback to env var
    if TROLLLLM_API_KEY:
        return TROLLLLM_API_KEY
    raise HTTPException(status_code=401, detail={
        "error": {
            "message": "Missing API key. Set TROLLLLM_API_KEY env var or use "
                       "Authorization: Bearer <your-key>"
        }
    })


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    request_id = uuid.uuid4().hex[:8]

    # 1. Get API key
    api_key = _get_api_key(request)

    # 2. Parse request body
    try:
        body = await request.json()
    except Exception:
        logger.warning(f"[{request_id}] Invalid JSON body")
        raise HTTPException(status_code=400, detail={
            "error": {"message": "Invalid JSON body"}
        })

    # 3. Validate input
    _validate_chat_body(body)

    model_id = body.get("model", "")
    is_stream = body.get("stream", False)
    msg_count = len(body.get("messages", []))
    logger.info(
        f"[{request_id}] >>> {model_id} | stream={is_stream} | "
        f"messages={msg_count} | max_tokens={body.get('max_tokens', 'default')}"
    )

    # Default max_tokens to 4096 if not specified
    if "max_tokens" not in body:
        body["max_tokens"] = 4096

    # 4. Build headers
    headers = trollllm_headers(api_key)

    # 5. Forward to TrollLLM
    url = f"{TROLLLLM_BASE_URL}/chat/completions"
    logger.info(f"[{request_id}] Route: TrollLLM -> {url} | stream={is_stream}")

    if is_stream:
        async def generate():
            # Connect with retry
            s_client, s_resp, status = await _request_with_retry(
                "POST", url, headers, body, STREAM_TIMEOUT, stream=True
            )
            if s_client is None:
                logger.error(
                    f"[{request_id}] Stream FAILED: upstream returned {status} "
                    f"after {MAX_RETRIES} retries"
                )
                chunk = {
                    "id": "error",
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": model_id,
                    "choices": [{
                        "index": 0,
                        "delta": {
                            "content": f"[Error {status}] Upstream unavailable "
                                       f"after {MAX_RETRIES} retries"
                        },
                        "finish_reason": "stop"
                    }],
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
                logger.warning(f"[{request_id}] Stream TIMEOUT")
                yield 'data: {"error":"timeout"}\n\n'
                yield "data: [DONE]\n\n"
            except Exception as exc:
                logger.warning(
                    f"[{request_id}] Stream interrupted: "
                    f"{type(exc).__name__}: {exc}"
                )
                yield "data: [DONE]\n\n"
            finally:
                await s_resp.aclose()
                await s_client.aclose()

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
        )

    else:
        # Non-streaming with retry
        resp = await _request_with_retry("POST", url, headers, body, UPSTREAM_TIMEOUT)

        if resp.status_code != 200:
            try:
                err = resp.json()
            except Exception:
                err = {"error": {"message": resp.text[:500]}}
            logger.error(
                f"[{request_id}] ERROR {resp.status_code}: "
                f"{json.dumps(err, ensure_ascii=False)[:300]}"
            )
            return JSONResponse(status_code=resp.status_code, content=err)

        raw_data = resp.json()
        cleaned = clean_response(raw_data)
        logger.info(
            f"[{request_id}] <<< OK | usage={cleaned.get('usage', {})}"
        )
        return JSONResponse(content=cleaned)


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    PORT = int(os.environ.get("PORT", 5001))

    if not TROLLLLM_API_KEY:
        print("""
╔══════════════════════════════════════════════════════════════╗
║  WARNING: TROLLLLM_API_KEY not set!                          ║
║  Set it via environment variable:                            ║
║    export TROLLLLM_API_KEY="sk-trollllm-xxx"                 ║
║  Or pass via Authorization header when calling API.          ║
╚══════════════════════════════════════════════════════════════╝
""")

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  MARL TrollLLM Proxy Server                                  ║
║  http://127.0.0.1:{PORT}/v1                                      ║
╠══════════════════════════════════════════════════════════════╣
║  GET  /v1/models            - List models                    ║
║  POST /v1/chat/completions  - Chat (stream & sync)           ║
║  GET  /health               - Health check                   ║
╠══════════════════════════════════════════════════════════════╣
║  Upstream: {TROLLLLM_BASE_URL:<40} ║
║  Retry: {MAX_RETRIES}x with exponential backoff                          ║
╚══════════════════════════════════════════════════════════════╝
""")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
