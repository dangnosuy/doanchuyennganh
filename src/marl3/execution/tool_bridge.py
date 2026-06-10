"""Tool bridge — exposes the execution tool surface as LLM-callable tools.

All network calls go through RecordingHttpClient so evidence is complete.
Browser, shell, and filesystem tools are kept inside the run workspace.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

from .recorder import RecordingHttpClient
from .browser import BrowserTool
from .filesystem import WorkspaceFilesystem
from .shell import ShellRunner
from ..recon.body_store import BodyStore
from ..recon.auth import AuthSessionStore

log = logging.getLogger("marl3.tool_bridge")

_TOOL_SPECS = [
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Make an HTTP request to the target. All requests are recorded automatically.",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]},
                    "url": {"type": "string", "description": "Full URL"},
                    "actor": {"type": "string", "description": "Auth session label (e.g. 'user_a', 'admin', 'anon')"},
                    "headers": {"type": "object", "description": "Additional headers"},
                    "body": {"description": "Request body (object for JSON, string for raw)"},
                    "label": {"type": "string", "description": "Human-readable label for this step"},
                },
                "required": ["method", "url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_body_get",
            "description": "Retrieve the full body of a previously recorded exchange by its exchange_id. Use this to read large responses without truncation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "exchange_id": {"type": "string"},
                    "json_path": {"type": "string", "description": "Optional dot-notation path to extract a specific field, e.g. 'data.items.0.price'"},
                },
                "required": ["exchange_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_navigate",
            "description": "Open or navigate a browser session for a given actor label.",
            "parameters": {
                "type": "object",
                "properties": {
                    "actor": {"type": "string", "description": "Auth session label (e.g. 'user_a', 'admin', 'anon')"},
                    "url": {"type": "string", "description": "Full URL"},
                    "wait_until": {"type": "string", "enum": ["domcontentloaded", "load", "networkidle"]},
                },
                "required": ["actor", "url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_click",
            "description": "Click a browser selector in the actor's session.",
            "parameters": {
                "type": "object",
                "properties": {
                    "actor": {"type": "string"},
                    "selector": {"type": "string"},
                },
                "required": ["actor", "selector"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_fill",
            "description": "Fill a browser field in the actor's session.",
            "parameters": {
                "type": "object",
                "properties": {
                    "actor": {"type": "string"},
                    "selector": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["actor", "selector", "value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_screenshot",
            "description": "Save a screenshot of the browser session.",
            "parameters": {
                "type": "object",
                "properties": {
                    "actor": {"type": "string"},
                    "path": {"type": "string"},
                },
                "required": ["actor"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "browser_network_requests",
            "description": "Return captured browser request/response activity for the actor.",
            "parameters": {
                "type": "object",
                "properties": {
                    "actor": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": ["actor"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "shell_execute",
            "description": "Run a command inside the workspace root and capture output.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "cwd": {"type": "string"},
                    "timeout_s": {"type": "integer"},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_text_file",
            "description": "Read a text file from the workspace root.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "max_chars": {"type": "integer"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write a file inside the workspace root.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "edit_file",
            "description": "Replace text in an existing workspace file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "old_text": {"type": "string"},
                    "new_text": {"type": "string"},
                    "replace_all": {"type": "boolean"},
                },
                "required": ["path", "old_text", "new_text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": "List files in a workspace directory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_files",
            "description": "Search for files matching a glob pattern within the workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "path": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": ["pattern"],
            },
        },
    },
]


DEFAULT_ALLOWED_TOOLS = {
    "http_request",
    "http_body_get",
    "browser_navigate",
    "browser_click",
    "browser_fill",
    "browser_screenshot",
    "browser_network_requests",
    "shell_execute",
    "read_text_file",
    "write_file",
    "edit_file",
    "list_directory",
    "search_files",
}

PREPARE_ALLOWED_TOOLS = {
    "http_request",
    "http_body_get",
    "browser_navigate",
    "browser_click",
    "browser_fill",
    "browser_screenshot",
    "browser_network_requests",
    "shell_execute",
    "read_text_file",
    "list_directory",
    "search_files",
}

VERIFY_ALLOWED_TOOLS = {
    "http_request",
    "http_body_get",
    "browser_navigate",
    "browser_screenshot",
    "browser_network_requests",
    "read_text_file",
    "list_directory",
}


class ToolBridge:
    def __init__(
        self,
        recorder: RecordingHttpClient,
        body_store: BodyStore,
        workspace_root,
        auth_store: AuthSessionStore,
        target_url: str,
        default_mode: str = "attack",
    ) -> None:
        self._recorder = recorder
        self._body_store = body_store
        self._workspace_root = workspace_root
        self._auth_store = auth_store
        self._target_url = target_url
        self._mode = default_mode
        self._filesystem = WorkspaceFilesystem(workspace_root)
        self._shell = ShellRunner(workspace_root)
        self._browser = BrowserTool(target_url=target_url, auth_store=auth_store, workspace_root=workspace_root)

    def set_mode(self, mode: str) -> None:
        self._mode = mode

    async def dispatch(self, tool_name: str, args: dict) -> str:
        """Dispatch a tool call and return the result as a string.

        The Exec agent decides which tool to call — no phase-based gating. Only known
        parameters are forwarded to each tool (model may include extra keys). Any tool
        error (bad/missing args, runtime failure) is caught and returned as an
        {"error": ...} string so a single bad call never kills the whole exec loop.
        """
        try:
            return await self._dispatch(tool_name, args)
        except TypeError as exc:
            # Usually a missing/extra required argument from a malformed tool call.
            return json.dumps({
                "error": f"bad arguments for {tool_name}: {exc}",
                "tool": tool_name,
                "hint": "Check the required parameters for this tool and retry.",
            })
        except Exception as exc:
            return json.dumps({"error": f"{tool_name} failed: {exc}", "tool": tool_name})

    async def _dispatch(self, tool_name: str, args: dict) -> str:
        if tool_name == "http_request":
            known = {k: v for k, v in args.items()
                     if k in ("method", "url", "actor", "headers", "body", "label")}
            return await self._http_request(**known)
        elif tool_name == "http_body_get":
            known = {k: v for k, v in args.items()
                     if k in ("exchange_id", "json_path")}
            return self._http_body_get(**known)
        elif tool_name == "browser_navigate":
            known = {k: v for k, v in args.items() if k in ("actor", "url", "wait_until")}
            return await self._browser_navigate(**known)
        elif tool_name == "browser_click":
            known = {k: v for k, v in args.items() if k in ("actor", "selector")}
            return await self._browser_click(**known)
        elif tool_name == "browser_fill":
            known = {k: v for k, v in args.items() if k in ("actor", "selector", "value")}
            return await self._browser_fill(**known)
        elif tool_name == "browser_screenshot":
            known = {k: v for k, v in args.items() if k in ("actor", "path")}
            return await self._browser_screenshot(**known)
        elif tool_name == "browser_network_requests":
            known = {k: v for k, v in args.items() if k in ("actor", "limit")}
            return await self._browser_network_requests(**known)
        elif tool_name == "shell_execute":
            known = {k: v for k, v in args.items() if k in ("command", "cwd", "timeout_s")}
            return self._shell_execute(**known)
        elif tool_name == "read_text_file":
            known = {k: v for k, v in args.items() if k in ("path", "max_chars")}
            return self._filesystem.read_text_file(**known)
        elif tool_name == "write_file":
            known = {k: v for k, v in args.items() if k in ("path", "content")}
            return self._filesystem.write_file(**known)
        elif tool_name == "edit_file":
            known = {k: v for k, v in args.items() if k in ("path", "old_text", "new_text", "replace_all")}
            return self._filesystem.edit_file(**known)
        elif tool_name == "list_directory":
            known = {k: v for k, v in args.items() if k in ("path",)}
            return self._filesystem.list_directory(**known)
        elif tool_name == "search_files":
            known = {k: v for k, v in args.items() if k in ("pattern", "path", "limit")}
            return self._filesystem.search_files(**known)
        else:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})

    async def _http_request(
        self,
        method: str,
        url: str,
        actor: str = "anon",
        headers: Optional[dict] = None,
        body: Any = None,
        label: str = "",
    ) -> str:
        resp = await self._recorder.request(
            method=method,
            url=url,
            actor=actor,
            headers=headers,
            body=body,
            label=label,
        )
        # Return a summary, not the full body (agent uses http_body_get for full body)
        exchange = self._recorder._evidence.exchanges[-1] if self._recorder._evidence.exchanges else None
        result = {
            "status": resp.status_code,
            "url": url,
            "method": method,
            "actor": actor,
        }
        if exchange:
            result["exchange_id"] = exchange.exchange_id
            result["json_keys"] = exchange.json_keys[:20]
            result["id_fields"] = exchange.id_fields
            result["numeric_fields"] = exchange.numeric_fields
            # Small preview (not truncated mid-string — this is just metadata)
            if exchange.response_body_ref:
                result["body_preview"] = exchange.response_body_ref.head_preview[:300]

        return json.dumps(result)

    async def _browser_navigate(self, actor: str, url: str, wait_until: str = "domcontentloaded") -> str:
        return await self._browser.navigate(actor=actor, url=url, wait_until=wait_until)

    async def _browser_click(self, actor: str, selector: str) -> str:
        return await self._browser.click(actor=actor, selector=selector)

    async def _browser_fill(self, actor: str, selector: str, value: str) -> str:
        return await self._browser.fill(actor=actor, selector=selector, value=value)

    async def _browser_screenshot(self, actor: str, path: Optional[str] = None) -> str:
        return await self._browser.screenshot(actor=actor, path=path)

    async def _browser_network_requests(self, actor: str, limit: int = 25) -> str:
        return await self._browser.network_requests(actor=actor, limit=limit)

    def _shell_execute(self, command: str, cwd: Optional[str] = None, timeout_s: Optional[int] = None) -> str:
        return self._shell.execute_command(command=command, cwd=cwd, timeout_s=timeout_s)

    def _http_body_get(self, exchange_id: str, json_path: Optional[str] = None) -> str:
        # Find exchange in evidence
        evidence = self._recorder._evidence
        exchange = next((e for e in evidence.exchanges if e.exchange_id == exchange_id), None)
        if not exchange:
            return json.dumps({"error": f"Exchange not found: {exchange_id}"})
        if not exchange.response_body_ref:
            return json.dumps({"body": None})

        # Cap what is injected into the agent's context. The full body is always on disk
        # (lossless); the agent only needs a bounded view — use json_path to drill in.
        MAX = 4000
        try:
            body_bytes = self._body_store.get(exchange.response_body_ref.blob_id)
            try:
                obj = json.loads(body_bytes)
                if json_path:
                    obj = _json_path_get(obj, json_path)
                text = json.dumps(obj)
                if len(text) > MAX:
                    return json.dumps({
                        "body_truncated": text[:MAX],
                        "note": f"Body is {len(text)} chars; showing first {MAX}. Use json_path to extract a specific field.",
                        "exchange_id": exchange_id,
                    })
                return json.dumps({"body": obj, "exchange_id": exchange_id})
            except json.JSONDecodeError:
                text = body_bytes.decode("utf-8", errors="replace")
                truncated = len(text) > MAX
                return json.dumps({
                    "body": text[:MAX],
                    "truncated": truncated,
                    "full_length": len(text),
                    "exchange_id": exchange_id,
                })
        except FileNotFoundError:
            return json.dumps({"error": "Body blob not found on disk"})

    async def close(self) -> None:
        await self._browser.close()


TOOL_DEFINITIONS = _TOOL_SPECS


def _json_path_get(obj: Any, path: str) -> Any:
    """Navigate a dot-separated path into a nested object."""
    for part in path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        elif isinstance(obj, list):
            try:
                obj = obj[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return obj
