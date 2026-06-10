from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from playwright.async_api import async_playwright, Browser, BrowserContext, Page

from ..recon.auth import AuthSessionStore

log = logging.getLogger("marl3.exec.browser")


@dataclass
class _BrowserActor:
    context: BrowserContext
    page: Page
    requests: list[dict] = field(default_factory=list)


class BrowserTool:
    def __init__(self, target_url: str, auth_store: AuthSessionStore, workspace_root: Path, headless: bool = True) -> None:
        self._target_url = target_url
        self._auth_store = auth_store
        self._workspace_root = Path(workspace_root).resolve()
        self._headless = headless
        self._browser: Optional[Browser] = None
        self._pw = None
        self._actors: dict[str, _BrowserActor] = {}
        parsed = urlparse(target_url)
        self._origin = f"{parsed.scheme}://{parsed.netloc}"

    async def _ensure_browser(self) -> Browser:
        if self._browser is not None:
            return self._browser
        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(
            headless=self._headless,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        return self._browser

    async def _ensure_actor(self, actor: str) -> _BrowserActor:
        if actor in self._actors:
            return self._actors[actor]

        browser = await self._ensure_browser()
        storage_state = self._auth_store.storage_state_for(actor)
        if storage_state:
            context = await browser.new_context(storage_state=storage_state)
        else:
            context = await browser.new_context()
            headers = self._auth_store.headers_for(actor)
            cookie_header = headers.get("Cookie", "")
            if cookie_header:
                cookies = []
                for part in cookie_header.split(";"):
                    if "=" not in part:
                        continue
                    name, _, value = part.strip().partition("=")
                    cookies.append({"url": self._origin, "name": name, "value": value})
                if cookies:
                    await context.add_cookies(cookies)

        page = await context.new_page()
        actor_state = _BrowserActor(context=context, page=page)

        page.on("request", lambda request: actor_state.requests.append({
            "type": "request",
            "method": request.method,
            "url": request.url,
            "resource_type": request.resource_type,
        }))
        page.on("response", lambda response: actor_state.requests.append({
            "type": "response",
            "status": response.status,
            "url": response.url,
        }))

        self._actors[actor] = actor_state
        return actor_state

    async def navigate(self, actor: str, url: str, wait_until: str = "domcontentloaded") -> str:
        try:
            actor_state = await self._ensure_actor(actor)
            resp = await actor_state.page.goto(url, wait_until=wait_until)
            title = await actor_state.page.title()
            body = await actor_state.page.content()
            return json.dumps({
                "actor": actor,
                "url": actor_state.page.url,
                "status": resp.status if resp else None,
                "title": title,
                "content_preview": body[:4000],
            })
        except Exception as exc:
            return json.dumps({"actor": actor, "url": url, "error": str(exc)})

    async def click(self, actor: str, selector: str) -> str:
        try:
            actor_state = await self._ensure_actor(actor)
            await actor_state.page.click(selector)
            await actor_state.page.wait_for_load_state("domcontentloaded")
            title = await actor_state.page.title()
            return json.dumps({"actor": actor, "url": actor_state.page.url, "title": title})
        except Exception as exc:
            return json.dumps({"actor": actor, "selector": selector, "error": str(exc)})

    async def fill(self, actor: str, selector: str, value: str) -> str:
        try:
            actor_state = await self._ensure_actor(actor)
            await actor_state.page.fill(selector, value)
            return json.dumps({"actor": actor, "selector": selector, "filled": True})
        except Exception as exc:
            return json.dumps({"actor": actor, "selector": selector, "error": str(exc)})

    async def screenshot(self, actor: str, path: str | None = None) -> str:
        try:
            actor_state = await self._ensure_actor(actor)
            shot_path = Path(path) if path else self._workspace_root / f"{actor}_browser.png"
            if not shot_path.is_absolute():
                shot_path = self._workspace_root / shot_path
            shot_path.parent.mkdir(parents=True, exist_ok=True)
            await actor_state.page.screenshot(path=str(shot_path), full_page=True)
            return json.dumps({"actor": actor, "path": str(shot_path)})
        except Exception as exc:
            return json.dumps({"actor": actor, "path": path, "error": str(exc)})

    async def network_requests(self, actor: str, limit: int = 25) -> str:
        try:
            actor_state = await self._ensure_actor(actor)
            items = actor_state.requests[-limit:]
            return json.dumps({"actor": actor, "requests": items})
        except Exception as exc:
            return json.dumps({"actor": actor, "error": str(exc)})

    async def close(self) -> None:
        for actor_state in self._actors.values():
            try:
                await actor_state.context.close()
            except Exception:
                pass
        self._actors.clear()
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._pw is not None:
            await self._pw.stop()
            self._pw = None
