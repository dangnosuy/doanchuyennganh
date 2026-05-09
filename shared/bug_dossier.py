"""
bug_dossier.py — deterministic enrichment for risk-bug.json entries.

Normalizes legacy and current bug schemas into a richer per-bug dossier so
Manage/Red/Blue receive concrete endpoint evidence instead of sparse titles.
"""

from __future__ import annotations

import ast
import json
import re
from html import unescape
from pathlib import Path
from urllib.parse import parse_qsl, urlparse


HTTP_EXAMPLES_LIMIT = 3
RESPONSE_SNIPPET_LIMIT = 400
REQUEST_PARAM_LIMIT = 20
FORM_FIELD_LIMIT = 20
RESPONSE_CLUE_LIMIT = 8
COOKIE_SURFACE_LIMIT = 8

IDENTITY_COOKIE_NAMES = {
    "role", "roles", "user_id", "userid", "user", "uid", "account_id",
    "accountid", "is_admin", "isadmin", "admin", "privilege", "permission",
}
SECURITY_COOKIE_NAMES = {
    "session", "sessionid", "phpsessid", "jsessionid", "sid", "auth",
    "auth_token", "token", "csrf", "xsrf",
}
BAC_SURFACE_KEYWORDS = (
    "bac", "idor", "access", "admin", "profile", "account", "order",
    "ownership", "role", "privilege", "user", "permission",
)


def _normalize_pattern_id(bug: dict) -> str:
    raw = str(bug.get("pattern_id") or bug.get("type") or "").strip().upper()
    if raw:
        return raw
    title = str(bug.get("title", "")).lower()
    desc = str(bug.get("description", "")).lower()
    text = f"{title}\n{desc}"
    if "idor" in text or "ownership" in text:
        return "BAC-03"
    if "cookie" in text or "admin" in text:
        return "BAC-02"
    if "quantity" in text or "amount" in text or "price" in text:
        return "BLF-07"
    return "BAC-00"


def _normalize_category(pattern_id: str) -> str:
    return "BLF" if pattern_id.startswith("BLF") else "BAC"


def _clean_text(text: str) -> str:
    text = unescape(text or "")
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _extract_response_clues(body: str, content_type: str) -> list[str]:
    if not body:
        return []

    clues: list[str] = []
    lower_ct = (content_type or "").lower()
    stripped = body.strip()
    is_jsonish = "json" in lower_ct or stripped.startswith("{") or stripped.startswith("[")

    if is_jsonish:
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                clues.append("JSON keys: " + ", ".join(list(data.keys())[:15]))
            elif isinstance(data, list):
                clues.append(f"JSON list size sample: {len(data)}")
                if data and isinstance(data[0], dict):
                    clues.append("JSON item keys: " + ", ".join(list(data[0].keys())[:15]))
        except Exception:
            clues.append("JSON-like response body present")
        return clues[:RESPONSE_CLUE_LIMIT]

    lower_body = body.lower()
    if "<html" in lower_body or "</html>" in lower_body:
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = _clean_text(title_match.group(1))
            if title:
                clues.append(f"HTML title: {title[:180]}")

        headings = [
            _clean_text(m)
            for m in re.findall(r"<h[1-3][^>]*>(.*?)</h[1-3]>", body, re.IGNORECASE | re.DOTALL)
        ]
        headings = [h for h in headings if h]
        if headings:
            clues.append("Headings: " + " | ".join(headings[:4]))

        keyword_map = (
            ("admin markers", ("admin", "dashboard", "user management")),
            ("account markers", ("profile", "my account", "account details")),
            ("commerce markers", ("cart", "checkout", "coupon", "quantity")),
            ("order/transfer markers", ("order", "payment", "transfer", "balance")),
            ("auth markers", ("login", "register", "logout", "password")),
        )
        for label, keywords in keyword_map:
            if any(k in lower_body for k in keywords):
                clues.append(label)
        return clues[:RESPONSE_CLUE_LIMIT]

    snippet = _clean_text(body)
    if snippet:
        clues.append("Text snippet: " + snippet[:220])
    return clues[:RESPONSE_CLUE_LIMIT]


def _extract_param_names(url: str, post_data: str | None) -> list[str]:
    names: list[str] = []
    parsed = urlparse(url)
    for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
        if key and key not in names:
            names.append(key)
    if post_data:
        body_pairs = parse_qsl(post_data, keep_blank_values=True)
        if body_pairs:
            for key, _value in body_pairs:
                if key and key not in names:
                    names.append(key)
        else:
            raw_names = re.findall(r"([A-Za-z_][A-Za-z0-9_\-]*)=", post_data)
            for key in raw_names:
                if key not in names:
                    names.append(key)
    return names[:REQUEST_PARAM_LIMIT]


def _parse_literal_dict(raw: str) -> dict:
    try:
        value = ast.literal_eval(raw)
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _parse_cookie_line(line: str) -> dict | None:
    match = re.match(r"([^=\s]+)=([^\s]*)\s+\((.*)\)$", line.strip())
    if not match:
        return None
    meta: dict[str, str] = {}
    for part in match.group(3).split(","):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        meta[key.strip()] = value.strip()
    return {
        "name": match.group(1).strip(),
        "value": match.group(2).strip(),
        "domain": meta.get("domain", ""),
        "path": meta.get("path", "/"),
        "httpOnly": meta.get("httpOnly", "False") == "True",
        "secure": meta.get("secure", "False") == "True",
    }


def _parse_form_field_line(line: str) -> dict | None:
    match = re.match(r"-\s+(.+?)\s+\(type=([^,]+),\s+value=(.*?)\)$", line.strip())
    if not match:
        return None
    value = match.group(3).strip()
    return {
        "name": match.group(1).strip(),
        "type": match.group(2).strip(),
        "value": None if value == "None" else value,
    }


def _empty_crawl_payload() -> dict:
    return {"anonymous": {"http_traffic": [], "cookies": []}, "authenticated": []}


def _parse_formatted_crawl_data(path: Path) -> dict:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return {}

    payload = _empty_crawl_payload()
    current_bucket: dict | None = None
    index = 0

    while index < len(lines):
        stripped = lines[index].strip()
        if stripped == "ANONYMOUS CRAWL DATA":
            current_bucket = payload["anonymous"]
            index += 1
            continue

        auth_match = re.match(r"AUTHENTICATED CRAWL.*account:\s*(.+)$", stripped)
        if auth_match:
            auth_entry = {
                "label": auth_match.group(1).strip() or "authenticated",
                "data": {"http_traffic": [], "cookies": []},
            }
            payload["authenticated"].append(auth_entry)
            current_bucket = auth_entry["data"]
            index += 1
            continue

        if current_bucket is None:
            index += 1
            continue

        if stripped == "## Cookies":
            index += 1
            while index < len(lines):
                cookie_line = lines[index]
                cookie_stripped = cookie_line.strip()
                if not cookie_stripped:
                    index += 1
                    break
                if cookie_stripped.startswith("## ") or cookie_stripped.startswith("Summary:"):
                    break
                if cookie_line.startswith("  "):
                    cookie = _parse_cookie_line(cookie_line)
                    if cookie:
                        current_bucket.setdefault("cookies", []).append(cookie)
                index += 1
            continue

        page_match = re.match(r"\[(\d+|\?)\]\s+([A-Z]+)\s+(\S+)", stripped)
        if page_match:
            record = {
                "response_status": None if page_match.group(1) == "?" else int(page_match.group(1)),
                "method": page_match.group(2).upper(),
                "url": page_match.group(3),
                "resource_type": "document",
                "headers": {},
                "response_headers": {},
                "response_body": "",
                "postData": None,
                "form_fields": None,
            }
            index += 1
            while index < len(lines):
                sub = lines[index]
                sub_stripped = sub.strip()
                if (
                    re.match(r"\[(\d+|\?)\]\s+[A-Z]+\s+\S+", sub_stripped)
                    or sub_stripped.startswith("FORM:")
                    or sub_stripped.startswith("## ")
                    or sub_stripped.startswith("Summary:")
                    or sub_stripped == "ANONYMOUS CRAWL DATA"
                    or sub_stripped.startswith("AUTHENTICATED CRAWL")
                ):
                    break
                if sub_stripped.startswith("Query params:"):
                    pass
                elif sub_stripped.startswith("Body params:"):
                    record["postData"] = sub_stripped.split(":", 1)[1].strip().replace(", ", "&")
                elif sub_stripped.startswith("Raw body:"):
                    record["postData"] = sub_stripped.split(":", 1)[1].strip()
                elif sub_stripped.startswith("Response headers:"):
                    record["response_headers"] = _parse_literal_dict(sub_stripped.split(":", 1)[1].strip())
                elif sub_stripped.startswith("Content-Type:"):
                    content_type = sub_stripped.split(":", 1)[1].strip()
                    record.setdefault("response_headers", {})["content-type"] = content_type
                elif sub_stripped.startswith("Body ("):
                    if index + 1 < len(lines) and lines[index + 1].strip() == "```":
                        index += 2
                        body_lines: list[str] = []
                        while index < len(lines) and lines[index].strip() != "```":
                            body_lines.append(lines[index])
                            index += 1
                        record["response_body"] = "\n".join(body_lines).rstrip()
                index += 1
            current_bucket.setdefault("http_traffic", []).append(record)
            continue

        form_match = re.match(r"FORM:\s+([A-Z]+)\s+(\S+)", stripped)
        if form_match:
            record = {
                "method": form_match.group(1).upper(),
                "url": form_match.group(2),
                "resource_type": "form",
                "headers": {},
                "response_headers": {},
                "response_body": None,
                "postData": None,
                "parent_url": None,
                "form_fields": [],
            }
            index += 1
            while index < len(lines):
                sub = lines[index]
                sub_stripped = sub.strip()
                if (
                    re.match(r"\[(\d+|\?)\]\s+[A-Z]+\s+\S+", sub_stripped)
                    or sub_stripped.startswith("FORM:")
                    or sub_stripped.startswith("## ")
                    or sub_stripped.startswith("Summary:")
                    or sub_stripped == "ANONYMOUS CRAWL DATA"
                    or sub_stripped.startswith("AUTHENTICATED CRAWL")
                ):
                    break
                if sub_stripped.startswith("Found on page:"):
                    record["parent_url"] = sub_stripped.split(":", 1)[1].strip()
                elif sub_stripped == "Fields:":
                    index += 1
                    while index < len(lines):
                        field_line = lines[index].strip()
                        if not field_line.startswith("- "):
                            break
                        field = _parse_form_field_line(field_line)
                        if field:
                            record["form_fields"].append(field)
                        index += 1
                    continue
                index += 1
            current_bucket.setdefault("http_traffic", []).append(record)
            continue

        index += 1

    return payload


def _request_text(record: dict) -> str:
    parsed = urlparse(record.get("url", ""))
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    lines = [f"{record.get('method', 'GET')} {path} HTTP/1.1"]
    host = parsed.netloc
    if host:
        lines.append(f"Host: {host}")

    headers = record.get("headers", {}) or {}
    content_type = headers.get("content-type") or headers.get("Content-Type")
    if content_type:
        lines.append(f"Content-Type: {content_type}")
    post_data = record.get("postData")
    if post_data:
        lines.append("")
        lines.append(str(post_data)[:1200])
    return "\n".join(lines)


def _path_regex(endpoint: str) -> re.Pattern[str]:
    path = urlparse(endpoint if "://" in endpoint else f"http://x{endpoint}").path or endpoint or "/"
    path = re.sub(r"\{[^}/]+\}", r"[^/]+", path)
    path = re.sub(r"<[^>/]+>", r"[^/]+", path)
    return re.compile(rf"^{path}$", re.IGNORECASE)


def _match_records(endpoint: str, method: str, crawl_payload: dict) -> list[dict]:
    if not crawl_payload:
        return []

    method = (method or "").upper()
    pattern = _path_regex(endpoint)
    matches: list[dict] = []

    def add_records(session_label: str, records: list[dict]) -> None:
        for record in records or []:
            record_method = str(record.get("method", "GET")).upper()
            parsed = urlparse(record.get("url", ""))
            path = parsed.path or "/"
            if method and record_method != method:
                continue
            if not pattern.match(path):
                continue
            enriched = dict(record)
            enriched["_session_label"] = session_label
            matches.append(enriched)

    anon = crawl_payload.get("anonymous") or {}
    add_records("anonymous", anon.get("http_traffic", []))
    for auth in crawl_payload.get("authenticated", []) or []:
        add_records(str(auth.get("label", "authenticated")), auth.get("data", {}).get("http_traffic", []))

    def sort_key(record: dict) -> tuple[int, int, int]:
        session_label = record.get("_session_label", "")
        auth_rank = 0 if session_label != "anonymous" else 1
        body_len = len(record.get("response_body") or "")
        form_rank = 0 if record.get("resource_type") == "form" else 1
        return (auth_rank, form_rank, -body_len)

    matches.sort(key=sort_key)
    return matches


def _build_http_examples(records: list[dict], endpoint: str) -> list[dict]:
    examples: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        key = (str(record.get("method", "GET")).upper(), record.get("url", ""))
        if key in seen:
            continue
        seen.add(key)
        body = record.get("response_body") or ""
        resp_headers = record.get("response_headers", {}) or {}
        content_type = str(resp_headers.get("content-type") or resp_headers.get("Content-Type") or "")
        response_clues = _extract_response_clues(body, content_type)
        why = f"Matched bug endpoint {endpoint}"
        if record.get("_session_label") and record["_session_label"] != "anonymous":
            why += f" with authenticated session {record['_session_label']}"
        if response_clues:
            why += "; " + "; ".join(response_clues[:2])
        examples.append({
            "request": _request_text(record),
            "response_status": record.get("response_status"),
            "response_snippet": (body[:RESPONSE_SNIPPET_LIMIT] + "...") if len(body) > RESPONSE_SNIPPET_LIMIT else body,
            "why_relevant": why,
            "session_label": record.get("_session_label", "anonymous"),
        })
        if len(examples) >= HTTP_EXAMPLES_LIMIT:
            break
    return examples


def _infer_method(bug: dict, records: list[dict]) -> str:
    method = str(bug.get("method") or "").upper().strip()
    if method:
        return method
    if records:
        return str(records[0].get("method", "GET")).upper()
    endpoint = str(bug.get("endpoint", "")).lower()
    payload = str(bug.get("payload", "")).lower()
    if any(k in endpoint for k in ("/add", "/update", "/delete", "/transfer", "/login")):
        return "POST"
    if "=" in payload and "cookie:" not in payload:
        return "POST"
    return "GET"


def _infer_auth_required(endpoint: str, records: list[dict], bug: dict) -> bool:
    if "auth_required" in bug:
        return bool(bug.get("auth_required"))
    if any(r.get("_session_label") != "anonymous" for r in records):
        return True
    endpoint_lower = endpoint.lower()
    return any(k in endpoint_lower for k in ("/admin", "/profile", "/account", "/cart", "/order", "/transfer"))


def _infer_credentials(records: list[dict], bug: dict) -> list[str]:
    creds = bug.get("auth_credentials_needed")
    labels = []
    for record in records:
        label = record.get("_session_label")
        if label and label != "anonymous" and label not in labels:
            labels.append(label)
    if isinstance(creds, list) and creds:
        normalized = [str(c).strip() for c in creds if str(c).strip()]
        if labels:
            matched = [c for c in normalized if c in labels]
            return matched or labels[:5]
        return normalized[:5]
    return labels[:5]


def _infer_endpoint_function(endpoint: str, body_clues: list[str], bug: dict) -> str:
    title = str(bug.get("title", ""))
    desc = str(bug.get("description", "") or bug.get("hypothesis", ""))
    if title:
        return title
    if desc:
        return desc[:160]
    if body_clues:
        return body_clues[0]
    return f"Observed endpoint {endpoint}"


def _infer_exploit_approach(bug: dict, endpoint: str, payload: str) -> str:
    existing = str(bug.get("exploit_approach", "")).strip()
    if existing:
        return existing
    desc = str(bug.get("description", "") or bug.get("hypothesis", "")).strip()
    if payload:
        return f"Khai thác quanh endpoint {endpoint} với payload/manipulation: {payload}. {desc}".strip()
    return desc or f"Kiểm tra endpoint {endpoint} để xác nhận hành vi BAC/BLF nghi ngờ."


def _infer_verify_method(bug: dict, endpoint: str, response_clues: list[str]) -> str:
    existing = str(bug.get("verify_method", "")).strip()
    if existing:
        return existing
    clue_text = "; ".join(response_clues[:3]) if response_clues else "so sánh response thực tế"
    return f"Thực hiện request tới {endpoint} và xác nhận bằng raw evidence: {clue_text}."


def _load_crawl_payload(run_dir: str) -> dict:
    path = Path(run_dir) / "crawl_raw.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        fallback_path = Path(run_dir) / "crawl_data.txt"
        return _parse_formatted_crawl_data(fallback_path)


def _cookie_value_sample(value: str) -> str:
    text = str(value or "")
    if len(text) <= 32:
        return text or "(empty)"
    return text[:18] + "..." + text[-8:]


def _cookie_probe_hint(name: str, value: str) -> str:
    lower_name = name.lower()
    lower_value = str(value or "").lower()
    if "role" in lower_name or "privilege" in lower_name or "permission" in lower_name:
        return "baseline user request -> tamper role-like cookie value (for example user to admin) -> verify impact"
    if lower_name in {"is_admin", "isadmin", "admin"}:
        return "baseline user request -> try boolean admin values such as 1/true -> verify impact"
    if lower_name in {"user_id", "userid", "uid", "account_id", "accountid", "user"}:
        if lower_value.isdigit():
            return "baseline user request -> try nearby object/user ids -> compare response ownership"
        return "baseline user request -> try alternate observed identity value -> compare response ownership"
    if lower_name in SECURITY_COOKIE_NAMES:
        return "session/auth cookie; only test structure if clearly client-controlled"
    return "compare baseline request with and without this client-visible cookie"


def _collect_cookie_surfaces(crawl_payload: dict) -> list[dict]:
    surfaces: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for auth_entry in crawl_payload.get("authenticated", []) or []:
        if not isinstance(auth_entry, dict):
            continue
        label = str(auth_entry.get("label", "authenticated") or "authenticated")
        cookies = auth_entry.get("cookies")
        if cookies is None:
            cookies = auth_entry.get("data", {}).get("cookies", [])
        for cookie in cookies or []:
            if not isinstance(cookie, dict):
                continue
            name = str(cookie.get("name", "") or "").strip()
            value = str(cookie.get("value", "") or "").strip()
            if not name:
                continue
            lower_name = name.lower()
            http_only = bool(cookie.get("httpOnly", False))
            secure = bool(cookie.get("secure", False))
            identity_like = lower_name in IDENTITY_COOKIE_NAMES
            client_visible = not http_only
            security_cookie = lower_name in SECURITY_COOKIE_NAMES
            if not (identity_like or (client_visible and not security_cookie)):
                continue
            key = (label, lower_name, value[:32])
            if key in seen:
                continue
            seen.add(key)
            if identity_like and client_visible:
                signal = "client-visible identity/role cookie"
            elif identity_like:
                signal = "identity/role cookie"
            else:
                signal = "client-visible application state cookie"
            surfaces.append({
                "session": label,
                "name": name,
                "value": value,
                "value_sample": _cookie_value_sample(value),
                "httpOnly": http_only,
                "secure": secure,
                "signal": signal,
                "probe": _cookie_probe_hint(name, value),
            })
    return surfaces[:COOKIE_SURFACE_LIMIT]


def _bug_can_use_cookie_surface(bug: dict, endpoint: str, pattern_id: str) -> bool:
    text = " ".join(
        str(bug.get(key, "") or "")
        for key in (
            "category", "title", "hypothesis", "exploit_approach",
            "verify_method", "auth_observation",
        )
    )
    text = f"{pattern_id} {endpoint} {text}".lower()
    if pattern_id.startswith("BLF"):
        return False
    return any(keyword in text for keyword in BAC_SURFACE_KEYWORDS)


def _derive_attack_variants(
    bug: dict,
    endpoint: str,
    method: str,
    cookie_surfaces: list[dict],
) -> list[str]:
    variants: list[str] = []
    lower_endpoint = endpoint.lower()
    lower_text = " ".join(
        str(bug.get(key, "") or "")
        for key in ("title", "hypothesis", "exploit_approach", "verify_method")
    ).lower()
    if method.upper() in {"GET", "HEAD"} and any(k in lower_text + " " + lower_endpoint for k in ("admin", "access", "idor", "profile", "order")):
        variants.append("direct read-only access with anonymous and regular-user session, then verify response marker/status")
    if "admin" in lower_endpoint or "admin" in lower_text:
        variants.append("sibling admin endpoints such as /admin/users, /admin/orders, /admin/dashboard if direct /admin redirects")
    if "idor" in lower_text or "{id}" in endpoint or any(k in lower_endpoint for k in ("profile", "order", "account")):
        variants.append("object/id tampering against nearby or observed ids, then compare owner-specific response data")
    for surface in cookie_surfaces:
        variants.append(f"cookie tampering candidate: {surface['name']}={surface['value_sample']} -> {surface['probe']}")
    deduped: list[str] = []
    for item in variants:
        if item not in deduped:
            deduped.append(item)
    return deduped[:8]


def _normalize_endpoint(bug: dict, records: list[dict]) -> str:
    endpoint = str(bug.get("endpoint", "")).strip()
    if endpoint:
        return urlparse(endpoint if "://" in endpoint else f"http://x{endpoint}").path or endpoint
    if records:
        return urlparse(records[0].get("url", "")).path or ""
    return ""


def _find_related_page_records(endpoint: str, crawl_payload: dict, records: list[dict]) -> list[dict]:
    related: list[dict] = []
    seen: set[str] = set()
    parent_urls = [
        r.get("parent_url")
        for r in records
        if r.get("resource_type") == "form" and r.get("parent_url")
    ]
    candidate_paths = [endpoint] + [
        urlparse(url).path or "/"
        for url in parent_urls
        if isinstance(url, str) and url.strip()
    ]

    for path in candidate_paths:
        page_records = _match_records(path, "GET", crawl_payload)
        for record in page_records:
            url = record.get("url", "")
            if url and url not in seen:
                seen.add(url)
                related.append(record)
    return related


def _derive_response_clues(records: list[dict], crawl_payload: dict, endpoint: str) -> list[str]:
    candidates = list(records)
    candidates.extend(_find_related_page_records(endpoint, crawl_payload, records))
    for record in candidates:
        body = record.get("response_body") or ""
        if not body:
            continue
        resp_headers = record.get("response_headers", {}) or {}
        content_type = str(resp_headers.get("content-type") or resp_headers.get("Content-Type") or "")
        clues = _extract_response_clues(body, content_type)
        if clues:
            return clues
    return []


def enrich_bugs(run_dir: str, bugs: list[dict]) -> list[dict]:
    """Return enriched bug dossiers derived from risk-bug + crawl artifacts."""
    crawl_payload = _load_crawl_payload(run_dir)
    all_cookie_surfaces = _collect_cookie_surfaces(crawl_payload)
    enriched_bugs: list[dict] = []

    for idx, original in enumerate(bugs):
        if not isinstance(original, dict):
            continue
        bug = dict(original)
        pattern_id = _normalize_pattern_id(bug)
        records_pre = _match_records(str(bug.get("endpoint", "")), str(bug.get("method", "")), crawl_payload)
        endpoint = _normalize_endpoint(bug, records_pre)
        records = _match_records(endpoint, str(bug.get("method", "")), crawl_payload)
        method = _infer_method(bug, records)
        records = _match_records(endpoint, method, crawl_payload)
        http_examples = bug.get("http_examples")
        if not isinstance(http_examples, list) or not http_examples:
            http_examples = _build_http_examples(records, endpoint)

        form_fields = bug.get("form_fields")
        if isinstance(form_fields, list) and form_fields and not all(isinstance(field, dict) for field in form_fields):
            normalized_fields = []
            for field in form_fields:
                if isinstance(field, dict):
                    name = str(field.get("name", "")).strip()
                    if not name:
                        continue
                    normalized_fields.append({
                        "name": name,
                        "type": str(field.get("type", "?") or "?"),
                        "value": str(field.get("value", "") or "")[:80],
                    })
                elif isinstance(field, str):
                    name = field.strip()
                    if name:
                        normalized_fields.append({"name": name, "type": "?", "value": ""})
            form_fields = normalized_fields
        if not isinstance(form_fields, list) or not form_fields:
            form_fields = []
            for record in records:
                if record.get("form_fields"):
                    form_fields = record["form_fields"][:FORM_FIELD_LIMIT]
                    break

        request_params = list(bug.get("request_params") or [])
        if not request_params and records:
            request_params = _extract_param_names(records[0].get("url", ""), records[0].get("postData"))
        if not request_params and form_fields:
            request_params = [
                str(field.get("name", "")).strip()
                for field in form_fields
                if str(field.get("name", "")).strip()
            ]

        response_clues = bug.get("response_clues")
        if not isinstance(response_clues, list) or not response_clues:
            response_clues = _derive_response_clues(records, crawl_payload, endpoint)

        payload = str(bug.get("payload", "")).strip()
        hypothesis = str(bug.get("hypothesis") or bug.get("description") or "").strip()
        auth_required = _infer_auth_required(endpoint, records, bug)
        auth_credentials_needed = _infer_credentials(records, bug)
        endpoint_function = str(bug.get("endpoint_function") or "").strip() or _infer_endpoint_function(endpoint, response_clues, bug)
        auth_observation = str(bug.get("auth_observation") or "").strip()
        if not auth_observation:
            auth_observation = "authenticated" if auth_required else "anonymous or mixed"
            if auth_credentials_needed:
                auth_observation += f"; observed sessions: {', '.join(auth_credentials_needed)}"
        cookie_attack_surface = bug.get("cookie_attack_surface")
        if not isinstance(cookie_attack_surface, list):
            cookie_attack_surface = []
        if not cookie_attack_surface and _bug_can_use_cookie_surface(bug, endpoint, pattern_id):
            cookie_attack_surface = all_cookie_surfaces[:COOKIE_SURFACE_LIMIT]

        attack_variants = bug.get("attack_variants")
        if not isinstance(attack_variants, list):
            attack_variants = []
        if not attack_variants:
            attack_variants = _derive_attack_variants(
                bug,
                endpoint,
                method,
                cookie_attack_surface,
            )

        enriched = dict(bug)
        enriched.update({
            "id": bug.get("id") or f"BUG-{idx + 1:03d}",
            "category": bug.get("category") or _normalize_category(pattern_id),
            "pattern_id": pattern_id,
            "title": bug.get("title") or endpoint_function,
            "risk_level": bug.get("risk_level") or "MEDIUM",
            "endpoint": endpoint,
            "method": method,
            "hypothesis": hypothesis,
            "exploit_approach": _infer_exploit_approach(bug, endpoint, payload),
            "verify_method": _infer_verify_method(bug, endpoint, response_clues),
            "http_examples": http_examples[:HTTP_EXAMPLES_LIMIT],
            "auth_required": auth_required,
            "auth_credentials_needed": auth_credentials_needed,
            "request_params": request_params[:REQUEST_PARAM_LIMIT],
            "form_fields": form_fields[:FORM_FIELD_LIMIT],
            "response_clues": response_clues[:RESPONSE_CLUE_LIMIT],
            "cookie_attack_surface": cookie_attack_surface[:COOKIE_SURFACE_LIMIT],
            "attack_variants": attack_variants[:8],
            "endpoint_function": endpoint_function,
            "auth_observation": auth_observation,
            "payload": payload,
            "status": bug.get("status", "PENDING"),
            "PoC": bug.get("PoC", ""),
            "attempt_count": int(bug.get("attempt_count", 0) or 0),
            "debate_rounds": int(bug.get("debate_rounds", 0) or 0),
        })
        enriched_bugs.append(enriched)

    return enriched_bugs


def load_and_enrich_risk_bugs(run_dir: str) -> list[dict]:
    """Load risk-bug.json, enrich it, persist it, and return the enriched list."""
    path = Path(run_dir) / "risk-bug.json"
    if not path.exists():
        return []

    try:
        bugs = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []

    if not isinstance(bugs, list):
        return []

    enriched = enrich_bugs(run_dir, bugs)
    if enriched != bugs:
        path.write_text(json.dumps(enriched, ensure_ascii=False, indent=2), encoding="utf-8")
    return enriched
