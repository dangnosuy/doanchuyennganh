from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field

from .body import BodyRef


class HttpExchange(BaseModel):
    """One complete HTTP request/response pair — shared by recon and exec subsystems.

    Bodies are stored losslessly via BodyRef; never truncate inline.
    """

    seq: int = Field(default=0, description="Monotonic sequence within a session/run")
    exchange_id: str = Field(description="Unique ID, e.g. recon-0042 or exec-BUG-003-001")
    method: str
    url: str
    endpoint: str = Field(default="", description="Parameterised template, e.g. /api/users/{id}")

    # Request
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body_ref: Optional[BodyRef] = None

    # Response
    status: int = Field(default=0)
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body_ref: Optional[BodyRef] = None

    # Execution context
    actor: str = Field(default="anon", description="Auth label, e.g. 'admin', 'user_a', 'anon'")
    auth_profile: str = Field(default="", description="Name of the AuthProfile used")

    # Extracted metadata (populated by recorder, usable by proof-gate without re-reading body)
    json_keys: list[str] = Field(default_factory=list, description="Top-level keys if response is JSON")
    numeric_fields: dict[str, float] = Field(default_factory=dict, description="name→value for detected numeric fields")
    id_fields: dict[str, str | int] = Field(default_factory=dict, description="Suspected ID fields and their values")

    # HTML signals (server-rendered sites)
    html_title: str = Field(default="", description="<title> of HTML responses")
    forms: list[dict] = Field(default_factory=list, description="Discovered HTML forms: action/method/fields")

    label: str = Field(default="", description="Free-label for human readability")
    timestamp: str = Field(default="", description="ISO-8601 UTC")
    elapsed_ms: int = Field(default=0)
    error: Optional[str] = None
