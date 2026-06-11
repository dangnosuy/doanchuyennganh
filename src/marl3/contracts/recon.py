from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field

from .http import HttpExchange


class AuthProfile(BaseModel):
    label: str = Field(description="Short label, must match ^[a-z0-9_]{1,32}$")
    role: str = Field(description="Semantic role, e.g. 'admin', 'user', 'anon'")
    # One of: bearer / cookie / storage_state
    bearer_token: Optional[str] = None
    cookie_header: Optional[str] = None
    storage_state_path: Optional[str] = None  # path to sessions.json slice


class AuthDiff(BaseModel):
    """Captures the access delta between two auth levels — core BAC signal."""

    endpoint: str
    method: str
    anon_status: int
    auth_status: int
    anon_body_ref_id: Optional[str] = None   # blob_id from BodyStore
    auth_body_ref_id: Optional[str] = None
    note: str = ""


class Endpoint(BaseModel):
    url: str
    method: str
    endpoint: str = ""  # parameterised template
    auth_required: bool = False
    content_type: str = ""
    parameters: list[str] = Field(default_factory=list)
    json_keys: list[str] = Field(default_factory=list)
    numeric_fields: list[str] = Field(default_factory=list)
    id_fields: list[str] = Field(default_factory=list)
    discovery: str = "crawled"  # "crawled" | "probed" | "guessed"


class WorkflowNode(BaseModel):
    node_id: str
    label: str
    url: str
    method: str
    auth_required: bool = False


class WorkflowEdge(BaseModel):
    from_node: str
    to_node: str
    label: str = ""


class WorkflowGraph(BaseModel):
    nodes: list[WorkflowNode] = Field(default_factory=list)
    edges: list[WorkflowEdge] = Field(default_factory=list)
    chains: list[list[str]] = Field(default_factory=list, description="Ordered node_id sequences")


class BusinessFlow(BaseModel):
    flow_id: str
    name: str
    description: str = ""
    steps: list[str] = Field(description="Ordered endpoint templates")
    state_fields: list[str] = Field(default_factory=list, description="Fields that carry state across steps")
    numeric_fields: list[str] = Field(default_factory=list, description="Mutable numeric fields (price, qty, …)")


class ReconArtifact(BaseModel):
    """The single source of truth produced by the crawler phase → recon.json."""

    target_url: str
    crawl_timestamp: str
    endpoints: list[Endpoint] = Field(default_factory=list)
    exchanges: list[HttpExchange] = Field(default_factory=list)
    auth_profiles: list[AuthProfile] = Field(default_factory=list)
    auth_diffs: list[AuthDiff] = Field(default_factory=list)
    workflow_graph: Optional[WorkflowGraph] = None
    business_flows: list[BusinessFlow] = Field(default_factory=list)
    api_hints: list[str] = Field(default_factory=list, description="Observed API framework hints")
    bodies_dir: str = Field(default="bodies", description="Relative path to BodyStore directory")
    # Issue-006: explicit auth outcome so downstream can distinguish "no BAC surface" from "login broke"
    auth_attempted: bool = Field(default=False, description="True if credentials were supplied")
    auth_succeeded: bool = Field(default=False, description="True if login returned a valid session")
    auth_error: str = Field(default="", description="Non-empty when auth was attempted but failed")
