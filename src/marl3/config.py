from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigError(Exception):
    """Raised for invalid or missing configuration — never calls sys.exit()."""


class LlmModelsConfig(BaseModel):
    crawler: str = "gpt-4.1"
    hunter: str = "gpt-4.1"
    red: str = "gpt-4.1"
    blue: str = "gpt-4.1"
    exec: str = "gpt-4.1"
    verifier: str = "gpt-4.1"
    reporter: str = "gpt-4.1"


class LlmConfig(BaseModel):
    base_url: str = "http://127.0.0.1:5000/v1"
    api_key: str = "sk-placeholder"
    models: LlmModelsConfig = Field(default_factory=LlmModelsConfig)
    timeout_s: int = 120
    max_retries: int = 3


class DebateConfig(BaseModel):
    max_rounds: int = 3
    max_exec_retries: int = 1
    max_verify_retries: int = 1
    per_bug_wall_clock_s: int = 600


class VerifierConfig(BaseModel):
    count: int = 3
    temperature: float = 0.0

    @classmethod
    def model_post_init(cls, __context):
        pass

    def __init__(self, **data):
        super().__init__(**data)
        if self.count % 2 == 0:
            raise ValueError(
                f"verifier.count must be odd for a clear majority vote, got {self.count}. Use 1, 3, 5, ..."
            )


class ExecutionConfig(BaseModel):
    http_timeout_s: int = 30
    max_redirects: int = 5
    user_agent: str = "marl3-pentest/0.1"


class ReconConfig(BaseModel):
    max_pages: int = 60
    max_depth: int = 4
    body_store_max_mb: int = 500


class WorkspaceConfig(BaseModel):
    base_dir: str = "./workspace"


class LoggingConfig(BaseModel):
    level: str = "INFO"
    file: str = "run.log"


class MemoryConfig(BaseModel):
    """Long-term experiential memory (persists across runs — 'gets smarter the more it is used')."""
    longterm_enabled: bool = True
    db_path: str = "~/.local/share/marl3/memory.db"  # ~ expanded at open time
    embedding_enabled: bool = False  # B2 enables semantic retrieval (fastembed)
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    promote_min_successes: int = 3   # B3: episodic → cross-target rule threshold
    promote_min_targets: int = 2


class AppConfig(BaseModel):
    llm: LlmConfig = Field(default_factory=LlmConfig)
    debate: DebateConfig = Field(default_factory=DebateConfig)
    verifier: VerifierConfig = Field(default_factory=VerifierConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    recon: ReconConfig = Field(default_factory=ReconConfig)
    workspace: WorkspaceConfig = Field(default_factory=WorkspaceConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)


_DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "default.yaml"


def load_config(config_path: Optional[Path] = None) -> AppConfig:
    """Load config from YAML file with .env overlay.

    Raises ConfigError (never sys.exit) on missing required values.
    """
    path = config_path or _DEFAULT_CONFIG_PATH
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")

    with open(path) as f:
        raw = yaml.safe_load(f)

    if raw is None:
        raw = {}

    # Resolve ${ENV_VAR} placeholders in string values
    raw = _resolve_env_vars(raw)

    # Overlay MARL2_* env vars (pydantic-settings style)
    _apply_env_overrides(raw)

    try:
        return AppConfig.model_validate(raw)
    except Exception as e:
        raise ConfigError(f"Invalid config: {e}") from e


def _resolve_env_vars(obj: object) -> object:
    if isinstance(obj, str):
        import re
        def _sub(m: re.Match) -> str:
            val = os.environ.get(m.group(1), "")
            return val
        return re.sub(r"\$\{([^}]+)\}", _sub, obj)
    if isinstance(obj, dict):
        return {k: _resolve_env_vars(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve_env_vars(v) for v in obj]
    return obj


def _apply_env_overrides(raw: dict) -> None:
    """Apply MARL2_LLM__BASE_URL style env overrides into raw dict."""
    prefix = "MARL2_"
    for key, val in os.environ.items():
        if not key.startswith(prefix):
            continue
        parts = key[len(prefix):].lower().split("__")
        node = raw
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = val
