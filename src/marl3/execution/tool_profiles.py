from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolProfile:
    name: str
    description: str
    tools: tuple[str, ...] = field(default_factory=tuple)


PREPARE_PROFILE = ToolProfile(
    name="prepare",
    description="Context gathering and local inspection before making state-changing calls.",
    tools=(
        "http_body_get",
        "read_text_file",
        "list_directory",
        "search_files",
        "browser_navigate",
        "browser_screenshot",
        "browser_network_requests",
    ),
)

ATTACK_PROFILE = ToolProfile(
    name="attack",
    description="Full exploit execution profile with browser, shell, filesystem, and HTTP tools.",
    tools=(
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
    ),
)

VERIFY_PROFILE = ToolProfile(
    name="verify",
    description="Evidence verification and post-exploit inspection profile.",
    tools=(
        "http_request",
        "http_body_get",
        "browser_navigate",
        "browser_screenshot",
        "browser_network_requests",
        "read_text_file",
        "list_directory",
    ),
)


PROFILES = {
    PREPARE_PROFILE.name: PREPARE_PROFILE,
    ATTACK_PROFILE.name: ATTACK_PROFILE,
    VERIFY_PROFILE.name: VERIFY_PROFILE,
}


def profile_for_mode(mode: str) -> ToolProfile:
    return PROFILES.get(mode, ATTACK_PROFILE)
