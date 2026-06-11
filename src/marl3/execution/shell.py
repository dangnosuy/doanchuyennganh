from __future__ import annotations

import json
import shlex
import subprocess
from pathlib import Path


class ShellRunner:
    def __init__(self, workspace_root: Path, default_timeout_s: int = 60) -> None:
        self._workspace_root = Path(workspace_root).resolve()
        self._default_timeout_s = default_timeout_s

    def execute_command(self, command: str, cwd: str | None = None, timeout_s: int | None = None) -> str:
        if not command or not command.strip():
            return json.dumps({"error": "empty command"})

        blocked = ("rm -rf", "shutdown", "reboot", "mkfs", ":(){", "dd if=", "chmod 000 /")
        lowered = command.lower()
        if any(token in lowered for token in blocked):
            return json.dumps({"error": "command blocked by safety policy", "command": command})

        args = shlex.split(command)
        if not args:
            return json.dumps({"error": "unable to parse command"})

        resolved_cwd = self._workspace_root
        if cwd:
            candidate = (Path(cwd) if Path(cwd).is_absolute() else self._workspace_root / cwd).resolve()
            if self._workspace_root not in candidate.parents and candidate != self._workspace_root:
                return json.dumps({"error": "cwd escapes workspace root", "cwd": cwd})
            resolved_cwd = candidate

        try:
            proc = subprocess.run(
                args,
                cwd=str(resolved_cwd),
                capture_output=True,
                text=True,
                timeout=timeout_s or self._default_timeout_s,
                check=False,
            )
            return json.dumps({
                "command": command,
                "cwd": str(resolved_cwd),
                "returncode": proc.returncode,
                "stdout": proc.stdout[-12000:],
                "stderr": proc.stderr[-12000:],
            })
        except subprocess.TimeoutExpired as exc:
            return json.dumps({
                "command": command,
                "cwd": str(resolved_cwd),
                "error": "timeout",
                "stdout": (exc.stdout or "")[-4000:],
                "stderr": (exc.stderr or "")[-4000:],
            })
