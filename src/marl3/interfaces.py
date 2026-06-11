"""Protocol interfaces — allow mock/test implementations without coupling."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from .contracts.recon import ReconArtifact
from .contracts.dossier import BugDossier
from .contracts.evidence import Evidence, Verdict
from .contracts.results import Finding


@runtime_checkable
class ReconPort(Protocol):
    async def run(self, target_url: str, credentials: dict[str, str]) -> ReconArtifact: ...


@runtime_checkable
class HunterPort(Protocol):
    async def run(self, recon: ReconArtifact) -> list[BugDossier]: ...


@runtime_checkable
class ExecPort(Protocol):
    async def run(self, dossier: BugDossier, recon: ReconArtifact, strategy: str) -> Evidence: ...


@runtime_checkable
class ReportSink(Protocol):
    async def write(self, findings: list[Finding]) -> None: ...
