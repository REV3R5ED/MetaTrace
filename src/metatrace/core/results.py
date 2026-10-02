"""Shared result envelope: every command returns this shape.

Human-readable rendering and ``--json`` derive from the same envelope
so automation consumers see a stable contract:

    {
      "tool": "metatrace",
      "version": "0.1.0",
      "command": "inspect",
      "timestamp": "2026-10-02T22:00:00Z",
      "target": "photo.jpg",
      "status": "ok" | "warning" | "error",
      "summary": "human one-liner",
      "data": {... command-specific ...},
      "findings": [...]
    }
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from metatrace import __version__
from metatrace.core.logging import utc_now_iso

Status = Literal["ok", "warning", "error"]


@dataclass
class Finding:
    """An observation worth flagging — never an authenticity verdict."""

    title: str
    severity: str  # "info" | "low" | "medium" | "high"
    reason: str
    evidence: list[str] = field(default_factory=list)
    confidence: int = 0  # 0-100, 0 = not assessed

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Result:
    command: str
    target: str | None = None
    status: Status = "ok"
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    tool: str = "metatrace"
    version: str = __version__
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        if self.status == "ok":
            self.status = "warning"

    def fail(self, summary: str) -> None:
        self.status = "error"
        self.summary = summary


# Structured exit codes shared by every command.
EXIT_OK = 0  # success, nothing of concern
EXIT_FINDINGS = 1  # success, but findings/warnings were produced
EXIT_ERROR = 2  # usage or operational error


def exit_code_for(result: Result) -> int:
    if result.status == "error":
        return EXIT_ERROR
    if result.status == "warning":
        return EXIT_FINDINGS
    return EXIT_OK
