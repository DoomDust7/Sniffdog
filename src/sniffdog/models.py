"""Core data model shared by every analyzer, reporter and the scoring engine."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[value.strip().upper()]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name.lower()


class Category:
    INSTALL_HOOK = "install-hook"
    EXFILTRATION = "exfiltration"
    CODE_EXECUTION = "code-execution"
    OBFUSCATION = "obfuscation"
    PERSISTENCE = "persistence"
    DOWNLOADER = "downloader"
    IOC = "indicator"
    BINARY = "binary"
    TYPOSQUAT = "typosquat"
    METADATA = "metadata"
    DEPENDENCY_CONFUSION = "dependency-confusion"


class Ecosystem:
    PYPI = "pypi"
    NPM = "npm"
    UNKNOWN = "unknown"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    message: str
    file: str | None = None
    line: int | None = None
    column: int | None = None
    snippet: str | None = None
    confidence: float = 0.8
    install_time: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable identity used for diffing two versions of a package.

        Line numbers are deliberately excluded: an unrelated edit higher up in a
        file must not make an old finding look new.
        """
        norm = " ".join((self.snippet or "").split())
        raw = f"{self.rule_id}|{self.file or ''}|{norm}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name.lower()
        d["fingerprint"] = self.fingerprint()
        return d


@dataclass
class PackageInfo:
    name: str
    version: str | None = None
    ecosystem: str = Ecosystem.UNKNOWN
    source: str | None = None  # path or URL the artifact came from
    sha256: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    package: PackageInfo
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    verdict: str = "clean"
    files_scanned: int = 0
    bytes_scanned: int = 0
    duration_ms: int = 0
    errors: list[str] = field(default_factory=list)
    suppressed: int = 0

    @property
    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": asdict(self.package),
            "score": self.score,
            "verdict": self.verdict,
            "max_severity": self.max_severity.name.lower() if self.max_severity is not None else None,
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "duration_ms": self.duration_ms,
            "suppressed": self.suppressed,
            "errors": self.errors,
            "findings": [f.to_dict() for f in sorted_findings(self.findings)],
        }


def sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, -f.confidence, f.file or "", f.line or 0))
