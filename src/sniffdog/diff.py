"""Behavioural diff between two versions of a package.

Most high-profile compromises (event-stream, ua-parser-js, coa, rc, ctx) shipped
as a *new version of a trusted package*. Reviewing an upgrade means asking
"what can this version do that the last one could not?" — which is exactly the
set difference of finding fingerprints.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding, ScanResult, sorted_findings


@dataclass
class DiffResult:
    old: ScanResult
    new: ScanResult
    added: list[Finding] = field(default_factory=list)
    removed: list[Finding] = field(default_factory=list)
    files_added: list[str] = field(default_factory=list)
    install_hooks_added: list[Finding] = field(default_factory=list)

    @property
    def score_delta(self) -> int:
        return self.new.score - self.old.score

    def to_dict(self) -> dict:
        return {
            "old": {
                "name": self.old.package.name,
                "version": self.old.package.version,
                "score": self.old.score,
                "verdict": self.old.verdict,
            },
            "new": {
                "name": self.new.package.name,
                "version": self.new.package.version,
                "score": self.new.score,
                "verdict": self.new.verdict,
            },
            "score_delta": self.score_delta,
            "added": [f.to_dict() for f in sorted_findings(self.added)],
            "removed": [f.to_dict() for f in sorted_findings(self.removed)],
            "files_added": self.files_added,
        }


def _strip_version(path: str | None, version: str | None) -> str | None:
    """Make per-version paths comparable (pkg-1.0/x.py vs pkg-1.1/x.py are already stripped by the loader)."""
    if path and version:
        return path.replace(version, "{v}")
    return path


def diff_results(old: ScanResult, new: ScanResult, old_files: set[str] | None = None, new_files: set[str] | None = None) -> DiffResult:
    def key(f: Finding, v: str | None) -> str:
        g = Finding(f.rule_id, f.title, f.severity, f.category, f.message, _strip_version(f.file, v), None, None, f.snippet)
        return g.fingerprint()

    old_keys = {key(f, old.package.version) for f in old.findings}
    new_keys = {key(f, new.package.version) for f in new.findings}
    d = DiffResult(old, new)
    d.added = [f for f in new.findings if key(f, new.package.version) not in old_keys and not f.rule_id.startswith("META-")]
    d.removed = [f for f in old.findings if key(f, old.package.version) not in new_keys and not f.rule_id.startswith("META-")]
    d.install_hooks_added = [f for f in d.added if f.install_time]
    if old_files is not None and new_files is not None:
        d.files_added = sorted(new_files - old_files)
    return d
