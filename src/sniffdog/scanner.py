"""Orchestrates analyzers over one package and post-processes their findings."""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path

from . import archive
from .analyzers.base import ScanContext
from .analyzers.heuristics import ArchiveAnomalyAnalyzer, BinaryAnalyzer, IOCAnalyzer, ManifestAnalyzer, ObfuscationAnalyzer
from .analyzers.javascript import JavaScriptAnalyzer
from .analyzers.metadata import MetadataAnalyzer
from .analyzers.python_taint import PythonTaintAnalyzer
from .analyzers.typosquat import TyposquatAnalyzer
from .config import Config
from .models import Ecosystem, Finding, PackageInfo, ScanResult, Severity
from .registry import Artifact, Spec, fetch, parse_spec
from .scoring import correlate, score, verdict

SUPPRESS = re.compile(r"(?:#|//)\s*sniffdog:\s*ignore(?:\[([\w\-, *]+)\])?", re.I)


def default_analyzers():
    return [
        PythonTaintAnalyzer(),
        JavaScriptAnalyzer(),
        ManifestAnalyzer(),
        ObfuscationAnalyzer(),
        IOCAnalyzer(),
        BinaryAnalyzer(),
        ArchiveAnomalyAnalyzer(),
        TyposquatAnalyzer(),
        MetadataAnalyzer(),
    ]


def _guess_identity(path: Path, contents: archive.PackageContents) -> tuple[str, str | None]:
    """Best-effort package name/version from metadata files, falling back to the file name."""
    import json

    for f in contents.find("package.json")[:1]:
        try:
            pj = json.loads(f.data)
            if pj.get("name"):
                return pj["name"], pj.get("version")
        except (ValueError, UnicodeDecodeError):
            pass
    for f in contents:
        if f.name in ("PKG-INFO", "METADATA") and f.path.count("/") <= 1:
            t = f.text() or ""
            n = re.search(r"^Name:\s*(\S+)", t, re.M)
            v = re.search(r"^Version:\s*(\S+)", t, re.M)
            if n:
                return n.group(1), v.group(1) if v else None
    for f in contents.find("setup.py")[:1]:
        t = f.text() or ""
        n = re.search(r"""\bname\s*=\s*['"]([A-Za-z0-9][\w.\-]*)['"]""", t)
        v = re.search(r"""\bversion\s*=\s*['"]([\w.\-+!]+)['"]""", t)
        if n:
            return n.group(1), v.group(1) if v else None
    for f in contents.find("pyproject.toml")[:1]:
        t = f.text() or ""
        n = re.search(r'^\s*name\s*=\s*"([^"]+)"', t, re.M)
        v = re.search(r'^\s*version\s*=\s*"([^"]+)"', t, re.M)
        if n:
            return n.group(1), v.group(1) if v else None
    stem = path.name
    for suf in archive.ARCHIVE_SUFFIXES:
        if stem.lower().endswith(suf):
            stem = stem[: -len(suf)]
            break
    m = re.match(r"^(.+?)-(\d[\w.!+]*)(?:-.*)?$", stem)
    return (m.group(1), m.group(2)) if m else (stem, None)


class Scanner:
    def __init__(self, config: Config | None = None, analyzers=None):
        self.config = config or Config()
        self.analyzers = analyzers if analyzers is not None else default_analyzers()
        if not self.config.metadata:
            self.analyzers = [a for a in self.analyzers if a.name != "metadata"]

    # ------------------------------------------------------------------ entry points

    def scan_path(self, path: str | Path, package: PackageInfo | None = None) -> ScanResult:
        p = Path(path)
        t0 = time.perf_counter()
        contents = archive.load(p)
        if package is None:
            name, version = _guess_identity(p, contents)
            sha = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
            package = PackageInfo(name=name, version=version, source=str(p), sha256=sha)
        return self._scan(contents, package, t0)

    def scan_bytes(self, data: bytes, filename: str, package: PackageInfo) -> ScanResult:
        t0 = time.perf_counter()
        return self._scan(archive.load_bytes(data, filename), package, t0)

    def scan_artifact(self, art: Artifact) -> ScanResult:
        pkg = PackageInfo(
            name=art.spec.name,
            version=art.version,
            ecosystem=art.spec.ecosystem,
            source=art.url,
            sha256=art.sha256,
            metadata={**art.metadata, "artifact": art.filename},
        )
        return self.scan_bytes(art.data, art.filename, pkg)

    def scan_spec(self, spec: Spec | str) -> list[ScanResult]:
        if isinstance(spec, str):
            spec = parse_spec(spec)
        return [self.scan_artifact(a) for a in fetch(spec, self.config.artifact)]

    def scan_target(self, target: str) -> list[ScanResult]:
        """A local path (dir, archive, file) or a registry spec."""
        if Path(target).exists():
            return [self.scan_path(target)]
        return self.scan_spec(target)

    # ------------------------------------------------------------------ core

    def _scan(self, contents: archive.PackageContents, package: PackageInfo, t0: float) -> ScanResult:
        ctx = ScanContext.build(contents, package)
        result = ScanResult(package=package, files_scanned=len(contents), bytes_scanned=contents.total_bytes)
        findings: list[Finding] = []
        for a in self.analyzers:
            try:
                findings += a.analyze(ctx)
            except Exception as e:  # noqa: BLE001 - one broken analyzer must not hide the others
                result.errors.append(f"{a.name}: {type(e).__name__}: {e}")
            result.errors += getattr(a, "errors", [])
            if hasattr(a, "errors"):
                a.errors = []
        findings = self._postprocess(findings, ctx, result)
        findings += correlate(findings)
        result.findings = self._dedupe(findings)
        result.score = score(result.findings)
        result.verdict = verdict(result.findings, result.score)
        if self.config.allowed(package.name):
            result.verdict = "allowed"
        result.findings = [f for f in result.findings if f.severity >= self.config.min_severity]
        result.duration_ms = round((time.perf_counter() - t0) * 1000)
        return result

    def _postprocess(self, findings: list[Finding], ctx: ScanContext, result: ScanResult) -> list[Finding]:
        out = []
        for f in findings:
            if self.config.ignores(f) or self._inline_suppressed(f, ctx):
                result.suppressed += 1
                continue
            base = (f.file or "").split("<layer")[0]
            # Cross-ecosystem code is not run by the package manager: JS in a wheel/sdist is browser assets,
            # Python in an npm tarball only runs if an install script launches it.
            foreign = (ctx.ecosystem == "pypi" and base.endswith((".js", ".mjs", ".cjs"))) or (
                ctx.ecosystem == "npm" and base.endswith(".py")
            )
            if foreign and not f.install_time and f.category not in ("indicator", "binary"):
                f.severity = Severity(max(0, int(f.severity) - 1))
                f.evidence["downgraded"] = "other ecosystem's code"
            # obfuscated code that runs during installation is rarely legitimate
            if f.category == "obfuscation" and ctx.is_install_time(base) and f.severity >= Severity.MEDIUM:
                f.severity = Severity(min(int(f.severity) + 1, int(Severity.CRITICAL)))
                f.install_time = True
            if ctx.is_low_trust_path(base) and not f.install_time and f.category not in ("typosquat", "metadata", "binary"):
                # Code under tests/, docs/, examples/, scripts/ is not executed by installing or importing the package.
                f.severity = Severity(max(0, int(f.severity) - 2))
                f.confidence = round(f.confidence * 0.5, 2)
                f.evidence["downgraded"] = "test/example/doc/tooling path"
            out.append(f)
        return out

    @staticmethod
    def _inline_suppressed(f: Finding, ctx: ScanContext) -> bool:
        # Inline comments are only trusted in the user's own source tree. A downloaded artifact could
        # otherwise silence its own findings, so for archives/registry packages they are ignored.
        if not f.file or not f.line or not ctx.package.source or not Path(ctx.package.source).is_dir():
            return False
        pf = ctx.contents.get(f.file)
        if pf is None:
            return False
        text = pf.text() or ""
        lines = text.splitlines()
        if not 1 <= f.line <= len(lines):
            return False
        m = SUPPRESS.search(lines[f.line - 1])
        if not m:
            return False
        rules = m.group(1)
        return rules is None or any(r.strip() in (f.rule_id, "*") for r in rules.split(","))

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        seen: dict[tuple, Finding] = {}
        for f in findings:
            k = (f.rule_id, f.file, f.line)
            if k not in seen or f.severity > seen[k].severity:
                seen[k] = f
        return list(seen.values())


def exit_code(results: list[ScanResult], fail_on: Severity) -> int:
    for r in results:
        if r.verdict == "allowed":
            continue
        if any(f.severity >= fail_on for f in r.findings):
            return 1
    return 0


__all__ = ["Scanner", "exit_code", "Ecosystem"]
