"""Audit a project's dependency manifest / lockfile.

Fast mode (default) needs no downloads beyond optional registry lookups:
typosquat checks on every name, plus dependency-confusion checks for names that
match the organisation's internal prefixes. ``--deep`` downloads and fully
scans every pinned dependency in parallel.
"""

from __future__ import annotations

import json
import re
import tomllib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from .analyzers.typosquat import check_name, normalize
from .config import Config
from .models import Category, Ecosystem, Finding, PackageInfo, ScanResult, Severity
from .registry import RegistryError, Spec, npm_exists, pypi_exists
from .scanner import Scanner
from .scoring import score, verdict


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str | None
    source: str  # file it came from
    direct: bool = True

    def spec(self) -> Spec:
        return Spec(self.ecosystem, self.name, self.version)


# --------------------------------------------------------------------------- parsers


def parse_requirements(path: Path, _seen: set[Path] | None = None) -> list[Dependency]:
    seen = _seen or set()
    if path.resolve() in seen:
        return []
    seen.add(path.resolve())
    deps = []
    for raw in path.read_text().splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ")):
            inc = path.parent / line.split(None, 1)[1].strip()
            if inc.exists():
                deps += parse_requirements(inc, seen)
            continue
        if line.startswith("-") or "://" in line or line.startswith((".", "/")):
            continue
        line = line.split(";", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(==|===)?\s*([^\s,;]+)?", line)
        if m:
            deps.append(Dependency(Ecosystem.PYPI, m.group(1), m.group(3) if m.group(2) else None, str(path)))
    return deps


def _pep508_name(req: str) -> tuple[str, str | None] | None:
    m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:==\s*([^\s,;]+))?", req)
    return (m.group(1), m.group(2)) if m else None


def parse_pyproject(path: Path) -> list[Dependency]:
    data = tomllib.loads(path.read_text())
    deps = []
    proj = data.get("project", {})
    reqs = list(proj.get("dependencies", []))
    for extra in proj.get("optional-dependencies", {}).values():
        reqs += extra
    for group in data.get("dependency-groups", {}).values():
        reqs += [g for g in group if isinstance(g, str)]
    for r in reqs:
        nv = _pep508_name(r)
        if nv:
            deps.append(Dependency(Ecosystem.PYPI, nv[0], nv[1], str(path)))
    poetry = data.get("tool", {}).get("poetry", {})
    for section in [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})] + [
        g.get("dependencies", {}) for g in poetry.get("group", {}).values()
    ]:
        for name, spec in section.items():
            if name.lower() == "python":
                continue
            ver = spec if isinstance(spec, str) else spec.get("version") if isinstance(spec, dict) else None
            exact = ver if ver and re.fullmatch(r"\d[\w.]*", ver) else None
            deps.append(Dependency(Ecosystem.PYPI, name, exact, str(path)))
    return deps


def parse_toml_lock(path: Path) -> list[Dependency]:  # poetry.lock, uv.lock, pdm.lock
    data = tomllib.loads(path.read_text())
    out = []
    for p in data.get("package", []):
        src = p.get("source")
        if isinstance(src, dict) and ("editable" in src or "virtual" in src or "directory" in src):
            continue
        if p.get("name") and p.get("version"):
            out.append(Dependency(Ecosystem.PYPI, p["name"], p["version"], str(path), direct=False))
    return out


def parse_pipfile_lock(path: Path) -> list[Dependency]:
    data = json.loads(path.read_text())
    out = []
    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            v = (info.get("version") or "").lstrip("=") or None
            out.append(Dependency(Ecosystem.PYPI, name, v, str(path)))
    return out


def parse_package_json(path: Path) -> list[Dependency]:
    data = json.loads(path.read_text())
    out = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, rng in (data.get(section) or {}).items():
            if not isinstance(rng, str) or re.match(r"^(file:|link:|workspace:|git|https?:|github:)", rng):
                continue
            if rng.startswith("npm:"):  # alias: "foo": "npm:real-pkg@^1.2"
                body = rng[4:]
                at = body.rfind("@")
                real, ver = (body[:at], body[at + 1 :]) if at > 0 else (body, None)
                out.append(Dependency(Ecosystem.NPM, real, ver or None, str(path)))
            else:
                out.append(Dependency(Ecosystem.NPM, name, rng, str(path)))
    return out


def parse_package_lock(path: Path) -> list[Dependency]:
    data = json.loads(path.read_text())
    out = []
    if "packages" in data:
        for key, info in data["packages"].items():
            if not key or info.get("link") or "node_modules/" not in key:
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
            if info.get("version"):
                out.append(Dependency(Ecosystem.NPM, name, info["version"], str(path), direct=key.count("node_modules/") == 1))
    else:

        def walk(deps: dict, direct: bool):
            for name, info in deps.items():
                if info.get("version"):
                    out.append(Dependency(Ecosystem.NPM, name, info["version"], str(path), direct))
                walk(info.get("dependencies", {}), False)

        walk(data.get("dependencies", {}), True)
    return out


def parse_yarn_lock(path: Path) -> list[Dependency]:
    out = []
    current: list[str] = []
    for line in path.read_text().splitlines():
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            current = []
            for entry in line.rstrip(":").split(","):
                entry = entry.strip().strip('"')
                name = entry.rsplit("@", 1)[0] if entry.count("@") > (1 if entry.startswith("@") else 0) else entry
                current.append(name)
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
        if m and current:
            for n in dict.fromkeys(current):
                out.append(Dependency(Ecosystem.NPM, n, m.group(1), str(path), direct=False))
            current = []
    return out


PARSERS = {
    "requirements.txt": parse_requirements,
    "pyproject.toml": parse_pyproject,
    "poetry.lock": parse_toml_lock,
    "uv.lock": parse_toml_lock,
    "pdm.lock": parse_toml_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
}


def parse_manifest(path: Path) -> list[Dependency]:
    name = path.name
    if name in PARSERS:
        parser = PARSERS[name]
    elif re.match(r".*requirements.*\.(txt|in)$", name):
        parser = parse_requirements
    else:
        raise ValueError(f"Don't know how to read {name}. Supported: {', '.join(PARSERS)} and *requirements*.txt")
    deps = parser(path)
    uniq: dict[tuple[str, str, str | None], Dependency] = {}
    for d in deps:
        uniq.setdefault((d.ecosystem, normalize(d.name, d.ecosystem), d.version), d)
    return list(uniq.values())


def discover(root: Path) -> list[Path]:
    """Find manifests in a project directory, preferring lockfiles over loose manifests."""
    found = []
    for name in ("poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock"):
        if (root / name).exists():
            found.append(root / name)
    has_py_lock = any(p.name in ("poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock") for p in found)
    has_js_lock = any(p.name in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock") for p in found)
    if not has_py_lock:
        found += sorted(root.glob("*requirements*.txt"))
        if not any(p.name.endswith(".txt") for p in found) and (root / "pyproject.toml").exists():
            found.append(root / "pyproject.toml")
    if not has_js_lock and (root / "package.json").exists():
        found.append(root / "package.json")
    return found


# --------------------------------------------------------------------------- audit


def _quick_findings(dep: Dependency, config: Config, check_registry: bool) -> list[Finding]:
    out = []
    m = check_name(dep.name, dep.ecosystem)
    if m:
        out.append(
            Finding(
                "TYPOSQUAT",
                "Possible typosquat",
                Severity.HIGH if m.rank <= 200 else Severity.MEDIUM,
                Category.TYPOSQUAT,
                f"`{dep.name}` resembles `{m.target}` (#{m.rank} on {dep.ecosystem}) via {m.technique}",
                file=dep.source,
                confidence=0.65,
                evidence={"target": m.target, "technique": m.technique},
            )
        )
    if any(normalize(dep.name, dep.ecosystem).startswith(normalize(p, dep.ecosystem)) for p in config.internal_prefixes) and check_registry:
        try:
            public = npm_exists(dep.name) if dep.ecosystem == Ecosystem.NPM else pypi_exists(dep.name)
        except RegistryError:
            public = False
        if public:
            out.append(
                Finding(
                    "DEP-CONFUSION",
                    "Dependency confusion",
                    Severity.CRITICAL,
                    Category.DEPENDENCY_CONFUSION,
                    f"internal package `{dep.name}` also exists on the public {dep.ecosystem} registry; "
                    "a resolver with both indexes configured may install the public one",
                    file=dep.source,
                    confidence=0.8,
                )
            )
    return out


def audit(
    manifests: list[Path], config: Config, *, deep: bool = False, workers: int = 8, check_registry: bool = True, progress=None
) -> list[ScanResult]:
    deps: list[Dependency] = []
    for m in manifests:
        deps += parse_manifest(m)
    results: dict[Dependency, ScanResult] = {}
    for d in deps:
        if config.allowed(d.name):
            continue
        fs = _quick_findings(d, config, check_registry)
        r = ScanResult(PackageInfo(d.name, d.version, d.ecosystem, source=d.source), fs)
        results[d] = r
    if deep:
        scanner = Scanner(config)
        todo = [d for d in results]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(scanner.scan_spec, d.spec()): d for d in todo}
            for fut in as_completed(futs):
                d = futs[fut]
                try:
                    scans = fut.result()
                    merged = results[d]
                    for s in scans:
                        merged.findings += [f for f in s.findings if f.rule_id != "TYPOSQUAT" or not merged.findings]
                        merged.package.version = s.package.version
                        merged.package.metadata = s.package.metadata
                        merged.files_scanned += s.files_scanned
                        merged.bytes_scanned += s.bytes_scanned
                        merged.errors += s.errors
                except Exception as e:  # noqa: BLE001
                    results[d].errors.append(f"{type(e).__name__}: {e}")
                if progress:
                    progress(d)
    out = []
    for r in results.values():
        r.findings = [f for f in r.findings if f.severity >= config.min_severity]
        r.score = score(r.findings)
        r.verdict = verdict(r.findings, r.score)
        out.append(r)
    return sorted(out, key=lambda r: (-r.score, r.package.name))
