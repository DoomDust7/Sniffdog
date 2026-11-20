from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..archive import PackageContents, PackageFile
from ..models import Ecosystem, Finding, PackageInfo

NPM_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish")

# Paths where findings are much less likely to be real attacks.
_LOW_TRUST_DIRS = re.compile(
    r"(^|/)(tests?|testing|testdata|examples?|docs?(_src)?|documentation|benchmarks?|__tests__|spec|fixtures?|scripts?|tools?"
    r"|MetaTools|devtools|ci|\.github|third_party|samples?|demos?|_static|bench|unittests?|testsuite|extern|vendored[-_][\w-]+)(/|$)|(^|/)test_[^/]*\.py$|_test\.py$|\.test\.[jt]s$",
    re.I,
)


# Bounded quantifiers: an unbounded `[\w./-]+` backtracks quadratically on long minified/base64 runs.
_DOTTED_MOD = re.compile(r"""['"}]((?:\.?[A-Za-z_][\w-]{0,60})(?:\.[A-Za-z_]\w{0,60}){1,6})['"]""")
_FILE_REF = re.compile(r"(?<![\w./-])[\w./-]{1,200}\.(?:c|m)?js\b|(?<![\w./-])[\w./-]{1,200}\.(?:py|sh)\b")


@dataclass
class ScanContext:
    contents: PackageContents
    package: PackageInfo
    ecosystem: str
    install_time_files: set[str] = field(default_factory=set)
    import_time_files: set[str] = field(default_factory=set)
    script_entry_files: set[str] = field(default_factory=set)  # launched as programs by install-time code
    package_json: dict[str, Any] | None = None
    package_json_path: str | None = None

    @classmethod
    def build(cls, contents: PackageContents, package: PackageInfo) -> ScanContext:
        ctx = cls(contents, package, package.ecosystem)
        ctx._detect_ecosystem()
        ctx._compute_entry_points()
        return ctx

    def _detect_ecosystem(self) -> None:
        pj = self.contents.find("package.json")
        root_pj = pj[0] if pj else None
        if root_pj is not None:
            try:
                self.package_json = json.loads(root_pj.data.decode("utf-8", "replace"))
                self.package_json_path = root_pj.path
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.package_json = None
        if self.ecosystem in (Ecosystem.UNKNOWN, None, ""):
            has_py = any(self.contents.find(n) for n in ("setup.py", "pyproject.toml", "PKG-INFO", "setup.cfg")) or any(
                f.path.endswith(".dist-info/METADATA") for f in self.contents
            )
            if self.package_json is not None and not has_py:
                self.ecosystem = Ecosystem.NPM
            elif has_py:
                self.ecosystem = Ecosystem.PYPI
            elif any(f.suffix == ".py" for f in self.contents):
                self.ecosystem = Ecosystem.PYPI
            elif any(f.suffix in (".js", ".mjs", ".cjs") for f in self.contents):
                self.ecosystem = Ecosystem.NPM
            self.package.ecosystem = self.ecosystem

    def _compute_entry_points(self) -> None:
        # Python: setup.py runs on every sdist install; .pth files run on every interpreter start.
        for f in self.contents:
            if f.name == "setup.py" and f.path.count("/") <= 1:
                self.install_time_files.add(f.path)
            if f.suffix == ".pth":
                self.install_time_files.add(f.path)
            if f.name == "__init__.py" and f.path.count("/") <= 2:
                self.import_time_files.add(f.path)
        # npm: files referenced by lifecycle scripts run during `npm install`.
        if self.package_json and isinstance(self.package_json.get("scripts"), dict):
            base = posixpath.dirname(self.package_json_path or "")
            for hook in NPM_LIFECYCLE:
                cmd = self.package_json["scripts"].get(hook)
                if not isinstance(cmd, str):
                    continue
                for token in re.findall(r"[\w./@-]+\.(?:c|m)?js\b", cmd):
                    path = posixpath.normpath(posixpath.join(base, token)).lstrip("./")
                    if path in self.contents.files:
                        self.install_time_files.add(path)
            main = self.package_json.get("main")
            if isinstance(main, str):
                path = posixpath.normpath(posixpath.join(base, main)).lstrip("./")
                for cand in (path, path + ".js", posixpath.join(path, "index.js")):
                    if cand in self.contents.files:
                        self.import_time_files.add(cand)
                        break
            elif "index.js" in self.contents.files:
                self.import_time_files.add("index.js")
        self._expand_install_time()

    def _expand_install_time(self, max_rounds: int = 3) -> None:
        """Files launched *by* install-time scripts run at install time too.

        e.g. Shai-Hulud 2.0: `preinstall: node setup_bun.js`, which spawns `bun bun_environment.js`.
        """
        py_files = [f.path for f in self.contents if f.suffix == ".py"]
        by_name: dict[str, list[str]] = {}
        for f in self.contents:
            if f.suffix in (".js", ".cjs", ".mjs", ".py", ".sh"):
                by_name.setdefault(f.name, []).append(f.path)
        for _ in range(max_rounds):
            added = set()
            for path in list(self.install_time_files):
                pf = self.contents.get(path)
                text = pf.text() if pf else None
                if not text:
                    continue
                for ref in set(_FILE_REF.findall(text[:500_000])):
                    for cand in by_name.get(posixpath.basename(ref), []):
                        if cand not in self.install_time_files:
                            added.add(cand)
                if path.endswith(".py"):  # `python -m pkg.utils.analyzer`, importlib.import_module("pkg.x")
                    for mod in set(_DOTTED_MOD.findall(text[:500_000])):
                        tail = mod.strip(".").replace(".", "/")
                        for suffix in (tail + ".py", tail + "/__init__.py"):
                            for cand in py_files:
                                if (cand == suffix or cand.endswith("/" + suffix)) and cand not in self.install_time_files:
                                    added.add(cand)
            if not added:
                break
            self.install_time_files |= added
            self.script_entry_files |= {a for a in added if a.endswith(".py")}

    def is_install_time(self, path: str | None) -> bool:
        return path in self.install_time_files

    def is_low_trust_path(self, path: str | None) -> bool:
        return bool(path and _LOW_TRUST_DIRS.search(path))


class Analyzer(Protocol):
    name: str

    def analyze(self, ctx: ScanContext) -> list[Finding]: ...


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def snippet_at(text: str, line: int, width: int = 160) -> str:
    lines = text.splitlines()
    if 1 <= line <= len(lines):
        s = lines[line - 1].strip()
        return s if len(s) <= width else s[: width - 1] + "…"
    return ""


def iter_text_files(ctx: ScanContext, suffixes: tuple[str, ...] | None = None):
    for f in ctx.contents:
        if suffixes and f.suffix not in suffixes:
            continue
        t = f.text()
        if t is not None:
            yield f, t


__all__ = ["ScanContext", "Analyzer", "PackageFile", "line_of", "snippet_at", "iter_text_files"]
