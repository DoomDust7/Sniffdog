"""User configuration: ``sniffdog.toml`` or ``[tool.sniffdog]`` in ``pyproject.toml``."""

from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding, Severity


@dataclass
class Config:
    fail_on: Severity = Severity.HIGH
    min_severity: Severity = Severity.LOW
    ignore_rules: list[str] = field(default_factory=list)
    ignore_paths: list[str] = field(default_factory=list)
    allow_packages: list[str] = field(default_factory=list)
    internal_prefixes: list[str] = field(default_factory=list)
    artifact: str = "sdist"  # sdist | wheel | all
    metadata: bool = True
    source: str | None = None

    def ignores(self, f: Finding) -> bool:
        if any(fnmatch.fnmatch(f.rule_id, pat) for pat in self.ignore_rules):
            return True
        if f.file and any(fnmatch.fnmatch(f.file, pat) for pat in self.ignore_paths):
            return True
        return False

    def allowed(self, name: str) -> bool:
        return any(fnmatch.fnmatch(name.lower(), p.lower()) for p in self.allow_packages)

    @classmethod
    def from_dict(cls, d: dict, source: str | None = None) -> Config:
        c = cls(source=source)
        for k, v in d.items():
            k = k.replace("-", "_")
            if k in ("fail_on", "min_severity"):
                setattr(c, k, Severity.parse(v))
            elif hasattr(c, k) and k != "source":
                setattr(c, k, v)
            else:
                raise ValueError(f"Unknown sniffdog config key: {k!r}")
        if c.artifact not in ("sdist", "wheel", "all"):
            raise ValueError("artifact must be one of sdist, wheel, all")
        return c


def load_config(explicit: str | None = None, start: Path | None = None) -> Config:
    if explicit:
        p = Path(explicit)
        data = tomllib.loads(p.read_text())
        return Config.from_dict(data.get("tool", {}).get("sniffdog", data), str(p))
    d = (start or Path.cwd()).resolve()
    for folder in [d, *d.parents]:
        f = folder / "sniffdog.toml"
        if f.is_file():
            return Config.from_dict(tomllib.loads(f.read_text()), str(f))
        f = folder / "pyproject.toml"
        if f.is_file():
            try:
                data = tomllib.loads(f.read_text())
            except tomllib.TOMLDecodeError:
                continue
            if "sniffdog" in data.get("tool", {}):
                return Config.from_dict(data["tool"]["sniffdog"], str(f))
        if (folder / ".git").exists():
            break
    return Config()
