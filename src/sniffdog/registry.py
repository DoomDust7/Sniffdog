"""Resolve package specs, download artifacts from PyPI / npm and verify their integrity."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .models import Ecosystem

PYPI = os.environ.get("SNIFFDOG_PYPI_URL", "https://pypi.org")
NPM = os.environ.get("SNIFFDOG_NPM_URL", "https://registry.npmjs.org")
UA = f"sniffdog/{__version__} (+https://github.com/DoomDust7/Sniffdog)"
MAX_DOWNLOAD = 200 * 1024 * 1024


class RegistryError(Exception):
    pass


@dataclass
class Spec:
    ecosystem: str
    name: str
    version: str | None = None  # exact version, range, or None for latest

    def __str__(self) -> str:
        sep = "==" if self.ecosystem == Ecosystem.PYPI else "@"
        return f"{self.ecosystem}:{self.name}{sep + self.version if self.version else ''}"


@dataclass
class Artifact:
    spec: Spec
    version: str
    filename: str
    url: str
    data: bytes
    sha256: str
    metadata: dict[str, Any] = field(default_factory=dict)


def parse_spec(raw: str, default_ecosystem: str | None = None) -> Spec:
    """Accepts ``pypi:requests==2.32.3``, ``npm:lodash@4.17.21``, ``requests``, ``@scope/pkg@1.0``."""
    s = raw.strip()
    eco = default_ecosystem
    m = re.match(r"^(pypi|pip|npm|py)[:/](.+)$", s, re.I)
    if m:
        eco = Ecosystem.NPM if m.group(1).lower() == "npm" else Ecosystem.PYPI
        s = m.group(2)
    if eco is None:
        eco = Ecosystem.NPM if (s.startswith("@") or re.search(r"[^@]@[\w^~*.<>=-]+$", s)) else Ecosystem.PYPI
    if eco == Ecosystem.PYPI:
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:===?\s*([^\s;,]+))?", s)
        if not m:
            raise RegistryError(f"Not a valid PyPI requirement: {raw!r}")
        return Spec(eco, m.group(1), m.group(2))
    m = re.match(r"^(@?[^@\s]+)(?:@(.+))?$", s)
    if not m:
        raise RegistryError(f"Not a valid npm spec: {raw!r}")
    return Spec(eco, m.group(1), m.group(2))


def _ssl_context():
    import ssl

    cafile = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    return ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()


def _get(url: str, *, accept: str = "application/json", limit: int = MAX_DOWNLOAD, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as r:
            data = r.read(limit + 1)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise RegistryError(f"Not found: {url}") from e
        raise RegistryError(f"HTTP {e.code} for {url}") from e
    except urllib.error.URLError as e:
        raise RegistryError(f"Network error for {url}: {e.reason}") from e
    if len(data) > limit:
        raise RegistryError(f"Artifact larger than {limit // (1024 * 1024)} MiB: {url}")
    return data


def _get_json(url: str) -> dict[str, Any]:
    return json.loads(_get(url, limit=64 * 1024 * 1024))


def cache_dir() -> Path:
    base = os.environ.get("SNIFFDOG_CACHE") or os.path.join(os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")), "sniffdog")
    p = Path(base)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _download_verified(
    url: str, *, sha256: str | None = None, integrity: str | None = None, shasum: str | None = None, use_cache: bool = True
) -> bytes:
    key = hashlib.sha256(url.encode()).hexdigest()[:32]
    cached = cache_dir() / key if use_cache else None
    if cached and cached.exists():
        data = cached.read_bytes()
        try:
            _verify(data, url, sha256, integrity, shasum)
            return data
        except RegistryError:
            cached.unlink(missing_ok=True)
    data = _get(url, accept="*/*")
    _verify(data, url, sha256, integrity, shasum)
    if cached:
        tmp = cached.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(cached)
    return data


def _verify(data: bytes, url: str, sha256: str | None, integrity: str | None, shasum: str | None) -> None:
    if sha256 and hashlib.sha256(data).hexdigest() != sha256.lower():
        raise RegistryError(f"SHA-256 mismatch for {url}: refusing to analyse a tampered artifact")
    if integrity:
        algo, _, b64 = integrity.partition("-")
        if algo in ("sha512", "sha384", "sha256") and base64.b64encode(hashlib.new(algo, data).digest()).decode() != b64:
            raise RegistryError(f"Subresource integrity mismatch for {url}")
    elif shasum and hashlib.sha1(data).hexdigest() != shasum:
        raise RegistryError(f"SHA-1 mismatch for {url}")


# --------------------------------------------------------------------------- PyPI


def pypi_project(name: str) -> dict[str, Any]:
    return _get_json(f"{PYPI}/pypi/{urllib.parse.quote(name)}/json")


def pypi_exists(name: str) -> bool:
    try:
        pypi_project(name)
        return True
    except RegistryError as e:
        if "Not found" in str(e):
            return False
        raise


def _pick_pypi_files(files: list[dict[str, Any]], mode: str) -> list[dict[str, Any]]:
    sdists = [f for f in files if f.get("packagetype") == "sdist"]
    wheels = [f for f in files if f.get("packagetype") == "bdist_wheel"]
    pure = [w for w in wheels if w["filename"].endswith("-none-any.whl")]
    linux = [w for w in wheels if "manylinux" in w["filename"] and "x86_64" in w["filename"]]
    if mode == "all":
        return sdists[:1] + (pure or linux or wheels)[:1]
    if mode == "wheel":
        return (pure or linux or wheels)[:1] or sdists[:1]
    return sdists[:1] or (pure or linux or wheels)[:1]


def fetch_pypi(spec: Spec, artifact: str = "sdist") -> list[Artifact]:
    proj = pypi_project(spec.name)
    version = spec.version or proj["info"]["version"]
    releases = proj.get("releases", {})
    if version not in releases:
        raise RegistryError(f"{spec.name} has no release {version!r} on PyPI")
    files = [f for f in releases[version] if not f.get("yanked")] or releases[version]
    chosen = _pick_pypi_files(files, artifact)
    if not chosen:
        raise RegistryError(f"{spec.name}=={version} has no downloadable files")
    meta = pypi_metadata(proj, version)
    out = []
    for f in chosen:
        data = _download_verified(f["url"], sha256=f.get("digests", {}).get("sha256"))
        out.append(Artifact(spec, version, f["filename"], f["url"], data, hashlib.sha256(data).hexdigest(), meta))
    return out


def pypi_metadata(proj: dict[str, Any], version: str) -> dict[str, Any]:
    info = proj.get("info", {})
    uploads = []
    for v, files in proj.get("releases", {}).items():
        for f in files:
            if f.get("upload_time_iso_8601"):
                uploads.append((f["upload_time_iso_8601"], v))
    uploads.sort()
    urls = info.get("project_urls") or {}
    return {
        "registry": "pypi",
        "summary": info.get("summary"),
        "author": info.get("author") or info.get("author_email"),
        "home_page": info.get("home_page") or next(iter(urls.values()), None),
        "repository": next((u for u in urls.values() if u and re.search(r"github|gitlab|bitbucket|codeberg", u, re.I)), None),
        "first_release": uploads[0][0] if uploads else None,
        "release_count": len(proj.get("releases", {})),
        "this_release": next((t for t, v in uploads if v == version), None),
        "license": info.get("license_expression") or info.get("license"),
    }


# --------------------------------------------------------------------------- npm


def npm_packument(name: str) -> dict[str, Any]:
    quoted = name.replace("/", "%2f") if name.startswith("@") else urllib.parse.quote(name)
    return _get_json(f"{NPM}/{quoted}")


def npm_exists(name: str) -> bool:
    try:
        npm_packument(name)
        return True
    except RegistryError as e:
        if "Not found" in str(e):
            return False
        raise


def _semver_key(v: str) -> tuple:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-([\w.]+))?", v)
    if not m:
        return (-1,)
    pre = m.group(4)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if pre else 1, pre or "")


def resolve_npm_version(packument: dict[str, Any], rng: str | None) -> str:
    versions = list(packument.get("versions", {}))
    tags = packument.get("dist-tags", {})
    if not rng or rng in ("latest", "*", "x", ""):
        return tags.get("latest") or max(versions, key=_semver_key)
    if rng in tags:
        return tags[rng]
    if rng in versions:
        return rng
    m = re.match(r"^([\^~]|>=)?\s*v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?", rng)
    if not m:
        raise RegistryError(f"Unsupported version range {rng!r}")
    op, major = m.group(1) or "", int(m.group(2))
    minor = None if m.group(3) in (None, "x", "*") else int(m.group(3))
    patch = None if m.group(4) in (None, "x", "*") else int(m.group(4))

    def ok(v: str) -> bool:
        k = _semver_key(v)
        if len(k) < 4 or k[3] == 0:  # skip pre-releases
            return False
        if op == ">=":
            return k[:3] >= (major, minor or 0, patch or 0)
        if op == "^":
            if k[0] != major:
                return False
            return k[:3] >= (major, minor or 0, patch or 0) and (major != 0 or minor is None or k[1] == minor)
        if op == "~":
            return k[0] == major and (minor is None or k[1] == minor) and k[2] >= (patch or 0)
        return k[0] == major and (minor is None or k[1] == minor) and (patch is None or k[2] == patch)

    matching = [v for v in versions if ok(v)]
    if not matching:
        raise RegistryError(f"No version of {packument.get('name')} satisfies {rng!r}")
    return max(matching, key=_semver_key)


def fetch_npm(spec: Spec) -> list[Artifact]:
    pk = npm_packument(spec.name)
    version = resolve_npm_version(pk, spec.version)
    vinfo = pk["versions"][version]
    dist = vinfo.get("dist", {})
    url = dist["tarball"]
    data = _download_verified(url, integrity=dist.get("integrity"), shasum=dist.get("shasum"))
    meta = npm_metadata(pk, version)
    return [Artifact(spec, version, url.rsplit("/", 1)[-1], url, data, hashlib.sha256(data).hexdigest(), meta)]


def npm_metadata(pk: dict[str, Any], version: str) -> dict[str, Any]:
    times = pk.get("time", {})
    v = pk.get("versions", {}).get(version, {})
    repo = v.get("repository") or pk.get("repository")
    if isinstance(repo, dict):
        repo = repo.get("url")
    return {
        "registry": "npm",
        "summary": pk.get("description"),
        "author": (v.get("author") or {}).get("name") if isinstance(v.get("author"), dict) else v.get("author"),
        "home_page": v.get("homepage"),
        "repository": repo,
        "first_release": times.get("created"),
        "release_count": len(pk.get("versions", {})),
        "this_release": times.get(version),
        "maintainers": len(pk.get("maintainers") or []),
        "has_install_script": bool(v.get("hasInstallScript")),
        "license": v.get("license") if isinstance(v.get("license"), str) else None,
    }


def fetch(spec: Spec, artifact: str = "sdist") -> list[Artifact]:
    if spec.ecosystem == Ecosystem.NPM:
        return fetch_npm(spec)
    return fetch_pypi(spec, artifact)


def age_days(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return (datetime.now(UTC) - dt).total_seconds() / 86400
