"""Read package artifacts *without ever extracting them to disk*.

Malicious archives are an attack surface of their own: path traversal
(``../../.bashrc``), symlinks pointing outside the tree, decompression bombs,
and millions of tiny members. Every member is read into memory under hard
limits, so the scanner never writes attacker-controlled paths anywhere.
"""

from __future__ import annotations

import io
import os
import posixpath
import tarfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

MAX_FILE_BYTES = 8 * 1024 * 1024  # analyse at most 8 MiB of any single file
MAX_TOTAL_BYTES = 256 * 1024 * 1024  # stop after 256 MiB of decompressed content
MAX_MEMBERS = 25_000
HEAD_BYTES = 64  # always keep the head of oversized files for magic-number checks

ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar", ".zip", ".whl", ".egg")


class ArchiveError(Exception):
    pass


@dataclass
class PackageFile:
    path: str  # normalised, relative, forward slashes, top-level wrapper dir removed
    data: bytes
    size: int  # real size (data may be truncated)
    truncated: bool = False
    executable_bit: bool = False

    @property
    def name(self) -> str:
        return posixpath.basename(self.path)

    @property
    def suffix(self) -> str:
        return posixpath.splitext(self.path)[1].lower()

    def text(self) -> str | None:
        """Decode as text, or None if it looks binary."""
        if b"\x00" in self.data[:8192]:
            return None
        try:
            return self.data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return self.data.decode("latin-1")
            except UnicodeDecodeError:  # pragma: no cover - latin-1 never fails
                return None


@dataclass
class Anomaly:
    path: str
    kind: str
    detail: str


class PackageContents:
    """An in-memory view of a package's files plus anomalies seen while reading."""

    def __init__(self) -> None:
        self.files: dict[str, PackageFile] = {}
        self.anomalies: list[Anomaly] = []
        self.total_bytes = 0
        self.limit_hit = False

    def add(self, f: PackageFile) -> None:
        self.files[f.path] = f
        self.total_bytes += len(f.data)

    def get(self, path: str) -> PackageFile | None:
        return self.files.get(path)

    def find(self, name: str) -> list[PackageFile]:
        """All files with this basename, shallowest first."""
        hits = [f for f in self.files.values() if f.name == name]
        return sorted(hits, key=lambda f: (f.path.count("/"), f.path))

    def __iter__(self) -> Iterator[PackageFile]:
        return iter(self.files.values())

    def __len__(self) -> int:
        return len(self.files)


def _normalise(name: str) -> tuple[str | None, str | None]:
    """Return (safe_relative_path, anomaly_reason)."""
    raw = name.replace("\\", "/")
    reason = None
    if raw.startswith("/") or (len(raw) > 1 and raw[1] == ":"):
        reason = "absolute path"
    parts = [p for p in raw.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        reason = "path traversal"
        parts = [p for p in parts if p != ".."]
    if not parts:
        return None, reason
    return "/".join(parts), reason


def _strip_wrapper(paths: list[str]) -> str:
    """sdists wrap content in ``name-1.0/`` and npm tarballs in ``package/``."""
    tops = {p.split("/", 1)[0] for p in paths}
    if len(tops) == 1 and all("/" in p for p in paths):
        return tops.pop() + "/"
    return ""


def is_archive(path: str | os.PathLike[str]) -> bool:
    return str(path).lower().endswith(ARCHIVE_SUFFIXES)


def load(path: str | os.PathLike[str]) -> PackageContents:
    p = Path(path)
    if p.is_dir():
        return _load_dir(p)
    lower = p.name.lower()
    if lower.endswith((".zip", ".whl", ".egg")):
        return _load_zip(p.read_bytes())
    if lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        return _load_tar(p.read_bytes())
    if p.is_file():  # single file scan
        c = PackageContents()
        data = p.read_bytes()
        c.add(PackageFile(p.name, data[:MAX_FILE_BYTES], len(data), len(data) > MAX_FILE_BYTES))
        return c
    raise ArchiveError(f"Unsupported artifact: {path}")


def load_bytes(data: bytes, filename: str) -> PackageContents:
    lower = filename.lower()
    if lower.endswith((".zip", ".whl", ".egg")):
        return _load_zip(data)
    if lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        return _load_tar(data)
    raise ArchiveError(f"Unsupported artifact type: {filename}")


def _budget(c: PackageContents, size: int) -> int:
    """How many bytes of the next member we are still allowed to read."""
    remaining = MAX_TOTAL_BYTES - c.total_bytes
    if remaining <= 0:
        c.limit_hit = True
        return 0
    return min(size, MAX_FILE_BYTES, remaining)


def _load_dir(root: Path) -> PackageContents:
    c = PackageContents()
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache"}
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in filenames:
            count += 1
            if count > MAX_MEMBERS:
                c.limit_hit = True
                return c
            full = Path(dirpath) / fn
            rel = full.relative_to(root).as_posix()
            if full.is_symlink():
                c.anomalies.append(Anomaly(rel, "symlink", f"-> {os.readlink(full)}"))
                continue
            try:
                size = full.stat().st_size
                n = _budget(c, size)
                with open(full, "rb") as fh:
                    data = fh.read(max(n, HEAD_BYTES))
                exe = bool(full.stat().st_mode & 0o111)
            except OSError:
                continue
            c.add(PackageFile(rel, data, size, size > len(data), exe))
    return c


def _load_tar(blob: bytes) -> PackageContents:
    c = PackageContents()
    try:
        tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
    except tarfile.TarError as e:
        raise ArchiveError(f"Corrupt tar archive: {e}") from e
    with tf:
        members = []
        for i, m in enumerate(tf):
            if i >= MAX_MEMBERS:
                c.limit_hit = True
                break
            members.append(m)
        prefix = _strip_wrapper([m.name.replace("\\", "/").lstrip("./") for m in members if m.isfile()])
        for m in members:
            rel, reason = _normalise(m.name)
            if rel is None:
                continue
            if prefix and rel.startswith(prefix):
                rel = rel[len(prefix) :]
            if reason:
                c.anomalies.append(Anomaly(rel, reason, m.name))
            if m.issym() or m.islnk():
                target = m.linkname
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(rel), target))
                if target.startswith("/") or resolved == ".." or resolved.startswith("../"):
                    c.anomalies.append(Anomaly(rel, "link escapes package", f"-> {target}"))
                continue
            if not m.isfile():
                if m.ischr() or m.isblk() or m.isfifo():
                    c.anomalies.append(Anomaly(rel, "device file", m.name))
                continue
            n = _budget(c, m.size)
            fh = tf.extractfile(m)
            if fh is None:
                continue
            data = fh.read(max(n, HEAD_BYTES))
            c.add(PackageFile(rel, data, m.size, m.size > len(data), bool(m.mode & 0o111)))
    return c


def _load_zip(blob: bytes) -> PackageContents:
    c = PackageContents()
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as e:
        raise ArchiveError(f"Corrupt zip archive: {e}") from e
    with zf:
        infos = [i for i in zf.infolist() if not i.is_dir()][:MAX_MEMBERS]
        if len(zf.infolist()) > MAX_MEMBERS:
            c.limit_hit = True
        prefix = _strip_wrapper([i.filename.replace("\\", "/") for i in infos])
        for info in infos:
            rel, reason = _normalise(info.filename)
            if rel is None:
                continue
            if prefix and rel.startswith(prefix):
                rel = rel[len(prefix) :]
            if reason:
                c.anomalies.append(Anomaly(rel, reason, info.filename))
            # Compression-ratio bomb guard.
            if info.compress_size and info.file_size / max(info.compress_size, 1) > 200 and info.file_size > 50 * 1024 * 1024:
                c.anomalies.append(Anomaly(rel, "decompression bomb", f"ratio {info.file_size // info.compress_size}:1"))
                continue
            n = _budget(c, info.file_size)
            try:
                with zf.open(info) as fh:
                    data = fh.read(max(n, HEAD_BYTES))
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as e:
                c.anomalies.append(Anomaly(rel, "unreadable member", str(e)))
                continue
            mode = (info.external_attr >> 16) & 0o777
            c.add(PackageFile(rel, data, info.file_size, info.file_size > len(data), bool(mode & 0o111)))
    return c
