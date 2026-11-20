"""Evaluate Sniffdog on *real* malware and *real* popular packages.

Malicious side: Datadog's open malicious-software-packages-dataset
(https://github.com/DataDog/malicious-software-packages-dataset). Samples are
password-protected zips. They are decrypted **in memory only**, re-packed in
memory and scanned statically. Nothing is extracted to disk and nothing runs.

    git clone --filter=blob:none --sparse https://github.com/DataDog/malicious-software-packages-dataset.git dd
    python bench/realworld_eval.py --dataset dd --per-category 150 --seed 7

Benign side: the top-N most downloaded PyPI and npm packages (latest release),
fetched from the registries with hash verification.

    python bench/realworld_eval.py --benign 300

Results are written to bench/results/*.json and summarised as Markdown.
"""

from __future__ import annotations

import argparse
import io
import json
import random
import signal
import subprocess
import sys
import time
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sniffdog.config import Config  # noqa: E402
from sniffdog.models import Ecosystem, PackageInfo, Severity  # noqa: E402
from sniffdog.scanner import Scanner  # noqa: E402

OUT = Path(__file__).parent / "results"
MARKERS = ("package.json", "setup.py", "pyproject.toml", "PKG-INFO", "setup.cfg")
DETECTED = ("malicious", "suspicious")


def _git_blob(repo: Path, path: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), "show", f"HEAD:{path}"], capture_output=True, check=True).stdout


def _repack(encrypted: bytes) -> bytes:
    """Decrypt a dataset zip in memory and re-root it at the package directory."""
    src = zipfile.ZipFile(io.BytesIO(encrypted))
    infos = [i for i in src.infolist() if not i.is_dir()]
    roots = sorted({i.filename.rsplit("/", 1)[0] for i in infos if i.filename.rsplit("/", 1)[-1] in MARKERS}, key=lambda p: p.count("/"))
    root = roots[0] + "/" if roots else ""
    buf = io.BytesIO()
    total = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst:
        for i in infos:
            if not i.filename.startswith(root) or i.filename.rsplit("/", 1)[-1].startswith("package_info-"):
                continue
            data = src.read(i, pwd=b"infected")
            total += len(data)
            if total > 300 * 1024 * 1024:
                break
            dst.writestr(i.filename[len(root) :], data)
    return buf.getvalue()


SAMPLE_TIMEOUT_S = 120
_REPO: Path | None = None


def _on_timeout(signum, frame):
    raise TimeoutError(f"sample exceeded {SAMPLE_TIMEOUT_S}s")


_SCANNER: Scanner | None = None


def _init_worker(repo: str) -> None:
    global _REPO, _SCANNER
    _REPO = Path(repo)
    _SCANNER = Scanner(Config(metadata=False, min_severity=Severity.LOW))


def _sample_name(dirname: str) -> str:
    # dataset encodes "@scope/name" as "@scope@name"
    if dirname.startswith("@") and "@" in dirname[1:]:
        return "@" + dirname[1:].replace("@", "/", 1)
    return dirname


def _run_malicious(item: tuple[str, str]) -> dict:
    cat, p = item
    parts = p.split("/")
    eco = Ecosystem.PYPI if parts[1] == "pypi" else Ecosystem.NPM
    name = _sample_name(parts[3])
    signal.signal(signal.SIGALRM, _on_timeout)
    signal.alarm(SAMPLE_TIMEOUT_S)
    try:
        data = _repack(_git_blob(_REPO, p))
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        # Some dataset entries are git checkouts of the source repo rather than the published (payload-carrying) artifact.
        snapshot = any(n.startswith(".git/") for n in names)
        r = _SCANNER.scan_bytes(data, "sample.zip", PackageInfo(name, parts[4], eco, source=p))
        top = sorted(r.findings, key=lambda f: -f.severity)[:3]
        return {
            "category": cat,
            "sample": p,
            "name": name,
            "verdict": r.verdict,
            "score": r.score,
            "rules": sorted({f.rule_id for f in r.findings if f.severity >= Severity.MEDIUM}),
            "top": [f"{f.rule_id}: {f.message[:120]}" for f in top],
            "files": r.files_scanned,
            "ms": r.duration_ms,
            "source_snapshot": snapshot,
        }
    except Exception as e:  # noqa: BLE001
        return {"category": cat, "sample": p, "name": name, "error": f"{type(e).__name__}: {e}"}
    finally:
        signal.alarm(0)


def eval_malicious(repo: Path, per_category: int, seed: int, workers: int) -> list[dict]:
    listing = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", "HEAD", "samples/"], capture_output=True, text=True, check=True
    ).stdout.split()
    by_cat: dict[str, list[str]] = defaultdict(list)
    for p in listing:
        parts = p.split("/")
        if len(parts) >= 5 and p.endswith(".zip") and parts[1] in ("pypi", "npm"):
            by_cat[f"{parts[1]}/{parts[2]}"].append(p)
    rng = random.Random(seed)
    chosen: list[tuple[str, str]] = []
    for cat, paths in sorted(by_cat.items()):
        # one version per package name, so a single campaign cannot dominate
        per_pkg: dict[str, str] = {}
        for p in sorted(paths):
            per_pkg.setdefault(p.split("/")[3], p)
        picks = sorted(per_pkg.values())
        rng.shuffle(picks)
        chosen += [(cat, p) for p in picks[:per_category]]
    with ProcessPoolExecutor(workers, initializer=_init_worker, initargs=(str(repo),)) as ex:
        return list(ex.map(_run_malicious, chosen, chunksize=2))


def _init_benign() -> None:
    global _SCANNER
    _SCANNER = Scanner(Config(min_severity=Severity.LOW))


def _run_benign(item: tuple[str, str]) -> dict:
    eco, name = item
    signal.signal(signal.SIGALRM, _on_timeout)
    signal.alarm(SAMPLE_TIMEOUT_S * 2)
    try:
        r = _SCANNER.scan_spec(f"{eco}:{name}")[0]
        return {
            "category": f"{eco}/popular",
            "name": name,
            "version": r.package.version,
            "verdict": r.verdict,
            "score": r.score,
            "rules": sorted({f.rule_id for f in r.findings if f.severity >= Severity.MEDIUM}),
            "top": [f"{f.rule_id}: {f.file}:{f.line} {f.message[:100]}" for f in sorted(r.findings, key=lambda f: -f.severity)[:3]],
            "files": r.files_scanned,
            "ms": r.duration_ms,
        }
    except Exception as e:  # noqa: BLE001
        return {"category": f"{eco}/popular", "name": name, "error": f"{type(e).__name__}: {e}"}
    finally:
        signal.alarm(0)


def eval_benign(n: int, workers: int, offset: int = 0) -> list[dict]:
    """Scan popularity ranks [offset, offset + n) of each ecosystem."""
    data = Path(__file__).resolve().parents[1] / "src" / "sniffdog" / "data"
    items = [(Ecosystem.PYPI, x) for x in (data / "top_pypi.txt").read_text().split()[offset : offset + n]]
    items += [(Ecosystem.NPM, x) for x in (data / "top_npm.txt").read_text().split()[offset : offset + n]]
    with ProcessPoolExecutor(workers, initializer=_init_benign) as ex:
        return list(ex.map(_run_benign, items, chunksize=2))


def summarise(rows: list[dict], positive: bool) -> str:
    lines = []
    cats = sorted({r["category"] for r in rows})
    head = "| Dataset | Scanned | Detected (malicious + suspicious) | Malicious | Suspicious | Low-risk | Clean | Errors |"
    lines += [head, "|---|---|---|---|---|---|---|---|"]
    for cat in cats + ["**all**"]:
        rs = [r for r in rows if cat == "**all**" or r["category"] == cat]
        ok = [r for r in rs if "error" not in r]
        c = Counter(r["verdict"] for r in ok)
        det = c["malicious"] + c["suspicious"]
        rate = det / len(ok) * 100 if ok else 0
        lines.append(
            f"| {cat} | {len(ok)} | {det} ({rate:.1f}%) | {c['malicious']} | {c['suspicious']} | {c['low-risk']} | {c['clean']} | {len(rs) - len(ok)} |"
        )
    snaps = [r for r in rows if r.get("source_snapshot")]
    if positive and snaps:
        real = [r for r in rows if "error" not in r and not r.get("source_snapshot")]
        det = sum(r["verdict"] in DETECTED for r in real)
        lines.append(
            f"\n{len(snaps)} sample(s) are git checkouts of the source repository rather than the published artifact (no payload present). "
            f"Excluding them: **{det}/{len(real)} detected ({det / max(len(real), 1) * 100:.1f}%)**."
        )
    ok = [r for r in rows if "error" not in r]
    if ok:
        ms = sorted(r["ms"] for r in ok)
        lines.append(f"\nMedian scan time {ms[len(ms) // 2]} ms, p95 {ms[int(len(ms) * 0.95)]} ms.")
    rules = Counter(rule for r in ok for rule in r.get("rules", []))
    if rules:
        lines.append("\nMost frequent medium+ rules: " + ", ".join(f"`{k}` ({v})" for k, v in rules.most_common(12)))
    if not positive:
        flagged = [r for r in ok if r["verdict"] in DETECTED]
        if flagged:
            lines.append("\nFalse positives (verdict suspicious or malicious):\n")
            for r in flagged:
                lines.append(f"- `{r['name']}` {r.get('version', '')} — {r['verdict']} ({r['score']}): {'; '.join(r['top'][:2])}")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", type=Path, help="path to a (partial) clone of DataDog/malicious-software-packages-dataset")
    ap.add_argument("--per-category", type=int, default=150)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--benign", type=int, default=0, help="scan the top-N PyPI and top-N npm packages")
    ap.add_argument("--benign-offset", type=int, default=0, help="skip the first K popularity ranks (held-out evaluation)")
    ap.add_argument("--tag", default="", help="suffix for result file names")
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    OUT.mkdir(exist_ok=True)
    if a.dataset:
        t = time.time()
        rows = eval_malicious(a.dataset, a.per_category, a.seed, a.workers)
        (OUT / f"malicious{a.tag}.json").write_text(json.dumps(rows, indent=1))
        md = summarise(rows, positive=True)
        (OUT / f"malicious{a.tag}.md").write_text(md + "\n")
        print(md, f"\n({time.time() - t:.0f}s)")
    if a.benign:
        t = time.time()
        rows = eval_benign(a.benign, a.workers, a.benign_offset)
        (OUT / f"benign{a.tag}.json").write_text(json.dumps(rows, indent=1))
        md = summarise(rows, positive=False)
        (OUT / f"benign{a.tag}.md").write_text(md + "\n")
        print(md, f"\n({time.time() - t:.0f}s)")


if __name__ == "__main__":
    main()
