"""Typosquatting detection against download-ranked package lists.

Bundled data: top 5,000 PyPI projects by 30-day downloads and ~3,000 of the
most-downloaded npm packages. A candidate that *is* itself popular is never
flagged; otherwise we look for the most popular package it imitates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

from ..models import Category, Ecosystem, Finding, Severity
from .base import ScanContext

HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("i", "l"), ("5", "s"), ("3", "e"), ("$", "s"), ("@", "a")]
PREFIXES = ("python-", "py-", "py", "node-", "js-", "the-", "lib")
SUFFIXES = ("-python", "-py", "py", "-js", "js", ".js", "-node", "2", "3", "-lib", "lib", "-dev", "-official", "-sdk")


@dataclass(frozen=True)
class SquatMatch:
    target: str
    technique: str
    rank: int  # 1-based popularity rank of the imitated package
    distance: int = 0


def normalize(name: str, ecosystem: str) -> str:
    name = name.strip().lower()
    if ecosystem == Ecosystem.PYPI:
        return re.sub(r"[-_.]+", "-", name)
    return name


@lru_cache(maxsize=4)
def popular(ecosystem: str) -> tuple[dict[str, int], dict[str, list[str]], dict[int, list[str]]]:
    fname = "top_pypi.txt" if ecosystem == Ecosystem.PYPI else "top_npm.txt"
    text = resources.files("sniffdog.data").joinpath(fname).read_text()
    ranks: dict[str, int] = {}
    for i, line in enumerate(text.split()):
        n = normalize(line, ecosystem)
        ranks.setdefault(n, i + 1)
    by_skeleton: dict[str, list[str]] = {}
    by_len: dict[int, list[str]] = {}
    for n in ranks:
        by_skeleton.setdefault(_skeleton(n), []).append(n)
        by_len.setdefault(len(n), []).append(n)
    return ranks, by_skeleton, by_len


def _skeleton(name: str) -> str:
    s = name.split("/")[-1]
    s = re.sub(r"[-_.]", "", s)
    for a, b in HOMOGLYPHS:
        s = s.replace(a, b)
    return s


def damerau_levenshtein(a: str, b: str, limit: int = 3) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        best = cur[0]
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
            best = min(best, cur[j])
        if best > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def check_name(name: str, ecosystem: str) -> SquatMatch | None:
    if ecosystem not in (Ecosystem.PYPI, Ecosystem.NPM):
        return None
    ranks, by_skel, by_len = popular(ecosystem)
    n = normalize(name, ecosystem)
    if n in ranks or len(n) < 3:
        return None
    candidates: list[SquatMatch] = []

    # npm scope impersonation: @evil/lodash or @types-x/react
    if ecosystem == Ecosystem.NPM and n.startswith("@") and "/" in n:
        scope, bare = n[1:].split("/", 1)
        if bare in ranks and ranks[bare] <= 1000:
            candidates.append(SquatMatch(bare, f"unofficial scope @{scope} on a popular unscoped name", ranks[bare]))
        known_scopes = {p.split("/")[0][1:] for p in ranks if p.startswith("@")}
        for ks in known_scopes:
            if ks != scope and damerau_levenshtein(ks, scope, 1) <= 1 and len(ks) >= 4:
                tgt = next((p for p in ranks if p.startswith(f"@{ks}/") and p.endswith("/" + bare)), f"@{ks}/{bare}")
                candidates.append(SquatMatch(tgt, f"scope @{scope} imitates @{ks}", ranks.get(tgt, 999)))
                break

    # separator / homoglyph collisions
    sk = _skeleton(n)
    for t in by_skel.get(sk, []):
        if t != n:
            plain = re.sub(r"[-_.]", "", n) == re.sub(r"[-_.]", "", t)
            candidates.append(SquatMatch(t, "separator confusion" if plain else "homoglyph substitution", ranks[t]))

    # edit distance (bounded search by length)
    if len(n) >= 4:
        for L in range(len(n) - 1, len(n) + 2):
            for t in by_len.get(L, []):
                if t[0] != n[0] and t[-1] != n[-1]:
                    continue
                r = ranks[t]
                max_d = 1 if len(t) < 10 else 2
                if max_d == 2 and r > 1500:
                    max_d = 1
                d = damerau_levenshtein(n, t, max_d)
                if 0 < d <= max_d:
                    candidates.append(SquatMatch(t, f"{d}-character edit", r, d))

    # affixes: python-requests, lodashjs, reactjs2 ...
    for p in PREFIXES:
        if n.startswith(p) and n[len(p) :] in ranks and ranks[n[len(p) :]] <= 1000 and len(n) - len(p) >= 4:
            candidates.append(SquatMatch(n[len(p) :], f"added prefix '{p}'", ranks[n[len(p) :]]))
    for s in SUFFIXES:
        if n.endswith(s) and n[: -len(s)] in ranks and ranks[n[: -len(s)]] <= 1000 and len(n) - len(s) >= 4:
            candidates.append(SquatMatch(n[: -len(s)], f"added suffix '{s}'", ranks[n[: -len(s)]]))

    # token reordering: dateutil-python vs python-dateutil
    if "-" in n:
        toks = tuple(sorted(n.split("-")))
        for t in by_len.get(len(n), []):
            if t != n and "-" in t and tuple(sorted(t.split("-"))) == toks:
                candidates.append(SquatMatch(t, "reordered name tokens", ranks[t]))

    if not candidates:
        return None
    return min(candidates, key=lambda c: (c.rank, c.distance))


class TyposquatAnalyzer:
    name = "typosquat"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.package.name or ctx.package.name.startswith("<"):
            return []
        m = check_name(ctx.package.name, ctx.ecosystem)
        if not m:
            return []
        sev = Severity.MEDIUM if m.rank <= 500 else Severity.LOW
        return [
            Finding(
                "TYPOSQUAT",
                "Possible typosquat",
                sev,
                Category.TYPOSQUAT,
                f"`{ctx.package.name}` resembles `{m.target}` (#{m.rank} most downloaded on {ctx.ecosystem}) via {m.technique}",
                confidence=0.6,
                evidence={"target": m.target, "technique": m.technique, "target_rank": m.rank},
            )
        ]
