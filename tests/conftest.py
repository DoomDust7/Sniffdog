from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bench"))


@pytest.fixture(scope="session")
def corpus() -> Path:
    import build_corpus

    if not (build_corpus.ROOT / "malicious").exists():
        build_corpus.build()
    return build_corpus.ROOT


def rules_of(findings, min_sev=None):
    from sniffdog.models import Severity

    m = min_sev if min_sev is not None else Severity.INFO
    return {f.rule_id for f in findings if f.severity >= m}
