"""Every labelled corpus sample must land on the right side of the decision boundary."""

import build_corpus
import pytest

from sniffdog.config import Config
from sniffdog.scanner import Scanner

SCANNER = Scanner(Config(metadata=False))


@pytest.mark.parametrize("name", sorted(build_corpus.MALICIOUS))
def test_malicious_sample_detected(corpus, name):
    r = SCANNER.scan_path(corpus / "malicious" / name)
    assert r.verdict in ("malicious", "suspicious"), [f"{f.rule_id} {f.severity}" for f in r.findings]
    assert r.score >= 40


@pytest.mark.parametrize("name", sorted(build_corpus.BENIGN))
def test_benign_sample_clean(corpus, name):
    r = SCANNER.scan_path(corpus / "benign" / name)
    assert r.verdict in ("clean", "low-risk"), [f"{f.rule_id} {f.severity} {f.message}" for f in r.findings]
