"""Live registry tests. Run with `pytest -m network`; deselected in offline CI with `-m 'not network'`."""

import pytest

from sniffdog.config import Config
from sniffdog.scanner import Scanner

pytestmark = pytest.mark.network


@pytest.mark.parametrize("spec", ["pypi:requests==2.32.3", "pypi:six==1.16.0", "npm:lodash@4.17.21", "npm:chalk@5.3.0"])
def test_popular_packages_are_clean(spec):
    r = Scanner(Config()).scan_spec(spec)[0]
    assert r.verdict in ("clean", "low-risk"), [f.rule_id for f in r.findings]
    assert r.package.sha256 and r.package.metadata["registry"] in ("pypi", "npm")
