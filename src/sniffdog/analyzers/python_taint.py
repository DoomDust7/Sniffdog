"""Inter-procedural taint analysis for Python sources.

The analysis is deliberately *flow-insensitive within a scope* (assignments are
iterated to a fixpoint, so statement order does not matter) and
*summary-based across functions*: every function gets a summary of which of
its parameters reach a sink and which labels its return value carries. That
lets us follow the classic stealer shape::

    def collect():            # returns {"env:all"}
        return dict(os.environ)

    def ship(payload):        # param 0 -> network sink
        requests.post(URL, json=payload)

    ship(collect())           # flagged here, reported at the sink

Labels
------
``env:all``      the whole environment (dict(os.environ), os.environ.items()...)
``env:secret``   a single env var whose *name* looks secret (AWS_SECRET..., *_TOKEN)
``env:var``      any other single env var (weak)
``cred``         content of a credential file (~/.ssh, ~/.aws, browser stores, wallets)
``sysinfo``      host fingerprint (hostname, username, MAC...)
``userfiles``    enumeration of the user's home directory
``decoded``      result of a decoding/decompression/decryption primitive
``remote``       content fetched from the network
``senspath``     a *path* naming a credential store (not data on its own)
``param:N``      symbolic: value of the enclosing function's N-th call argument
"""

from __future__ import annotations

import ast
import base64
import binascii
import codecs
import re
import warnings
import zlib
from dataclasses import dataclass, field

from ..models import Category, Finding, Severity
from .base import ScanContext, iter_text_files, snippet_at

# --------------------------------------------------------------------------- tables

SENSITIVE_PATH = re.compile(
    r"\.ssh\b|id_rsa|id_ed25519|id_ecdsa|\.aws[/\\]|\.azure[/\\]|gcloud[/\\]|application_default_credentials"
    r"|\.npmrc|\.pypirc|\.git-credentials|\.netrc|\.docker[/\\]config|\.kube[/\\]config"
    r"|Login Data|Local State|Cookies\b|Web Data|\.bash_history|\.zsh_history|/etc/shadow|/etc/passwd"
    r"|wallet\.dat|Exodus|Electrum|Atomic[/\\]Local Storage|MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn"
    r"|Local Storage[/\\]leveldb|discord[/\\]|\.gnupg|keychain|\.password-store|Telegram Desktop[/\\]tdata"
    r"|^\.(aws|azure|kube|docker|gnupg|ssh|config/gcloud)$|^(leveldb|Local Storage|discord(canary|ptb)?|Login Data|Cookies|credentials|id_rsa)$",
    re.I,
)
SECRET_ENV_NAME = re.compile(
    r"TOKEN|SECRET|PASSW|API_?KEY|ACCESS_?KEY|PRIVATE|CREDENTIAL|SESSION|COOKIE|^AWS_|^NPM_|^GITHUB_|^GH_|"
    r"PYPI|SLACK|DISCORD|STRIPE|OPENAI|ANTHROPIC|DATABASE_URL|_KEY$",
    re.I,
)
PERSIST_PATH = re.compile(
    r"\.bashrc|\.bash_profile|\.zshrc|\.zprofile|(?:^|[/\\~])\.profile\b|/etc/cron|crontab|LaunchAgents|LaunchDaemons"
    r"|Programs[/\\]+Startup|CurrentVersion[/\\]+Run|systemd[/\\]+(?:system|user)|\.config[/\\]autostart"
    r"|authorized_keys|/etc/rc\.local|/etc/profile|sitecustomize\.py|usercustomize\.py",
    re.I,
)
SHELL_DOWNLOAD = re.compile(
    r"\b(curl|wget)\b[^|;&]*https?://|\b(curl|wget)\b.*\|\s*(ba|z|da)?sh\b|Invoke-WebRequest|\biwr\b|Invoke-Expression|\biex\b"
    r"|DownloadString|DownloadFile|certutil\s+.*-urlcache|bitsadmin\s+/transfer|powershell(\.exe)?\s+.*-e(nc(odedcommand)?)?\s"
    r"|/dev/tcp/|\bnc\s+(-\w+\s+)*-e\b|\bncat\b.*-e|bash\s+-i\s+>&|mshta\s|regsvr32\s+/s\s+/n|python[23]?\s+-c\s+.*(urlopen|requests|socket)",
    re.I,
)

LOLBIN = re.compile(r"\b(rundll32|regsvr32|mshta|certutil|bitsadmin|wscript|cscript|installutil|forfiles|odbcconf)(\.exe)?\b", re.I)
SELF_PUBLISH = re.compile(r"\bnpm\s+publish\b|\btwine\s+upload\b|\byarn\s+(npm\s+)?publish\b|\bpnpm\s+publish\b", re.I)

SYSINFO_CALLS = {
    "socket.gethostname",
    "platform.node",
    "getpass.getuser",
    "os.getlogin",
    "os.uname",
    "platform.uname",
    "uuid.getnode",
    "pwd.getpwuid",
    "socket.getfqdn",
    "platform.platform",
    "os.getuid",
}
DECODERS = {
    "base64.b64decode",
    "base64.b32decode",
    "base64.b16decode",
    "base64.a85decode",
    "base64.b85decode",
    "base64.decodebytes",
    "base64.decodestring",
    "base64.urlsafe_b64decode",
    "base64.standard_b64decode",
    "codecs.decode",
    "binascii.unhexlify",
    "binascii.a2b_base64",
    "binascii.a2b_hex",
    "bytes.fromhex",
    "zlib.decompress",
    "gzip.decompress",
    "lzma.decompress",
    "bz2.decompress",
    "marshal.loads",
    "cryptography.fernet.Fernet().decrypt",
    "Crypto.Cipher.AES.new().decrypt",
}
FILE_READERS = {
    "open",
    "io.open",
    "codecs.open",
    "builtins.open",
    "sqlite3.connect",
    "shutil.copy",
    "shutil.copyfile",
    "shutil.copytree",
    "shutil.make_archive",
    "glob.glob",
    "glob.iglob",
    "os.listdir",
    "os.walk",
    "os.scandir",
}
HOME_ENUM = {"os.walk", "os.listdir", "os.scandir", "glob.glob", "glob.iglob", "pathlib.Path.home().rglob", "pathlib.Path.home().glob"}

NET_SINKS = [
    re.compile(
        r"^(requests|httpx)(\.api)?(\.(Session|session|Client|AsyncClient)\(\))?\.(get|post|put|patch|delete|head|request|options|stream)$"
    ),
    re.compile(r"^urllib[23]?(\.request)?\.(urlopen|Request|urlretrieve)$"),
    re.compile(r"^urllib2\.(urlopen|Request)$"),
    re.compile(r"^(http\.client|httplib)\.HTTPS?Connection\(\)\.(request|putrequest|send|putheader)$"),
    re.compile(r"^socket\.(socket|create_connection)\(\)\.(send|sendall|sendto|connect)$"),
    re.compile(r"^aiohttp\.ClientSession\(\)\.(get|post|put|patch|request)$"),
    re.compile(r"^smtplib\.SMTP(_SSL)?\(\)\.(sendmail|send_message)$"),
    re.compile(r"^ftplib\.FTP(_TLS)?\(\)\.(storbinary|storlines)$"),
    re.compile(r"^(websocket|websockets).*\.send$"),
    re.compile(r"^(discord_webhook|dhooks)\..*"),
    re.compile(r"^pycurl\.Curl\(\)\.setopt$"),
]
DNS_SINKS = [
    re.compile(r"^socket\.(gethostbyname|gethostbyname_ex|getaddrinfo)$"),
    re.compile(r"^dns\.resolver\.(resolve|query)$"),
    re.compile(r"^dns\.resolver\.Resolver\(\)\.(resolve|query)$"),
]
NET_FETCH = [
    re.compile(r"^(requests|httpx)(\.api)?(\.(Session|session|Client)\(\))?\.(get|request|post)$"),
    re.compile(r"^urllib[23]?(\.request)?\.urlopen$"),
    re.compile(r"^urllib2\.urlopen$"),
    re.compile(r"^(http\.client|httplib)\.HTTPS?Connection\(\)\.getresponse$"),
    re.compile(r"^socket\.(socket|create_connection)\(\)\.recv$"),
]
EXEC_SINKS = {"exec", "eval", "compile", "builtins.exec", "builtins.eval", "builtins.compile", "execfile"}
SHELL_SINKS = {
    "os.system",
    "os.popen",
    "os.popen2",
    "os.popen3",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execl",
    "os.execlp",
    "os.spawnl",
    "os.spawnv",
    "os.spawnlp",
    "os.startfile",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "commands.getoutput",
    "pty.spawn",
    "asyncio.create_subprocess_shell",
    "asyncio.create_subprocess_exec",
}
SHELLCODE = re.compile(
    r"^ctypes\.(windll|cdll|WinDLL|CDLL\(\))\.?(kernel32\.)?(VirtualAlloc|VirtualProtect|CreateThread|RtlMoveMemory|WriteProcessMemory|CreateRemoteThread|NtAllocateVirtualMemory)"
)
SURVEILLANCE = {
    "pynput.keyboard.Listener": "keystroke capture",
    "keyboard.on_press": "keystroke capture",
    "keyboard.hook": "keystroke capture",
    "PIL.ImageGrab.grab": "screen capture",
    "pyscreenshot.grab": "screen capture",
    "pyautogui.screenshot": "screen capture",
    "browser_cookie3.load": "browser cookie theft",
    "browser_cookie3.chrome": "browser cookie theft",
    "win32crypt.CryptUnprotectData": "decryption of browser-stored passwords",
    "pyperclip.copy": "clipboard write",
}
DANGEROUS_NAMES = {
    "system",
    "popen",
    "exec",
    "eval",
    "compile",
    "__import__",
    "b64decode",
    "loads",
    "urlopen",
    "Popen",
    "check_output",
    "call",
    "run",
    "getattr",
    "spawn",
    "startfile",
    "execv",
    "decompress",
}
IGNORED_KWARGS = {
    "proxies",
    "verify",
    "cert",
    "timeout",
    "allow_redirects",
    "stream",
    "auth",
    "cwd",
    "env",
    "stdout",
    "stderr",
    "stdin",
    "shell",
    "text",
    "check",
    "encoding",
    "capture_output",
}
INSTALL_CMD_BASES = {
    "install",
    "develop",
    "egg_info",
    "build_py",
    "build_ext",
    "sdist",
    "bdist_egg",
    "bdist_wheel",
    "build",
    "install_lib",
    "install_scripts",
    "easy_install",
}

STRONG = {"cred", "env:all"}
REAL_LABELS = {"env:all", "env:secret", "env:var", "cred", "sysinfo", "userfiles"}

# --------------------------------------------------------------------------- helpers


def _matches(q: str | None, patterns) -> bool:
    return bool(q) and any(p.search(q) for p in patterns)


def _real(labels: set[str]) -> set[str]:
    return labels & REAL_LABELS


def _bump(sev: Severity, n: int = 1) -> Severity:
    return Severity(min(int(sev) + n, int(Severity.CRITICAL)))


@dataclass
class Scope:
    name: str
    node: ast.AST
    is_module: bool = False
    is_method: bool = False
    params: list[str] = field(default_factory=list)
    taint: dict[str, set[str]] = field(default_factory=dict)
    types: dict[str, str] = field(default_factory=dict)
    globals_: set[str] = field(default_factory=set)
    stmts: list[ast.AST] = field(default_factory=list)  # nodes owned by this scope (no nested defs)
    main_guarded: set[int] = field(default_factory=set)  # ids of nodes under `if __name__ == "__main__"`


@dataclass
class SinkHit:
    kind: str  # net | dns | exec | shell | write
    q: str
    node: ast.AST
    labels: set[str]
    scope: Scope
    via: str | None = None  # "func() at line N" for summary-propagated sinks
    sink_line: int | None = None


@dataclass
class Summary:
    returns: set[str] = field(default_factory=set)
    sinks: set[tuple[int, str, str, int]] = field(default_factory=set)  # (param idx, kind, q, line)
    params: list[str] = field(default_factory=list)
    is_method: bool = False


class _ConstFolder:
    """Best-effort constant evaluation used to deobfuscate payloads statically."""

    def __init__(self, qual):
        self.qual = qual
        self.consts: dict[str, ast.AST] = {}  # module-level names assigned exactly once

    def fold(self, node: ast.AST, depth: int = 0) -> str | bytes | None:
        if depth > 12:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            return node.value
        if isinstance(node, ast.Name) and node.id in self.consts:
            return self.fold(self.consts[node.id], depth + 1)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            a, b = self.fold(node.left, depth + 1), self.fold(node.right, depth + 1)
            if isinstance(a, str) and isinstance(b, str) or isinstance(a, bytes) and isinstance(b, bytes):
                return a + b  # type: ignore[operator]
            return None
        if isinstance(node, ast.JoinedStr):
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant):
                    parts.append(str(v.value))
                else:
                    return None
            return "".join(parts)
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
            s = node.slice
            if s.lower is None and s.upper is None and isinstance(s.step, ast.UnaryOp) and isinstance(s.step.op, ast.USub):
                inner = self.fold(node.value, depth + 1)
                if inner is not None and isinstance(s.step.operand, ast.Constant) and s.step.operand.value == 1:
                    return inner[::-1]
            return None
        if isinstance(node, ast.Call):
            q = self.qual(node.func)
            args = node.args
            if q and q.endswith(".join") and isinstance(node.func, ast.Attribute) and args and isinstance(args[0], ast.Call):
                inner = args[0]
                if self.qual(inner.func) == "map" and len(inner.args) == 2 and self.qual(inner.args[0]) == "chr":
                    sep = self.fold(node.func.value, depth + 1)
                    seq = inner.args[1]
                    if isinstance(sep, str) and isinstance(seq, (ast.List, ast.Tuple)):
                        vals = [e.value for e in seq.elts if isinstance(e, ast.Constant) and isinstance(e.value, int)]
                        if len(vals) == len(seq.elts):
                            try:
                                return sep.join(map(chr, vals))
                            except (ValueError, OverflowError):
                                return None
            if q == "chr" and args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, int):
                try:
                    return chr(args[0].value)
                except (ValueError, OverflowError):
                    return None
            if q and q.endswith(".join") and isinstance(node.func, ast.Attribute) and args:
                sep = self.fold(node.func.value, depth + 1)
                if isinstance(sep, str) and isinstance(args[0], (ast.List, ast.Tuple)):
                    items = [self.fold(e, depth + 1) for e in args[0].elts]
                    if all(isinstance(i, str) for i in items):
                        return sep.join(items)  # type: ignore[arg-type]
                if isinstance(sep, str) and isinstance(args[0], (ast.GeneratorExp, ast.ListComp)):
                    return self._fold_chr_comprehension(args[0], sep)
            if q and q.endswith((".decode", ".encode")) and isinstance(node.func, ast.Attribute):
                inner = self.fold(node.func.value, depth + 1)
                try:
                    if isinstance(inner, bytes) and q.endswith(".decode"):
                        return inner.decode("utf-8", "replace")
                    if isinstance(inner, str) and q.endswith(".encode"):
                        return inner.encode()
                except Exception:  # noqa: BLE001
                    return None
                return None
            if not args:
                return None
            inner = self.fold(args[0], depth + 1)
            if inner is None:
                return None
            raw = inner.encode() if isinstance(inner, str) else inner
            try:
                if q in (
                    "base64.b64decode",
                    "base64.decodebytes",
                    "base64.standard_b64decode",
                    "base64.decodestring",
                    "binascii.a2b_base64",
                ):
                    return base64.b64decode(raw + b"=" * (-len(raw) % 4))
                if q == "base64.urlsafe_b64decode":
                    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))
                if q == "base64.b32decode":
                    return base64.b32decode(raw)
                if q == "base64.b16decode":
                    return base64.b16decode(raw)
                if q == "base64.b85decode":
                    return base64.b85decode(raw)
                if q == "base64.a85decode":
                    return base64.a85decode(raw)
                if q in ("bytes.fromhex", "binascii.unhexlify", "binascii.a2b_hex"):
                    return binascii.unhexlify(raw.strip())
                if q == "zlib.decompress":
                    return zlib.decompress(raw)
                if q == "codecs.decode" and len(args) > 1:
                    enc = self.fold(args[1], depth + 1)
                    if isinstance(enc, str) and enc.lower().replace("_", "").replace("-", "") in ("rot13", "rot13"):
                        return codecs.decode(inner if isinstance(inner, str) else inner.decode(), "rot13")
                    if isinstance(enc, str) and enc.lower() in ("hex", "base64", "zlib"):
                        return codecs.decode(raw, enc)
            except Exception:  # noqa: BLE001 - garbage in, nothing out
                return None
        return None

    def _fold_chr_comprehension(self, comp, sep: str) -> str | None:
        # "".join(chr(c) for c in [104, 105])  /  "".join([chr(x ^ 7) for x in (...)]) (no xor support)
        if len(comp.generators) != 1:
            return None
        gen = comp.generators[0]
        if not isinstance(gen.iter, (ast.List, ast.Tuple)):
            return None
        elt = comp.elt
        if not (isinstance(elt, ast.Call) and self.qual(elt.func) == "chr" and len(elt.args) == 1):
            return None
        if not (isinstance(elt.args[0], ast.Name) and isinstance(gen.target, ast.Name) and elt.args[0].id == gen.target.id):
            return None
        vals = []
        for e in gen.iter.elts:
            if isinstance(e, ast.Constant) and isinstance(e.value, int) and 0 <= e.value < 0x110000:
                vals.append(chr(e.value))
            else:
                return None
        return sep.join(vals)


# --------------------------------------------------------------------------- analysis


class ModuleAnalysis:
    MAX_ITER = 6

    def __init__(self, tree: ast.Module, path: str, text: str, install_time: bool, import_time: bool, run_as_main: bool = False):
        self.run_as_main = run_as_main  # launched via `python -m` / `python file.py`: the __main__ block executes
        self.tree = tree
        self.path = path
        self.text = text
        self.install_time = install_time
        self.import_time = import_time
        self.imports: dict[str, str] = {}
        self.global_taint: dict[str, set[str]] = {}
        self.global_types: dict[str, str] = {}
        self.scopes: list[Scope] = []
        self.functions: dict[str, Scope] = {}
        self.summaries: dict[str, Summary] = {}
        self.classes: dict[str, list[str]] = {}  # class -> base qualnames
        self.cmdclass_methods: set[int] = set()  # ids of FunctionDef nodes that run at install time
        self.parents: dict[int, ast.AST] = {}
        self.folder = _ConstFolder(lambda n: self.qual(n, None))
        self.findings: list[Finding] = []
        self._seen: set[tuple] = set()

    # ----------------------------------------------------------------- setup

    def prepare(self) -> None:
        for parent in ast.walk(self.tree):
            for child in ast.iter_child_nodes(parent):
                self.parents[id(child)] = parent
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.imports[a.asname] = a.name
                    else:
                        self.imports[a.name.split(".")[0]] = a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for a in node.names:
                    self.imports[a.asname or a.name] = f"{node.module}.{a.name}"
        counts: dict[str, int] = {}
        for n in ast.walk(self.tree):
            if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.For, ast.With, ast.NamedExpr)):
                targets = n.targets if isinstance(n, ast.Assign) else [getattr(n, "target", None)]
                for t in targets:
                    if isinstance(t, ast.Name):
                        counts[t.id] = counts.get(t.id, 0) + 1
        for n in self.tree.body:
            if (
                isinstance(n, ast.Assign)
                and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name)
                and counts.get(n.targets[0].id) == 1
            ):
                self.folder.consts[n.targets[0].id] = n.value
        module = Scope("<module>", self.tree, is_module=True)
        self.scopes.append(module)
        self._collect(self.tree.body, module, cls=None, guarded=False)

    def _is_main_guard(self, node: ast.If) -> bool:
        t = node.test
        return (
            isinstance(t, ast.Compare)
            and isinstance(t.left, ast.Name)
            and t.left.id == "__name__"
            and any(isinstance(c, ast.Constant) and c.value == "__main__" for c in t.comparators)
        )

    INSTALL_COMMANDS = {
        "install",
        "develop",
        "egg_info",
        "build",
        "build_ext",
        "build_py",
        "bdist_wheel",
        "bdist_egg",
        "dist_info",
        "editable_wheel",
    }

    def _is_maintainer_command(self, node: ast.If) -> bool:
        """`if sys.argv[-1] == "publish":` in setup.py runs only when a maintainer types that command.

        Guards naming an install-path command (or none at all) are *not* exempt, so
        `if "install" in sys.argv:` payloads are still treated as install-time code.
        """
        test = node.test
        mentions_argv = any(isinstance(n, ast.Attribute) and n.attr == "argv" for n in ast.walk(test))
        consts = {n.value for n in ast.walk(test) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        return mentions_argv and bool(consts) and not (consts & self.INSTALL_COMMANDS)

    def _collect(self, body, scope: Scope, cls: str | None, guarded: bool) -> None:
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fs = Scope(stmt.name, stmt, is_method=cls is not None)
                args = stmt.args
                fs.params = [a.arg for a in args.posonlyargs + args.args + args.kwonlyargs]
                if fs.is_method and fs.params and fs.params[0] in ("self", "cls"):
                    fs.params = fs.params[1:]
                for i, p in enumerate(fs.params):
                    fs.taint[p] = {f"param:{i}"}
                self.scopes.append(fs)
                self.functions.setdefault(stmt.name, fs)
                self.summaries.setdefault(stmt.name, Summary(params=fs.params, is_method=fs.is_method))
                if cls is not None and stmt.name == "run" and self._is_install_cmd(cls):
                    self.cmdclass_methods.add(id(stmt))
                self._collect(stmt.body, fs, cls=None, guarded=False)
                for d in stmt.decorator_list:
                    scope.stmts.append(d)
                continue
            if isinstance(stmt, ast.ClassDef):
                self.classes[stmt.name] = [self.qual(b, None) or "" for b in stmt.bases]
                self._collect(stmt.body, scope, cls=stmt.name, guarded=guarded)
                continue
            if isinstance(stmt, ast.Global):
                scope.globals_.update(stmt.names)
            g = guarded
            if (
                isinstance(stmt, ast.If)
                and scope.is_module
                and ((self._is_main_guard(stmt) and not self.run_as_main) or self._is_maintainer_command(stmt))
            ):
                g = True
            # Own every node of this statement except nested function / class bodies.
            stack = [stmt]
            while stack:
                n = stack.pop()
                scope.stmts.append(n)
                if g:
                    scope.main_guarded.add(id(n))
                for child in ast.iter_child_nodes(n):
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        self._collect([child], scope, cls=cls, guarded=g)
                    elif isinstance(child, ast.Lambda):
                        stack.append(child.body)
                    else:
                        stack.append(child)

    def _is_install_cmd(self, cls: str) -> bool:
        for b in self.classes.get(cls, []):
            last = b.split(".")[-1]
            if last in INSTALL_CMD_BASES or b.split(".")[-2:-1] and b.split(".")[-2] in INSTALL_CMD_BASES:
                return True
        return False

    # ----------------------------------------------------------------- name resolution

    def qual(self, node: ast.AST, scope: Scope | None) -> str | None:
        if isinstance(node, ast.Name):
            if scope is not None and node.id in scope.types:
                return scope.types[node.id]
            if node.id in self.global_types and (scope is None or node.id not in scope.taint):
                return self.global_types[node.id]
            return self.imports.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.qual(node.value, scope)
            if base is None:
                return None
            if base == "__builtins__":
                base = "builtins"
            return f"{base}.{node.attr}"
        if isinstance(node, ast.Call):
            f = self.qual(node.func, scope)
            if f in ("__import__", "importlib.import_module", "builtins.__import__") and node.args:
                s = self.folder.fold(node.args[0])
                if isinstance(s, str):
                    return s
            if f == "getattr" and len(node.args) >= 2:
                base = self.qual(node.args[0], scope)
                s = self.folder.fold(node.args[1])
                if base and isinstance(s, str):
                    return f"{'builtins' if base == '__builtins__' else base}.{s}"
            if f == "pathlib.Path" or f == "Path":
                return "pathlib.Path()"
            return f + "()" if f else None
        if isinstance(node, ast.Subscript):
            base = self.qual(node.value, scope)
            return f"{base}[]" if base else None
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            return type(node.value).__name__  # "".join(...) -> "str.join", b"".fromhex -> "bytes.fromhex"
        return None

    def _func_key(self, q: str | None) -> str | None:
        if not q:
            return None
        parts = q.split(".")
        if len(parts) == 1 and q in self.functions and q not in self.imports:
            return q
        if len(parts) == 2 and (parts[0] in ("self", "cls") or parts[0].removesuffix("()") in self.classes) and parts[1] in self.functions:
            return parts[1]
        return None

    # ----------------------------------------------------------------- labels

    def _env_key_label(self, key: ast.AST | None) -> str:
        s = self.folder.fold(key) if key is not None else None
        if isinstance(s, str):
            return "env:secret" if SECRET_ENV_NAME.search(s) else "env:var"
        return "env:var"

    def _env_label(self, node: ast.AST) -> str | None:
        p = self.parents.get(id(node))
        if isinstance(p, ast.Subscript) and p.value is node:
            if not isinstance(p.ctx, ast.Load):
                return None
            return self._env_key_label(p.slice)
        if isinstance(p, ast.Attribute) and p.value is node:
            gp = self.parents.get(id(p))
            if p.attr in ("get", "pop", "setdefault") and isinstance(gp, ast.Call):
                return self._env_key_label(gp.args[0] if gp.args else None)
            if p.attr in ("items", "copy", "values", "__repr__", "__str__"):
                return "env:all"
            if p.attr == "keys":
                return "env:var"
            return None
        if isinstance(p, ast.Compare):
            return None
        if isinstance(p, ast.keyword) and p.arg == "env":
            return None
        if isinstance(p, ast.Call) and p.func is node:
            return None
        return "env:all"

    def labels(self, expr: ast.AST | None, scope: Scope) -> set[str]:
        if expr is None:
            return set()
        out: set[str] = set()
        for n in ast.walk(expr):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                if n.id in scope.taint:
                    out |= scope.taint[n.id]
                elif n.id in self.global_taint:
                    out |= self.global_taint[n.id]
                if self.imports.get(n.id) == "os.environ":
                    lab = self._env_label(n)
                    if lab:
                        out.add(lab)
            elif isinstance(n, ast.Attribute):
                q = self.qual(n, scope)
                if q == "os.environ":
                    lab = self._env_label(n)
                    if lab:
                        out.add(lab)
                if isinstance(n.value, ast.Name) and n.value.id == "self":
                    out |= self.global_taint.get(f"self.{n.attr}", set())
            elif isinstance(n, ast.Call):
                out |= self._call_labels(n, scope)
            elif isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) < 512:
                if SENSITIVE_PATH.search(n.value):
                    out.add("senspath")
            elif isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Slice):
                st = n.slice.step
                # "...")[::-1] on a *string constant* is an obfuscation idiom; reversing lists is not
                if isinstance(st, ast.UnaryOp) and isinstance(st.op, ast.USub) and isinstance(self.folder.fold(n.value), (str, bytes)):
                    out.add("decoded")
        return out

    def _call_labels(self, call: ast.Call, scope: Scope) -> set[str]:
        q = self.qual(call.func, scope)
        out: set[str] = set()
        if not q:
            return out
        if q in SYSINFO_CALLS:
            out.add("sysinfo")
        if q == "os.getenv" or q == "os.environ.get":
            out.add(self._env_key_label(call.args[0] if call.args else None))
        if q in DECODERS or q.endswith((".decrypt", ".fromhex")) or q.endswith("Fernet().decrypt"):
            out.add("decoded")
        if q.endswith(".join") and any(
            (isinstance(a, ast.Call) and self.qual(a.func, scope) == "chr") or (isinstance(a, ast.Name) and a.id == "chr")
            for arg in call.args
            for a in ast.walk(arg)
        ):
            out.add("decoded")
        if q == "bytes" and call.args and isinstance(call.args[0], (ast.List, ast.Tuple)) and len(call.args[0].elts) > 16:
            out.add("decoded")
        if _matches(q, NET_FETCH) or q.endswith(("urlopen().read", ".recv")):
            out.add("remote")
        # file / directory readers: a sensitive path in -> credential data out
        is_reader = q in FILE_READERS or q.endswith((".read_text", ".read_bytes", ".open", ".iterdir", ".rglob", ".glob"))
        if is_reader:
            arg_labels: set[str] = set()
            for a in call.args:
                arg_labels |= self.labels(a, scope)
            if isinstance(call.func, ast.Attribute):
                arg_labels |= self.labels(call.func.value, scope)
            if "senspath" in arg_labels and not self._is_write_open(call, q):
                out.add("cred")
            if q in HOME_ENUM or q.endswith((".rglob",)):
                if any(self._mentions_home(a, scope) for a in call.args) or (
                    isinstance(call.func, ast.Attribute) and self._mentions_home(call.func.value, scope)
                ):
                    out.add("userfiles")
        key = self._func_key(q)
        if key:
            out |= self._subst(self.summaries[key].returns, call, key, scope)
        return out

    def _mentions_home(self, node: ast.AST, scope: Scope) -> bool:
        for n in ast.walk(node):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.strip() in ("~", "~/", "/home", "/Users", "C:\\Users"):
                return True
            if isinstance(n, ast.Call):
                q = self.qual(n.func, scope)
                if q in ("os.path.expanduser", "pathlib.Path.home", "Path.home") and (
                    not n.args or (isinstance(n.args[0], ast.Constant) and str(n.args[0].value).rstrip("/") == "~")
                ):
                    return True
            if isinstance(n, ast.Name) and self.imports.get(n.id) == "os.environ":
                continue
        return False

    def _is_write_open(self, call: ast.Call, q: str) -> bool:
        if q not in ("open", "io.open", "codecs.open", "builtins.open") and not q.endswith(".open"):
            return False
        mode = call.args[1] if len(call.args) > 1 else next((k.value for k in call.keywords if k.arg == "mode"), None)
        m = self.folder.fold(mode) if mode is not None else None
        return isinstance(m, str) and any(c in m for c in "wax")

    def _subst(self, labels: set[str], call: ast.Call, key: str, scope: Scope) -> set[str]:
        out = {lab for lab in labels if not lab.startswith("param:")}
        summ = self.summaries[key]
        for lab in labels:
            if lab.startswith("param:"):
                idx = int(lab.split(":")[1])
                arg = self._arg_for(call, idx, summ)
                if arg is not None:
                    out |= self.labels(arg, scope)
        return out

    @staticmethod
    def _arg_for(call: ast.Call, idx: int, summ: Summary) -> ast.AST | None:
        if idx < len(call.args) and not any(isinstance(a, ast.Starred) for a in call.args[: idx + 1]):
            return call.args[idx]
        if idx < len(summ.params):
            name = summ.params[idx]
            for k in call.keywords:
                if k.arg == name:
                    return k.value
        return None

    # ----------------------------------------------------------------- propagation

    def _assign(self, target: ast.AST, labels: set[str], scope: Scope, value: ast.AST | None) -> bool:
        changed = False
        if isinstance(target, ast.Name):
            store = self.global_taint if (scope.is_module or target.id in scope.globals_) else scope.taint
            cur = store.setdefault(target.id, set())
            if not labels <= cur:
                cur |= labels
                changed = True
            if isinstance(value, ast.Call) or isinstance(value, ast.Await):
                inner = value.value if isinstance(value, ast.Await) else value
                q = self.qual(inner, scope)
                fq = self.qual(inner.func, scope) if isinstance(inner, ast.Call) else None
                # `x = Foo()` types x as "Foo()"; `m = __import__("o" + "s")` makes m an alias of module "os".
                is_module_alias = fq in ("__import__", "importlib.import_module", "builtins.__import__")
                if q and (q.endswith("()") or is_module_alias):
                    types = self.global_types if scope.is_module else scope.types
                    if types.get(target.id) != q:
                        types[target.id] = q
        elif isinstance(target, (ast.Tuple, ast.List)):
            for e in target.elts:
                changed |= self._assign(e.value if isinstance(e, ast.Starred) else e, labels, scope, None)
        elif isinstance(target, ast.Attribute):
            if isinstance(target.value, ast.Name) and target.value.id == "self":
                key = f"self.{target.attr}"
                cur = self.global_taint.setdefault(key, set())
                if not labels <= cur:
                    cur |= labels
                    changed = True
        elif isinstance(target, ast.Subscript):
            root = self._root_name(target)
            if root is not None and root.id not in self.imports:
                changed |= self._assign(root, labels, scope, None)
        return changed

    @staticmethod
    def _root_name(node: ast.AST) -> ast.Name | None:
        while isinstance(node, (ast.Subscript, ast.Attribute)):
            node = node.value
        return node if isinstance(node, ast.Name) else None

    def propagate(self, scope: Scope) -> bool:
        changed = False
        for n in scope.stmts:
            if isinstance(n, ast.Assign):
                lab = self.labels(n.value, scope)
                for t in n.targets:
                    changed |= self._assign(t, lab, scope, n.value)
            elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and n.value is not None:
                changed |= self._assign(n.target, self.labels(n.value, scope), scope, n.value)
            elif isinstance(n, ast.NamedExpr):
                changed |= self._assign(n.target, self.labels(n.value, scope), scope, n.value)
            elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
                changed |= self._assign(n.target, self.labels(n.iter, scope), scope, None)
            elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                changed |= self._assign(n.optional_vars, self.labels(n.context_expr, scope), scope, n.context_expr)
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                # container mutation: buf.append(x), d.update(x), out.write(x)
                if n.func.attr in ("append", "extend", "update", "add", "insert", "write", "writelines", "setdefault", "appendleft"):
                    root = self._root_name(n.func.value)
                    rtype = (scope.types.get(root.id) or self.global_types.get(root.id) or "") if root is not None else ""
                    file_like = n.func.attr in ("write", "writelines") and rtype.startswith(
                        ("open(", "io.open(", "builtins.open(", "tempfile.", "codecs.open(", "gzip.open(", "pathlib.Path().open(")
                    )
                    recv = n.func.value
                    if isinstance(recv, ast.Attribute) and isinstance(recv.value, ast.Name) and recv.value.id == "self":
                        lab = set()
                        for a in list(n.args) + [k.value for k in n.keywords]:
                            lab |= self.labels(a, scope)
                        changed |= self._assign(recv, lab, scope, None)
                    elif root is not None and root.id not in self.imports and not file_like:
                        lab = set()
                        for a in list(n.args) + [k.value for k in n.keywords]:
                            lab |= self.labels(a, scope)
                        if lab:
                            changed |= self._assign(root, lab, scope, None)
            elif isinstance(n, ast.Return) and n.value is not None and not scope.is_module:
                summ = self.summaries.get(scope.name)
                if summ is not None:
                    lab = self.labels(n.value, scope) - {"senspath"} | (self.labels(n.value, scope) & {"senspath"})
                    if not lab <= summ.returns:
                        summ.returns |= lab
                        changed = True
            elif isinstance(n, (ast.Yield, ast.YieldFrom)) and n.value is not None and not scope.is_module:
                summ = self.summaries.get(scope.name)
                if summ is not None:
                    lab = self.labels(n.value, scope)
                    if not lab <= summ.returns:
                        summ.returns |= lab
                        changed = True
        # sinks reached by parameters become part of the function summary
        if not scope.is_module:
            summ = self.summaries.get(scope.name)
            if summ is not None:
                for hit in self.sink_hits(scope):
                    for lab in hit.labels:
                        if lab.startswith("param:"):
                            entry = (int(lab.split(":")[1]), hit.kind, hit.q, hit.sink_line or getattr(hit.node, "lineno", 0))
                            if entry not in summ.sinks:
                                summ.sinks.add(entry)
                                changed = True
        return changed

    def _type_pass(self) -> None:
        """Infer constructor types before taint propagation so traversal order cannot matter."""
        for _ in range(2):
            for s in self.scopes:
                for n in s.stmts:
                    if isinstance(n, ast.Assign) and isinstance(n.value, (ast.Call, ast.Await)):
                        for t in n.targets:
                            if isinstance(t, ast.Name):
                                self._assign(t, set(), s, n.value)
                    elif isinstance(n, ast.withitem) and isinstance(n.optional_vars, ast.Name) and isinstance(n.context_expr, ast.Call):
                        self._assign(n.optional_vars, set(), s, n.context_expr)

    def run(self) -> None:
        self.prepare()
        self._type_pass()
        for _ in range(self.MAX_ITER):
            changed = False
            for s in self.scopes:
                changed |= self.propagate(s)
            if not changed:
                break
        self.reachable = self._reachable_from_module()
        for s in self.scopes:
            self.check_scope(s)

    def _reachable_from_module(self) -> set[str]:
        """Functions that execute when the module is imported (or setup.py runs)."""
        module = self.scopes[0]
        graph: dict[str, set[str]] = {}
        for s in self.scopes[1:]:
            graph.setdefault(s.name, set())
            for n in s.stmts:
                if isinstance(n, ast.Name) and n.id in self.functions:
                    graph[s.name].add(n.id)
                elif (
                    isinstance(n, ast.Attribute)
                    and n.attr in self.functions
                    and isinstance(n.value, ast.Name)
                    and n.value.id in ("self", "cls")
                ):
                    graph[s.name].add(n.attr)
        roots = set()
        for n in module.stmts:
            if id(n) in module.main_guarded:
                continue
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in self.functions:
                parent = self.parents.get(id(n))
                if not isinstance(parent, ast.FunctionDef):  # decorators count, they run at import
                    roots.add(n.id)
            if (
                isinstance(n, ast.Attribute)
                and n.attr in self.functions
                and (
                    (isinstance(n.value, ast.Name) and (n.value.id in self.classes or n.value.id in self.global_types))
                    or (isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name) and n.value.func.id in self.classes)
                )
            ):
                roots.add(n.attr)
        for s in self.scopes[1:]:
            if id(s.node) in self.cmdclass_methods:
                roots.add(s.name)
            # class instantiated at module level -> __init__ runs
        if "__init__" in self.functions and any(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in self.classes
            for n in module.stmts
            if id(n) not in module.main_guarded
        ):
            roots.add("__init__")
        seen: set[str] = set()
        stack = list(roots)
        while stack:
            f = stack.pop()
            if f in seen:
                continue
            seen.add(f)
            stack.extend(graph.get(f, ()))
        return seen

    # ----------------------------------------------------------------- sinks

    def _call_arg_labels(self, call: ast.Call, scope: Scope, skip_first: bool = False) -> set[str]:
        out: set[str] = set()
        for i, a in enumerate(call.args):
            if skip_first and i == 0:
                continue
            out |= self.labels(a, scope)
        for k in call.keywords:
            if k.arg in IGNORED_KWARGS:
                continue
            out |= self.labels(k.value, scope)
        return out

    def sink_hits(self, scope: Scope) -> list[SinkHit]:
        hits: list[SinkHit] = []
        for n in scope.stmts:
            if not isinstance(n, ast.Call):
                continue
            q = self.qual(n.func, scope)
            if not q:
                continue
            if _matches(q, NET_SINKS):
                hits.append(SinkHit("net", q, n, self._call_arg_labels(n, scope), scope))
            elif _matches(q, DNS_SINKS):
                hits.append(SinkHit("dns", q, n, self._call_arg_labels(n, scope), scope))
            elif q in EXEC_SINKS:
                hits.append(SinkHit("exec", q, n, self.labels(n.args[0], scope) if n.args else set(), scope))
            elif q in SHELL_SINKS:
                lab = self._call_arg_labels(n, scope)
                cmd = n.args[0] if n.args else next((k.value for k in n.keywords if k.arg in ("args", "cmd", "command")), None)
                cmd_labels = self.labels(cmd, scope) if cmd is not None else set()
                lab = (lab - {"decoded", "remote"}) | (cmd_labels & {"decoded", "remote"})
                hits.append(SinkHit("shell", q, n, lab, scope))
            key = self._func_key(q)
            if key and self.summaries[key].sinks:
                summ = self.summaries[key]
                for idx, kind, sq, line in summ.sinks:
                    arg = self._arg_for(n, idx, summ)
                    if arg is None:
                        continue
                    lab = self.labels(arg, scope)
                    hits.append(SinkHit(kind, sq, n, lab, scope, via=f"{key}() line {line}", sink_line=line))
        return hits

    # ----------------------------------------------------------------- findings

    def _ctx(self, scope: Scope, node: ast.AST) -> tuple[bool, bool]:
        """(install_time, import_time) for code at this location."""
        guarded = id(node) in scope.main_guarded
        in_install_cmd = id(scope.node) in self.cmdclass_methods
        install = (self.install_time and not guarded) or in_install_cmd
        runs_on_load = (scope.is_module and not guarded) or scope.name in getattr(self, "reachable", set())
        if self.install_time and not scope.is_module and scope.name not in getattr(self, "reachable", set()):
            install = in_install_cmd
        return install, self.import_time and runs_on_load

    def add(
        self,
        rule: str,
        title: str,
        sev: Severity,
        cat: str,
        msg: str,
        node: ast.AST,
        *,
        conf: float = 0.8,
        install: bool = False,
        evidence: dict | None = None,
        line: int | None = None,
    ) -> None:
        ln = line or getattr(node, "lineno", None)
        key = (rule, ln, msg)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(
            Finding(
                rule_id=rule,
                title=title,
                severity=sev,
                category=cat,
                message=msg,
                file=self.path,
                line=ln,
                column=getattr(node, "col_offset", None),
                snippet=snippet_at(self.text, ln or 0) if ln else None,
                confidence=conf,
                install_time=install,
                evidence=evidence or {},
            )
        )

    def check_scope(self, scope: Scope) -> None:
        for hit in self.sink_hits(scope):
            self._check_hit(hit)
        for n in scope.stmts:
            if isinstance(n, ast.Call):
                self._check_call(n, scope)

    def _describe(self, labels: set[str]) -> str:
        names = {
            "cred": "credential/secret files",
            "env:all": "the entire environment",
            "env:secret": "secret environment variables",
            "env:var": "environment variables",
            "sysinfo": "host fingerprint (hostname/user)",
            "userfiles": "user home directory listing",
        }
        return ", ".join(names[lab] for lab in sorted(labels) if lab in names)

    def _check_hit(self, hit: SinkHit) -> None:
        install, on_import = self._ctx(hit.scope, hit.node)
        via = f" (via {hit.via})" if hit.via else ""
        real = _real(hit.labels)
        if hit.kind in ("net", "dns") and real:
            if real & STRONG:
                sev = Severity.HIGH
            elif "userfiles" in real:
                sev = Severity.MEDIUM
            elif real & {"sysinfo", "env:secret"}:
                sev = Severity.LOW
            else:
                sev = Severity.INFO
            if install:
                sev = Severity.CRITICAL if real & (STRONG | {"env:secret"}) else _bump(sev, 2)
            elif on_import:
                sev = _bump(sev, 1)
            if hit.kind == "dns":
                sev = _bump(sev, 1)
            if sev == Severity.INFO:
                return
            dkey = ("exfil", hit.scope.name, frozenset(real), hit.kind)
            if dkey in self._seen:
                return
            self._seen.add(dkey)
            channel = "DNS lookups" if hit.kind == "dns" else f"`{hit.q}`"
            self.add(
                "PY-EXFIL-DNS" if hit.kind == "dns" else "PY-EXFIL",
                "Sensitive data sent over the network" if hit.kind == "net" else "Data exfiltration via DNS",
                sev,
                Category.EXFILTRATION,
                f"{self._describe(real)} flows into {channel}{via}"
                + (" during package installation" if install else " at import time" if on_import else ""),
                hit.node,
                conf=0.9 if real & STRONG else 0.75,
                install=install,
                evidence={"sources": sorted(real), "sink": hit.q, "via": hit.via},
            )
        elif hit.kind == "exec":
            if "remote" in hit.labels:
                self.add(
                    "PY-EXEC-REMOTE",
                    "Downloads and executes code",
                    Severity.CRITICAL,
                    Category.CODE_EXECUTION,
                    f"content fetched from the network is passed to `{hit.q}`{via}",
                    hit.node,
                    conf=0.95,
                    install=install,
                )
            elif "decoded" in hit.labels:
                payload = self._try_decode(hit)
                ev = {"decoded_preview": payload[:300]} if payload else {}
                self.add(
                    "PY-EXEC-OBFUSCATED",
                    "Executes obfuscated code",
                    Severity.CRITICAL if (install or on_import) else Severity.HIGH,
                    Category.OBFUSCATION,
                    f"decoded/decompressed data is passed to `{hit.q}`{via}",
                    hit.node,
                    conf=0.9,
                    install=install,
                    evidence=ev,
                )
                if payload:
                    self._analyze_layer(payload, hit, install)
            elif hit.node.args and not isinstance(hit.node.args[0], ast.Constant) and not hit.via:
                arg = hit.node.args[0]
                reads_local = any(
                    isinstance(x, ast.Call)
                    and (
                        (isinstance(x.func, ast.Attribute) and x.func.attr in ("read", "read_text", "read_bytes", "get_data"))
                        or (self.qual(x.func, hit.scope) or "") in ("open", "io.open", "codecs.open")
                    )
                    for x in ast.walk(arg)
                ) and not (hit.labels & {"cred", "remote", "decoded"})
                if reads_local:
                    return  # exec(open("pkg/_version.py").read()) is a common, benign setup.py idiom
                self.add(
                    "PY-EXEC-DYNAMIC",
                    "Dynamic code execution",
                    Severity.MEDIUM if install else Severity.LOW,
                    Category.CODE_EXECUTION,
                    f"`{hit.q}` is called with a non-literal argument",
                    hit.node,
                    conf=0.5,
                    install=install,
                )
        elif hit.kind == "shell":
            text = self._const_text(hit.node)
            if "remote" in hit.labels or "decoded" in hit.labels:
                self.add(
                    "PY-SHELL-OBFUSCATED",
                    "Runs a decoded or downloaded command",
                    Severity.CRITICAL,
                    Category.CODE_EXECUTION,
                    f"`{hit.q}` executes data that was decoded or downloaded{via}",
                    hit.node,
                    conf=0.9,
                    install=install,
                )
            elif LOLBIN.search(text):
                self.add(
                    "PY-LOLBIN",
                    "Runs a living-off-the-land binary",
                    Severity.CRITICAL if install else Severity.HIGH,
                    Category.CODE_EXECUTION,
                    f"`{hit.q}` invokes {LOLBIN.search(text).group(0)!r}, a Windows binary abused to proxy execution",
                    hit.node,
                    conf=0.8,
                    install=install,
                )
            elif SELF_PUBLISH.search(text) and id(hit.node) in hit.scope.main_guarded:
                pass  # a maintainer's `setup.py publish` / __main__ release helper
            elif SELF_PUBLISH.search(text):
                self.add(
                    "PY-SELF-PUBLISH",
                    "Publishes packages from code",
                    Severity.HIGH if install or on_import else Severity.MEDIUM,
                    Category.PERSISTENCE,
                    f"`{hit.q}` runs {SELF_PUBLISH.search(text).group(0)!r}: worm-style self-propagation or spam publishing",
                    hit.node,
                    conf=0.7,
                    install=install,
                )
            elif SHELL_DOWNLOAD.search(text):
                sev = Severity.CRITICAL if install or on_import else Severity.HIGH
                rule = "PY-SHELL-EXFIL" if real & (STRONG | {"env:secret", "sysinfo"}) else "PY-SHELL-DOWNLOAD"
                self.add(
                    rule,
                    "Shell command downloads or connects out",
                    sev,
                    Category.DOWNLOADER,
                    f"`{hit.q}` runs a command that fetches remote content or opens a reverse shell: {text[:120]!r}",
                    hit.node,
                    conf=0.85,
                    install=install,
                    evidence={"command": text[:500]},
                )
            elif real & (STRONG | {"env:secret"}) and install:
                self.add(
                    "PY-SHELL-EXFIL",
                    "Secrets passed to a subprocess at install time",
                    Severity.HIGH,
                    Category.EXFILTRATION,
                    f"{self._describe(real)} reach `{hit.q}` during installation{via}",
                    hit.node,
                    conf=0.7,
                    install=install,
                )
            elif install and not hit.via:
                self.add(
                    "PY-INSTALL-SUBPROCESS",
                    "Spawns a process during installation",
                    Severity.INFO,
                    Category.INSTALL_HOOK,
                    f"`{hit.q}` runs while the package is being installed",
                    hit.node,
                    conf=0.4,
                    install=True,
                )

    def _const_text(self, call: ast.Call) -> str:
        parts = []
        for n in ast.walk(call):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                parts.append(n.value)
        return " ".join(parts)

    def _try_decode(self, hit: SinkHit) -> str | None:
        if not hit.node.args:
            return None
        arg = hit.node.args[0]
        val = self.folder.fold(arg)
        if val is None and isinstance(arg, ast.Name):  # exec(payload) where payload = b64decode("...")
            for n in hit.scope.stmts + self.scopes[0].stmts:
                if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == arg.id for t in n.targets):
                    val = self.folder.fold(n.value)
                    if val is not None:
                        break
        if val is None and isinstance(arg, ast.Call) and arg.args:
            val = self.folder.fold(arg.args[0]) if self.qual(arg.func, hit.scope) in DECODERS else None
        if isinstance(val, bytes):
            try:
                if val[:2] in (b"x\x9c", b"x\xda", b"x\x01"):
                    val = zlib.decompress(val)
                val = val.decode("utf-8")
            except Exception:  # noqa: BLE001
                return None
        return val if isinstance(val, str) else None

    def _analyze_layer(self, payload: str, hit: SinkHit, install: bool) -> None:
        depth = self.path.count("<layer")
        if depth >= 3:
            return
        try:
            tree = ast.parse(payload)
        except (SyntaxError, ValueError):
            return
        sub = ModuleAnalysis(
            tree, f"{self.path}<layer{depth + 1}@L{hit.node.lineno}>", payload, install or self.install_time, self.import_time
        )
        sub.imports.update(self.imports)
        sub.run()
        for f in sub.findings:
            f.evidence["unpacked_from"] = f"{self.path}:{hit.node.lineno}"
            f.confidence = min(1.0, f.confidence + 0.05)
        self.findings.extend(sub.findings)

    def _check_call(self, call: ast.Call, scope: Scope) -> None:
        q = self.qual(call.func, scope) or ""
        install, on_import = self._ctx(scope, call)
        # writes downloaded content to disk (dropper)
        file_write = q.endswith(".write_bytes") or (
            q.endswith(".write") and q.startswith(("open()", "io.open()", "builtins.open()", "codecs.open()", "pathlib.Path().open()"))
        )
        if file_write and call.args and "remote" in self.labels(call.args[0], scope):
            self.add(
                "PY-DROPPER",
                "Writes downloaded content to disk",
                Severity.MEDIUM if install or on_import else Severity.LOW,
                Category.DOWNLOADER,
                "data fetched from the network is written to a file",
                call,
                conf=0.7,
                install=install,
            )
        if q.endswith("urlretrieve"):
            self.add(
                "PY-DROPPER",
                "Downloads a file",
                Severity.MEDIUM if install else Severity.LOW,  # native-build setup.py scripts fetch sources; download+run is separate
                Category.DOWNLOADER,
                f"`{q}` saves a remote file locally",
                call,
                conf=0.6,
                install=install,
            )
            runs = [
                n
                for n in scope.stmts
                if isinstance(n, ast.Call)
                and (self.qual(n.func, scope) or "") in SHELL_SINKS
                and n.args
                and not isinstance(n.args[0], ast.Constant)
            ]
            if runs and (install or on_import):
                self.add(
                    "PY-DOWNLOAD-EXECUTE",
                    "Downloads and runs an executable",
                    Severity.CRITICAL,
                    Category.DOWNLOADER,
                    f"a file fetched with `{q}` is executed in the same function (line {runs[0].lineno})",
                    call,
                    conf=0.85,
                    install=install,
                )
        # persistence
        if q in ("open", "io.open", "builtins.open", "codecs.open") or q.endswith(
            (".write_text", ".open", "winreg.SetValueEx", "winreg.SetValue")
        ):
            if q.endswith((".write_text", ".open")) and isinstance(call.func, ast.Attribute):
                path_nodes = [call.func.value]
            elif "winreg" in q:
                path_nodes = list(call.args[:2])
            else:
                path_nodes = list(call.args[:1])
            consts = [n.value for a in path_nodes for n in ast.walk(a) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
            hit = next((c for c in consts if PERSIST_PATH.search(c)), None)
            writes = self._is_write_open(call, q) or q.endswith((".write_text", "SetValueEx", "SetValue"))
            if hit and writes:
                sev = Severity.CRITICAL if "authorized_keys" in hit or install else Severity.HIGH
                if re.search(r"(site|user)customize\.py", hit) and not install:
                    sev = Severity.MEDIUM  # also legitimately written by virtualenv/pip build isolation
                self.add(
                    "PY-PERSISTENCE",
                    "Modifies a persistence location",
                    sev,
                    Category.PERSISTENCE,
                    f"writes to {hit!r}, which runs code at login/startup or grants remote access",
                    call,
                    conf=0.85,
                    install=install,
                )
        if q in SHELL_SINKS:
            text = self._const_text(call)
            if re.search(r"crontab|schtasks\s+/create|launchctl\s+load|systemctl\s+enable|reg\s+add\s+.*\\Run", text, re.I):
                self.add(
                    "PY-PERSISTENCE",
                    "Registers a startup task",
                    Severity.HIGH,
                    Category.PERSISTENCE,
                    f"`{q}` installs a scheduled/startup task: {text[:100]!r}",
                    call,
                    conf=0.8,
                    install=install,
                )
            if q == "subprocess.Popen" and install:
                kws = {k.arg for k in call.keywords}
                if "start_new_session" in kws or "creationflags" in kws or "preexec_fn" in kws:
                    self.add(
                        "PY-DETACHED-PROCESS",
                        "Spawns a detached background process during install",
                        Severity.MEDIUM,
                        Category.INSTALL_HOOK,
                        "a process is started that will outlive the installer",
                        call,
                        conf=0.7,
                        install=True,
                    )
        # obfuscated attribute access: getattr(os, "sys"+"tem")
        if q == "getattr" and len(call.args) >= 2 and not isinstance(call.args[1], ast.Constant):
            if self.folder.fold(call.args[1]) is None and "decoded" in self.labels(call.args[1], scope):
                self.add(
                    "PY-OBFUSCATED-API",
                    "Obfuscated access to a dangerous function",
                    Severity.MEDIUM,
                    Category.OBFUSCATION,
                    "`getattr(...)` with an attribute name that is decoded at runtime",
                    call,
                    conf=0.8,
                    install=install,
                )
            name = self.folder.fold(call.args[1])
            if isinstance(name, str) and name in DANGEROUS_NAMES:
                self.add(
                    "PY-OBFUSCATED-API",
                    "Obfuscated access to a dangerous function",
                    Severity.HIGH,
                    Category.OBFUSCATION,
                    f"`getattr(..., <computed>)` resolves to {name!r}",
                    call,
                    conf=0.85,
                    install=install,
                )
        if (
            q in ("__import__", "importlib.import_module", "builtins.__import__")
            and call.args
            and not isinstance(call.args[0], ast.Constant)
        ):
            name = self.folder.fold(call.args[0])
            if isinstance(name, str):
                self.add(
                    "PY-OBFUSCATED-IMPORT",
                    "Obfuscated import",
                    Severity.MEDIUM,
                    Category.OBFUSCATION,
                    f"module name is computed at runtime and resolves to {name!r}",
                    call,
                    conf=0.8,
                    install=install,
                )
            elif "decoded" in self.labels(call.args[0], scope):
                self.add(
                    "PY-OBFUSCATED-IMPORT",
                    "Obfuscated import",
                    Severity.HIGH,
                    Category.OBFUSCATION,
                    "module name is decoded at runtime",
                    call,
                    conf=0.85,
                    install=install,
                )
        if SHELLCODE.search(q):
            arg_labels = self._call_arg_labels(call, scope)
            loader = bool(arg_labels & {"decoded", "remote"}) or "CreateThread" in self.text or "CreateRemoteThread" in self.text
            self.add(
                "PY-SHELLCODE",
                "Native memory manipulation typical of shellcode loaders",
                Severity.CRITICAL if install and loader else Severity.HIGH if loader else Severity.LOW,
                Category.CODE_EXECUTION,
                f"`{q}` is used to allocate or run executable memory",
                call,
                conf=0.75,
                install=install,
            )
        for prefix, what in SURVEILLANCE.items():
            if q == prefix or q.startswith(prefix + "("):
                sev = Severity.HIGH if what in ("browser cookie theft", "decryption of browser-stored passwords") else Severity.MEDIUM
                self.add(
                    "PY-SURVEILLANCE",
                    f"Performs {what}",
                    _bump(sev) if install or on_import else sev,
                    Category.EXFILTRATION,
                    f"`{q}` enables {what}",
                    call,
                    conf=0.7,
                    install=install,
                )


# --------------------------------------------------------------------------- analyzer


def _setup_py_checks(tree: ast.Module, path: str, text: str) -> list[Finding]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            bases = {ast.unparse(b).split(".")[-1] for b in node.bases}
            hooked = bases & INSTALL_CMD_BASES
            if hooked and any(isinstance(b, ast.FunctionDef) and b.name == "run" for b in node.body):
                out.append(
                    Finding(
                        "PY-SETUP-CMDCLASS",
                        "Custom install command",
                        Severity.LOW,
                        Category.INSTALL_HOOK,
                        f"class {node.name} overrides the `{sorted(hooked)[0]}` command; its run() executes during `pip install`",
                        file=path,
                        line=node.lineno,
                        snippet=snippet_at(text, node.lineno),
                        confidence=0.5,
                        install_time=True,
                    )
                )
    return out


def analyze_python_source(
    text: str, path: str, *, install_time: bool = False, import_time: bool = False, run_as_main: bool = False
) -> tuple[list[Finding], str | None]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as e:
        return [], f"{path}: could not parse ({type(e).__name__})"
    ma = ModuleAnalysis(tree, path, text, install_time, import_time, run_as_main)
    try:
        ma.run()
    except RecursionError:
        return ma.findings, f"{path}: too deeply nested to analyse fully"
    findings = ma.findings
    if path.endswith("setup.py"):
        findings += _setup_py_checks(tree, path, text)
    return findings, None


class PythonTaintAnalyzer:
    name = "python"

    def __init__(self) -> None:
        self.errors: list[str] = []

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for f, text in iter_text_files(ctx, (".py", ".pyw")):
            if len(text) > 2_000_000:
                continue
            res, err = analyze_python_source(
                text,
                f.path,
                install_time=ctx.is_install_time(f.path),
                import_time=f.path in ctx.import_time_files,
                run_as_main=f.path in ctx.script_entry_files,
            )
            findings += res
            if err:
                self.errors.append(err)
        # .pth files: lines starting with `import` are executed on *every* interpreter start-up.
        for f, text in iter_text_files(ctx, (".pth",)):
            code_lines = [(i + 1, ln) for i, ln in enumerate(text.splitlines()) if ln.startswith(("import ", "import\t"))]
            if not code_lines:
                continue
            joined = "\n".join(ln for _, ln in code_lines)
            dangerous = re.search(
                r"b64decode|decompress|exec\((?!\s*['\"])|eval\(|compile\(|urlopen|requests|socket|subprocess|os\.system|__import__\(.{0,20}\+|marshal|fromhex",
                joined,
            )
            namespace_shim = re.search(
                r"has_mfs|__path__|_distutils_hack|importlib\.util|types\.ModuleType|sys\.modules\.setdefault", joined
            )
            if namespace_shim and not dangerous:
                continue
            sev = Severity.HIGH if dangerous else Severity.LOW
            findings.append(
                Finding(
                    "PY-PTH-EXEC",
                    "Executable .pth file",
                    sev,
                    Category.INSTALL_HOOK,
                    ".pth files run on every Python start-up; this one executes code"
                    + (
                        " that decodes, spawns or connects, a known persistence trick"
                        if dangerous
                        else " (common for coverage/instrumentation tools)"
                    ),
                    file=f.path,
                    line=code_lines[0][0],
                    snippet=code_lines[0][1][:160],
                    confidence=0.85,
                    install_time=True,
                )
            )
            res, _ = analyze_python_source(joined, f.path, install_time=True)
            for r in res:
                r.line = code_lines[0][0]
            findings += res
        return findings
