"""Language-agnostic analyzers: install manifests, obfuscation, IOCs, binaries, archive anomalies."""

from __future__ import annotations

import base64
import math
import re
from collections import Counter

from ..models import Category, Finding, Severity
from .base import NPM_LIFECYCLE, ScanContext, iter_text_files, line_of, snippet_at
from .python_taint import SHELL_DOWNLOAD

CODE_SUFFIXES = (".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".sh", ".ps1", ".bat", ".cmd", ".pth", ".rb", ".php")


def shannon_entropy(s: str | bytes) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


# --------------------------------------------------------------------------- manifests


class ManifestAnalyzer:
    """npm lifecycle scripts and Python build configuration."""

    name = "manifest"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        pj = ctx.package_json
        if pj and isinstance(pj.get("scripts"), dict):
            path = ctx.package_json_path
            raw = ctx.contents.get(path).text() if path and ctx.contents.get(path) else ""
            for hook in NPM_LIFECYCLE:
                cmd = pj["scripts"].get(hook)
                if not isinstance(cmd, str):
                    continue
                line = next((i + 1 for i, ln in enumerate((raw or "").splitlines()) if f'"{hook}"' in ln), None)
                benign = re.fullmatch(
                    r"\s*(node-gyp(-build)?( rebuild)?|prebuild-install( \|\| node-gyp rebuild)?.*|husky( install)?|npm run build|tsc|"
                    r"patch-package|node-pre-gyp install.*|opencollective.*|echo .*|ngcc.*|is-ci \|\| husky install)\s*",
                    cmd,
                )
                if hook == "prepare" or hook == "prepublish":
                    sev = Severity.INFO
                elif benign:
                    sev = Severity.INFO
                else:
                    sev = Severity.MEDIUM
                if SHELL_DOWNLOAD.search(cmd):
                    out.append(
                        Finding(
                            "NPM-SCRIPT-DOWNLOAD",
                            "Install script downloads or connects out",
                            Severity.CRITICAL,
                            Category.DOWNLOADER,
                            f"`{hook}` runs: {cmd[:160]}",
                            file=path,
                            line=line,
                            snippet=cmd[:200],
                            confidence=0.9,
                            install_time=True,
                        )
                    )
                    continue
                inline = re.search(r"\bnode\s+(?:-e|--eval|-p|--print)\s+(['\"])(.+)\1", cmd, re.S)
                if inline:
                    from .javascript import analyze_js_source

                    for sub in analyze_js_source(inline.group(2).replace('\\"', '"'), path or "package.json", install_time=True):
                        sub.line, sub.snippet = line, cmd[:200]
                        sub.message += f" (inline `{hook}` script)"
                        out.append(sub)
                if re.search(r"\bnode\s+-e\b|\beval\b|base64|\\x[0-9a-f]{2}|Buffer\.from", cmd):
                    out.append(
                        Finding(
                            "NPM-SCRIPT-INLINE",
                            "Install script runs inline code",
                            Severity.HIGH,
                            Category.INSTALL_HOOK,
                            f"`{hook}` executes inline/encoded JavaScript: {cmd[:160]}",
                            file=path,
                            line=line,
                            snippet=cmd[:200],
                            confidence=0.8,
                            install_time=True,
                        )
                    )
                    continue
                out.append(
                    Finding(
                        "NPM-INSTALL-SCRIPT",
                        f"Runs code on `npm {hook}`",
                        sev,
                        Category.INSTALL_HOOK,
                        f"`{hook}`: {cmd[:160]}",
                        file=path,
                        line=line,
                        snippet=cmd[:200],
                        confidence=0.5,
                        install_time=True,
                    )
                )
            deps = {**(pj.get("dependencies") or {}), **(pj.get("optionalDependencies") or {})}
            for name, spec in deps.items():
                if (
                    isinstance(spec, str)
                    and re.match(r"^(https?://|git(\+\w+)?://|github:|[\w-]+/[\w.-]+(#.*)?$)", spec)
                    and not spec.startswith("npm:")
                ):
                    out.append(
                        Finding(
                            "NPM-REMOTE-DEPENDENCY",
                            "Dependency fetched from a URL",
                            Severity.LOW,
                            Category.METADATA,
                            f"`{name}` resolves to {spec!r}, bypassing the registry and its integrity checks",
                            file=ctx.package_json_path,
                            confidence=0.6,
                        )
                    )
        for f in ctx.contents.find("pyproject.toml")[:1]:
            text = f.text() or ""
            m = re.search(r"^\s*backend-path\s*=", text, re.M)
            if m:
                ln = line_of(text, m.start())
                out.append(
                    Finding(
                        "PY-INTREE-BACKEND",
                        "In-tree build backend",
                        Severity.LOW,
                        Category.INSTALL_HOOK,
                        "the package ships its own PEP 517 build backend, which runs during installation",
                        file=f.path,
                        line=ln,
                        snippet=snippet_at(text, ln),
                        confidence=0.5,
                        install_time=True,
                    )
                )
        return out


# --------------------------------------------------------------------------- obfuscation

_LONG_STRING = re.compile(r"""(['"])([A-Za-z0-9+/=_\-\\x]{200,})\1""")
_HEX_ESC = re.compile(r"(\\x[0-9a-fA-F]{2}){40,}")
_JS_OBFUSCATOR = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
_CODE_HINT = re.compile(
    rb"\bexec\(|\beval\(|^\s*import \w|^\s*from \w+ import|require\(['\"]|subprocess|child_process|powershell|/bin/(ba)?sh|os\.system|__import__",
    re.I | re.M,
)
_BINARY_MAGIC = (b"\x89PNG", b"GIF8", b"\xff\xd8", b"%PDF", b"PK\x03", b"\x00\x00\x01\x00", b"RIFF", b"wOF", b"OTTO", b"\x00\x01\x00\x00")


class ObfuscationAnalyzer:
    name = "obfuscation"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        for f, text in iter_text_files(ctx, CODE_SUFFIXES):
            minified = (
                f.path.endswith((".min.js", ".bundle.js"))
                or any(d in f"/{f.path}" for d in ("/dist/", "/umd/", "/compiled/", "/build/"))
                or (len(text) > 50_000 and len(text) / (text.count("\n") + 1) > 500)
            )
            # 1. encoded blobs that decode to code
            for m in _LONG_STRING.finditer(text):
                blob = m.group(2)
                ent = shannon_entropy(blob)
                decoded = _try_b64(blob)
                ln = line_of(text, m.start())
                if decoded is not None and _CODE_HINT.search(decoded):
                    out.append(
                        Finding(
                            "OBF-ENCODED-CODE",
                            "Encoded code embedded in source",
                            Severity.HIGH,
                            Category.OBFUSCATION,
                            f"a {len(blob)}-char base64 string decodes to executable code",
                            file=f.path,
                            line=ln,
                            snippet=snippet_at(text, ln, 120),
                            confidence=0.85,
                            install_time=ctx.is_install_time(f.path),
                            evidence={"decoded_preview": decoded[:200].decode("utf-8", "replace")},
                        )
                    )
                    break
                if ent > 5.2 and len(blob) > 400 and not minified:
                    out.append(
                        Finding(
                            "OBF-HIGH-ENTROPY",
                            "High-entropy string",
                            Severity.LOW,
                            Category.OBFUSCATION,
                            f"{len(blob)}-char string with entropy {ent:.2f} bits/char (packed or encrypted data)",
                            file=f.path,
                            line=ln,
                            snippet=snippet_at(text, ln, 100),
                            confidence=0.4,
                            install_time=ctx.is_install_time(f.path),
                        )
                    )
                    break
            # 2. hex-escape walls
            m = _HEX_ESC.search(text)
            if m:
                ln = line_of(text, m.start())
                out.append(
                    Finding(
                        "OBF-HEX-ESCAPES",
                        "Long hex-escaped string",
                        Severity.MEDIUM,
                        Category.OBFUSCATION,
                        "a long run of \\xNN escapes hides the real string content",
                        file=f.path,
                        line=ln,
                        snippet=snippet_at(text, ln, 100),
                        confidence=0.6,
                        install_time=ctx.is_install_time(f.path),
                    )
                )
            # 3. javascript-obfuscator signature
            if f.suffix in (".js", ".mjs", ".cjs"):
                ids = set(_JS_OBFUSCATOR.findall(text))
                if len(ids) >= 15:
                    out.append(
                        Finding(
                            "OBF-JS-OBFUSCATOR",
                            "javascript-obfuscator output",
                            Severity.HIGH if not minified else Severity.MEDIUM,
                            Category.OBFUSCATION,
                            f"{len(ids)} `_0x\u2026` identifiers: code was deliberately obfuscated",
                            file=f.path,
                            line=line_of(text, text.find(next(iter(ids)))),
                            confidence=0.8,
                            install_time=ctx.is_install_time(f.path),
                        )
                    )
            # 4. hidden code: very long single line in a hand-written source file, or code pushed far right
            if not minified:
                for i, line in enumerate(text.splitlines(), 1):
                    if len(line) > 200 and re.match(r"^\S.{0,150}?\s{150,}\S", line):
                        out.append(
                            Finding(
                                "OBF-WHITESPACE-HIDING",
                                "Code hidden off-screen",
                                Severity.HIGH,
                                Category.OBFUSCATION,
                                "statement padded with hundreds of spaces so it is invisible in editors and diffs",
                                file=f.path,
                                line=i,
                                snippet=line.strip()[:160],
                                confidence=0.85,
                                install_time=ctx.is_install_time(f.path),
                            )
                        )
                        break
            # 5. Unicode tricks: bidi overrides (Trojan Source) and invisible characters
            m = re.search("[\u202a-\u202e\u2066-\u2069]", text)
            if m:
                ln = line_of(text, m.start())
                out.append(
                    Finding(
                        "OBF-BIDI",
                        "Bidirectional control characters (Trojan Source)",
                        Severity.HIGH,
                        Category.OBFUSCATION,
                        "Unicode direction overrides make code render differently from how it executes (CVE-2021-42574)",
                        file=f.path,
                        line=ln,
                        snippet=repr(snippet_at(text, ln, 100)),
                        confidence=0.8,
                    )
                )
            m = re.search("[\u200b\u200c\u200d\u2060\ufeff\u3164\uffa0]", text[1:])
            ln = line_of(text, m.start() + 1) if m else 0
            if m and f.suffix in (".py", ".js", ".mjs", ".cjs") and not minified and _invisible_in_code(text, ln):
                out.append(
                    Finding(
                        "OBF-INVISIBLE-CHARS",
                        "Invisible characters in code",
                        Severity.MEDIUM,
                        Category.OBFUSCATION,
                        "zero-width / Hangul filler characters can create look-alike identifiers",
                        file=f.path,
                        line=ln,
                        snippet=repr(snippet_at(text, ln, 100)),
                        confidence=0.6,
                    )
                )
        return out


_STR_LIT = re.compile(r"""(['"`])(?:\\.|(?!\1).)*\1""")
_INVISIBLE = re.compile("[\u200b\u200c\u200d\u2060\u3164\uffa0]")


def _invisible_in_code(text: str, first_line: int) -> bool:
    """True if an invisible character appears outside string literals and comments (i.e. in an identifier)."""
    checked = 0
    for line in text.splitlines()[first_line - 1 :]:
        if not _INVISIBLE.search(line):
            continue
        checked += 1
        if checked > 200 or len(line) > 4000:  # minified data tables: not hand-written identifiers
            continue
        code = _STR_LIT.sub("", line).split("#")[0].split("//")[0]
        if _INVISIBLE.search(code):
            return True
    return False


def _try_b64(s: str) -> bytes | None:
    if "\\x" in s:
        return None
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
    except Exception:  # noqa: BLE001
        return None
    if not raw or raw.startswith(_BINARY_MAGIC):
        return None
    try:
        import zlib

        if raw[:2] in (b"x\x9c", b"x\xda", b"x\x01"):
            raw = zlib.decompress(raw)
    except Exception:  # noqa: BLE001
        pass
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in raw[:2000]) / max(1, min(len(raw), 2000))
    return raw if printable > 0.9 else None


# --------------------------------------------------------------------------- indicators of compromise

IOC_PATTERNS: list[tuple[str, re.Pattern, Severity, str]] = [
    (
        "IOC-DISCORD-WEBHOOK",
        re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/[\w-]+", re.I),
        Severity.HIGH,
        "Discord webhook (common exfiltration drop)",
    ),
    ("IOC-TELEGRAM-BOT", re.compile(r"api\.telegram\.org/bot\d+:[\w-]+", re.I), Severity.HIGH, "Telegram bot API with embedded token"),
    (
        "IOC-PASTE-SITE",
        re.compile(
            r"https?://(?:www\.)?(?:pastebin\.com/raw|paste\.ee/r|hastebin\.com/raw|rentry\.co/\w+/raw|ghostbin\.\w+|controlc\.com|dpaste\.\w+/\w+/raw)",
            re.I,
        ),
        Severity.MEDIUM,
        "raw paste-site URL (payload staging)",
    ),
    (
        "IOC-TUNNEL",
        re.compile(
            r"https?://(?:[\w-]{1,63}\.){0,6}(?:ngrok\.io|ngrok-free\.app|ngrok\.app|serveo\.net|loca\.lt|trycloudflare\.com|localhost\.run)",
            re.I,
        ),
        Severity.HIGH,
        "ephemeral tunnel endpoint",
    ),
    (
        "IOC-OAST",
        re.compile(
            r"(?<![\w.-])(?:[\w-]{1,63}\.){0,6}(?:burpcollaborator\.net|oastify\.com|interact\.sh|oast\.(?:fun|live|me|online|pro|site)|dnslog\.cn|ceye\.io|canarytokens\.com|requestbin\.net|pipedream\.net|webhook\.site|beeceptor\.com)",
            re.I,
        ),
        Severity.HIGH,
        "out-of-band interaction / request-capture service",
    ),
    (
        "IOC-FILE-DROP",
        re.compile(r"https?://(?:transfer\.sh|file\.io|anonfiles\.com|gofile\.io|bashupload\.com|temp\.sh|0x0\.st)", re.I),
        Severity.MEDIUM,
        "anonymous file-sharing service",
    ),
    ("IOC-ONION", re.compile(r"\b[a-z2-7]{56}\.onion\b"), Severity.HIGH, "Tor hidden service address"),
    (
        "IOC-RAW-IP-URL",
        re.compile(
            r"https?://(?!(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0|169\.254\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.))(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|\b)"
        ),
        Severity.MEDIUM,
        "URL pointing at a raw public IP address",
    ),
    (
        "IOC-DISCORD-TOKEN-REGEX",
        re.compile(r"\[\\w-\]\{24(?:,26)?\}\\\.\[\\w-\]\{6\}\\\.\[\\w-\]\{(?:25,110|27|38)\}|mfa\\\.\[\\w-\]\{84\}|dQw4w9WgXcQ:"),
        Severity.CRITICAL,
        "Discord token-grabbing regular expression",
    ),
    (
        "IOC-CRYPTO-CLIPPER",
        re.compile(
            r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b.{0,200}(?:clipboard|pyperclip|clipboardy)|(?:clipboard|pyperclip|clipboardy).{0,200}\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b",
            re.I | re.S,
        ),
        Severity.HIGH,
        "cryptocurrency address together with clipboard access (clipper malware)",
    ),
]


# Cheap substring checks that must pass before an expensive regex runs.
IOC_PREFILTER = {
    "IOC-DISCORD-WEBHOOK": ("webhooks",),
    "IOC-TELEGRAM-BOT": ("api.telegram.org",),
    "IOC-ONION": (".onion",),
    "IOC-CRYPTO-CLIPPER": ("clipboard", "pyperclip", "clipboardy"),
    "IOC-DISCORD-TOKEN-REGEX": ("{24", "dqw4w9wgxcq"),
    "IOC-TUNNEL": ("ngrok", "serveo", "loca.lt", "trycloudflare", "localhost.run"),
    "IOC-RAW-IP-URL": ("http",),
    "IOC-OAST": (
        "burpcollaborator",
        "oastify",
        "interact.sh",
        "oast.",
        "dnslog",
        "ceye",
        "canarytokens",
        "requestbin",
        "pipedream",
        "webhook.site",
        "beeceptor",
    ),
    "IOC-PASTE-SITE": ("paste", "rentry", "ghostbin", "controlc"),
    "IOC-FILE-DROP": ("transfer.sh", "file.io", "anonfiles", "gofile", "bashupload", "temp.sh", "0x0.st"),
}


RAW_SOCKET_USE = re.compile(
    r"""require\(\s*['"](node:)?(net|tls|dgram)['"]\s*\)|from\s+['"](node:)?(net|tls)['"]|\bsocket\.socket\(|\bsocket\.create_connection\("""
)
QUOTED_IP = re.compile(r"""['"]((?:\d{1,3}\.){3}\d{1,3})['"]""")


def _public_ip(ip: str) -> bool:
    import ipaddress

    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    doc = any(a in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
    return a.is_global and not doc


class LineIndex:
    """O(log n) offset -> line lookups (snippet_at/line_of are O(n) per call)."""

    def __init__(self, text: str) -> None:
        import bisect

        self._bisect = bisect.bisect_right
        self.text = text
        self.starts = [0]
        pos = text.find("\n")
        while pos != -1:
            self.starts.append(pos + 1)
            pos = text.find("\n", pos + 1)

    def line_of(self, offset: int) -> int:
        return self._bisect(self.starts, offset)

    def line_text(self, line: int) -> str:
        start = self.starts[line - 1]
        end = self.starts[line] - 1 if line < len(self.starts) else len(self.text)
        return self.text[start:end]


STRONG_IOCS = {"IOC-DISCORD-WEBHOOK", "IOC-TELEGRAM-BOT", "IOC-DISCORD-TOKEN-REGEX", "IOC-CRYPTO-CLIPPER", "IOC-ONION"}


def _in_docstring(text: str, pos: int) -> bool:
    """Cheap check: an odd number of triple quotes before pos means we are inside one."""
    before = text[max(0, pos - 20000) : pos]
    return (before.count('"""') + before.count("'''")) % 2 == 1


class IOCAnalyzer:
    name = "ioc"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        for f, text in iter_text_files(ctx):
            is_code = f.suffix in CODE_SUFFIXES or f.name in ("package.json", "setup.cfg")
            if not is_code and f.suffix not in (".json", ".cfg", ".toml", ".txt", ".yml", ".yaml", ""):
                continue
            if f.name.lower().startswith(("readme", "changelog", "changes", "history", "license", "authors")):
                continue
            idx = LineIndex(text)
            lower = text.lower()
            if is_code and RAW_SOCKET_USE.search(text):
                for m_ip in QUOTED_IP.finditer(text):
                    ip = m_ip.group(1)
                    if _public_ip(ip):
                        ln = idx.line_of(m_ip.start())
                        out.append(
                            Finding(
                                "IOC-RAW-IP-SOCKET",
                                "Hard-coded IP with raw socket use",
                                Severity.MEDIUM if not ctx.is_install_time(f.path) else Severity.HIGH,
                                Category.IOC,
                                f"public IP {ip} is hard-coded in a file that opens raw sockets (typical of reverse shells/RATs)",
                                file=f.path,
                                line=ln,
                                snippet=idx.line_text(ln).strip()[:140],
                                confidence=0.7,
                                install_time=ctx.is_install_time(f.path),
                                evidence={"indicator": ip},
                            )
                        )
                        break
            for rule, rx, sev, desc in IOC_PATTERNS:
                pre = IOC_PREFILTER.get(rule)
                if pre and not any(k in lower for k in pre):
                    continue
                m = None
                for n_cand, cand in enumerate(rx.finditer(text)):
                    if n_cand > 50:
                        break
                    src_line = idx.line_text(idx.line_of(cand.start())).strip()
                    if src_line.startswith(("#", "//", "*", "/*", ">>>", "..", "-", "`")) or _in_docstring(text, cand.start()):
                        continue
                    m = cand
                    break
                if not m:
                    continue
                ln = idx.line_of(m.start())
                if rule not in STRONG_IOCS:
                    sev = min(sev, Severity.MEDIUM)
                s = sev if is_code else Severity(max(0, int(sev) - 1))
                if ctx.is_install_time(f.path) and s < Severity.CRITICAL:
                    s = Severity(int(s) + 1)
                conf = (0.85 if rule in STRONG_IOCS else 0.7) if is_code else 0.5
                out.append(
                    Finding(
                        rule,
                        desc[0].upper() + desc[1:],
                        s,
                        Category.IOC,
                        f"{desc}: {m.group(0)[:100]}",
                        file=f.path,
                        line=ln,
                        snippet=idx.line_text(ln).strip()[:140],
                        confidence=conf,
                        install_time=ctx.is_install_time(f.path),
                        evidence={"indicator": m.group(0)[:200]},
                    )
                )
        return out


# --------------------------------------------------------------------------- binaries

MAGIC = [
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE"),
    (b"\xcf\xfa\xed\xfe", "Mach-O"),
    (b"\xce\xfa\xed\xfe", "Mach-O"),
    (b"\xca\xfe\xba\xbe", "Mach-O (universal)"),
]
NATIVE_LIB_EXT = (".so", ".pyd", ".dll", ".dylib", ".node", ".a", ".lib", ".o", ".wasm")


SECRET_HUNT = re.compile(
    r"trufflehog|NPM_TOKEN|GITHUB_TOKEN|AWS_ACCESS_KEY_ID|\.npmrc|gh auth token|ACTIONS_RUNTIME_TOKEN|registry\.npmjs\.org/-/whoami", re.I
)


class BinaryAnalyzer:
    name = "binary"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        install_texts = [(p, (ctx.contents.get(p).text() or "")[:2_000_000]) for p in ctx.install_time_files if ctx.contents.get(p)]
        # large payloads executed during installation (legit install hooks are tiny: node-gyp, husky, prebuild)
        for p, text in install_texts:
            pf = ctx.contents.get(p)
            if pf.suffix in (".js", ".cjs", ".mjs") and pf.size > 1_000_000:
                hunt = SECRET_HUNT.findall(text)
                out.append(
                    Finding(
                        "NPM-LARGE-INSTALL-PAYLOAD",
                        "Large bundle executed at install time",
                        Severity.CRITICAL if len(set(h.lower() for h in hunt)) >= 2 else Severity.HIGH,
                        Category.INSTALL_HOOK,
                        f"{p} ({pf.size:,} bytes) runs during `npm install`"
                        + (f" and references credential stores/tokens ({', '.join(sorted(set(hunt))[:4])})" if hunt else ""),
                        file=p,
                        confidence=0.8,
                        install_time=True,
                    )
                )
        is_wheel = any(f.path.endswith(".dist-info/WHEEL") for f in ctx.contents)
        for f in ctx.contents:
            head = f.data[:64]
            kind = next((k for magic, k in MAGIC if head.startswith(magic)), None)
            if kind is None or (kind == "PE" and b"PE\x00\x00" not in f.data[:1024] and len(f.data) > 64):
                continue
            ext = f.suffix
            name_lower = f.name.lower()
            stem = f.name.rsplit(".", 1)[0]
            loader = next(
                (
                    p
                    for p, t in install_texts
                    if p != f.path and len(stem) >= 4 and (f.name in t or f"'{stem}" in t or f'"{stem}' in t or f"/{stem}" in t)
                ),
                None,
            )
            disguised_ext = (".png", ".jpg", ".jpeg", ".gif", ".txt", ".json", ".md", ".css", ".py", ".js", ".ttf", ".woff", ".ico", ".svg")
            if loader and ext not in (".node",) and ext not in disguised_ext:
                out.append(
                    Finding(
                        "BIN-LOADED-AT-INSTALL",
                        "Install script runs a bundled binary",
                        Severity.HIGH,
                        Category.BINARY,
                        f"{loader} references the bundled {kind} binary {f.path}, which cannot be reviewed as source",
                        file=f.path,
                        confidence=0.8,
                        install_time=True,
                    )
                )
                continue
            if ext in NATIVE_LIB_EXT or ".so." in name_lower or ".cpython-" in name_lower:
                if not is_wheel and ctx.ecosystem == "pypi" and ext in (".so", ".pyd", ".dll", ".dylib"):
                    out.append(
                        Finding(
                            "BIN-PREBUILT-IN-SDIST",
                            "Prebuilt native library in source distribution",
                            Severity.LOW,
                            Category.BINARY,
                            f"{kind} binary shipped in an sdist cannot be reviewed from source",
                            file=f.path,
                            confidence=0.5,
                        )
                    )
                continue
            if ext in disguised_ext:
                out.append(
                    Finding(
                        "BIN-DISGUISED",
                        "Executable disguised as another file type",
                        Severity.CRITICAL,
                        Category.BINARY,
                        f"{f.path} has a {ext} extension but is a {kind} executable",
                        file=f.path,
                        confidence=0.95,
                    )
                )
                continue
            sev = Severity.MEDIUM if ext in (".scr", ".com") else Severity.LOW
            out.append(
                Finding(
                    "BIN-EXECUTABLE",
                    "Bundled executable",
                    sev,
                    Category.BINARY,
                    f"package ships a {kind} executable ({f.size:,} bytes)",
                    file=f.path,
                    confidence=0.6,
                )
            )
        return out


class ArchiveAnomalyAnalyzer:
    name = "archive"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        out = []
        for a in ctx.contents.anomalies:
            sev = Severity.HIGH if a.kind in ("path traversal", "absolute path", "link escapes package", "device file") else Severity.MEDIUM
            if a.kind == "symlink":
                sev = Severity.LOW
            out.append(
                Finding(
                    "ARCHIVE-" + a.kind.upper().replace(" ", "-"),
                    f"Archive anomaly: {a.kind}",
                    sev,
                    Category.METADATA,
                    f"{a.path}: {a.detail}",
                    file=a.path,
                    confidence=0.8,
                )
            )
        if ctx.contents.limit_hit:
            out.append(
                Finding(
                    "ARCHIVE-LIMIT",
                    "Scan limits reached",
                    Severity.INFO,
                    Category.METADATA,
                    "archive exceeded size/member limits; part of it was not analysed",
                    confidence=1.0,
                )
            )
        return out
