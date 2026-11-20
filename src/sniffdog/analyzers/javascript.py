"""Taint analysis for JavaScript using a real parser (tree-sitter).

Same label vocabulary as the Python analyzer. JS-specific twists:

* ``require`` / ES ``import`` aliases are resolved (``const {exec: run} = require('child_process')``).
* Objects are typed by their constructor so ``req.write(data)`` is recognised
  as a network sink when ``req = https.request(...)``.
* Callback parameters inherit the labels of the call they are passed to, which
  is how data arrives in Node (``https.get(u, res => res.on('data', d => eval(d)))``).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from ..models import Category, Finding, Severity
from .base import ScanContext, iter_text_files, snippet_at
from .python_taint import LOLBIN, PERSIST_PATH, SECRET_ENV_NAME, SELF_PUBLISH, SENSITIVE_PATH, SHELL_DOWNLOAD

try:  # pragma: no cover - import guard
    import tree_sitter as _ts
    import tree_sitter_javascript as _tsjs

    _LANG = _ts.Language(_tsjs.language())
except Exception:  # noqa: BLE001
    _LANG = None

FUNC_TYPES = {
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
    "generator_function",
}

SYSINFO = {"os.hostname", "os.userInfo", "os.homedir", "os.networkInterfaces", "os.tmpdir().constructor"}
DECODERS = {
    "atob",
    "zlib.inflateSync",
    "zlib.gunzipSync",
    "zlib.inflateRawSync",
    "zlib.brotliDecompressSync",
    "crypto.createDecipheriv",
    "crypto.createDecipher",
}
LIB_SINK_ROOTS = {"axios", "got", "superagent", "needle", "request", "undici", "phin", "node-fetch", "cross-fetch", "isomorphic-fetch"}
FILE_READ = re.compile(
    r"^(fs|fs\.promises|fs/promises|fs-extra)\.(readFileSync|readFile|createReadStream|readdirSync|readdir|copyFileSync|copyFile)$"
)
FILE_WRITE = re.compile(r"^(fs|fs\.promises|fs/promises|fs-extra)\.(writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream)$")
NET_SINK = [
    re.compile(r"^(https?|http2)\.(request|get)$"),
    re.compile(r"^(https?|http2)\.(request|get)\(\)\.(write|end)$"),
    re.compile(r"^(node-fetch|undici)?\.?fetch$"),
    re.compile(r"^(node-fetch|cross-fetch|isomorphic-fetch|axios|got|needle|superagent)$"),
    re.compile(r"^(axios|got|superagent|needle|request|undici|phin)(\.(get|post|put|patch|request|delete|default))?$"),
    re.compile(r"^(net|tls)\.(connect|createConnection)$"),
    re.compile(r"^(net|tls)\.(connect|createConnection|Socket)\(\)\.(write|end|connect)$"),
    re.compile(r"^dgram\.createSocket\(\)\.send$"),
    re.compile(r"^XMLHttpRequest\(\)\.send$"),
    re.compile(r"^(ws|WebSocket)\(\)\.send$"),
    re.compile(r"^navigator\.sendBeacon$"),
]
NET_FETCH = [
    re.compile(r"^(net|tls)\.(connect|createConnection|Socket\(\))$"),
    re.compile(r"^(net|tls)\.Socket$"),
    re.compile(r"^(ws|WebSocket)$"),
    re.compile(r"^(https?)\.(get|request)$"),
    re.compile(r"^(node-)?fetch$"),
    re.compile(r"^(cross|isomorphic)-fetch$"),
    re.compile(r"^(axios|got|needle)(\.(get|request))?$"),
]
DNS_SINK = re.compile(r"^dns(\.promises)?\.(lookup|resolve|resolve4|resolve6|resolveTxt|resolveCname|resolveAny)$")
EXEC_SINK = {
    "eval",
    "Function",
    "Function()",
    "vm.runInNewContext",
    "vm.runInThisContext",
    "vm.runInContext",
    "vm.Script",
    "vm.Script()",
    "vm.compileFunction",
    "setTimeout",
    "setInterval",
    "module.constructor()._compile",
    "module._compile",
}
SHELL_SINK = re.compile(r"^child_process\.(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)$")
JS_GLOBALS = {
    "process",
    "console",
    "module",
    "exports",
    "require",
    "global",
    "globalThis",
    "window",
    "self",
    "document",
    "Buffer",
    "JSON",
    "Object",
    "Array",
    "Math",
    "Promise",
    "Reflect",
    "Symbol",
    "Error",
    "String",
    "Number",
}
SENSITIVE_MODULES = {"child_process", "fs", "net", "http", "https", "os", "dns", "vm", "tls", "dgram", "crypto", "fs/promises"}
REAL = {"env:all", "env:secret", "env:var", "cred", "sysinfo", "userfiles"}
STRONG = {"env:all", "cred"}


def _bump(s: Severity, n: int = 1) -> Severity:
    return Severity(min(int(s) + n, int(Severity.CRITICAL)))


def _str_value(node) -> str | None:
    if node is None:
        return None
    if node.type == "string":
        return "".join(c.text.decode("utf-8", "replace") for c in node.children if c.type in ("string_fragment", "escape_sequence"))
    if node.type == "template_string":
        if any(c.type == "template_substitution" for c in node.children):
            return None
        return "".join(c.text.decode("utf-8", "replace") for c in node.children if c.type == "string_fragment")
    if node.type == "binary_expression" and node.child_by_field_name("operator") and node.child_by_field_name("operator").type == "+":
        a, b = _str_value(node.child_by_field_name("left")), _str_value(node.child_by_field_name("right"))
        return a + b if a is not None and b is not None else None
    if node.type == "parenthesized_expression" and node.named_child_count == 1:
        return _str_value(node.named_children[0])
    return None


@dataclass
class _Hit:
    kind: str
    q: str
    node: object
    labels: set[str]


PACKAGE_JS_BUDGET_S = 45.0


def _is_bundle(f) -> bool:
    """Large build output (webpack/rollup/esbuild) rather than hand-written source."""
    if len(f.data) > 256_000:
        return True
    lines = f.data.count(b"\n") + 1
    return len(f.data) > 50_000 and len(f.data) / lines > 500


class AnalysisBudgetExceeded(Exception):
    pass


class JSFileAnalysis:
    def __init__(self, src: bytes, path: str, install_time: bool, import_time: bool, budget_s: float = 10.0, bundle_mode: bool = False):
        # bundle_mode: huge build outputs get conservative propagation (no context-insensitive parameter
        # binding / container smearing); their flows are reported as capped "capability" evidence.
        self.bundle_mode = bundle_mode
        self.src = src
        self.text = src.decode("utf-8", "replace")
        self.path = path
        self.install_time = install_time
        self.import_time = import_time
        parser = _ts.Parser(_LANG)
        self.tree = parser.parse(src)
        self.aliases: dict[tuple[int, str], str] = {}  # (scope, name) -> qualified name
        self.taint: dict[tuple[int, str], set[str]] = {}
        self.declared: dict[int, set[str]] = {0: set()}
        self.func_returns: dict[str, set[str]] = {}
        self.findings: list[Finding] = []
        self._seen: set = set()
        self.nodes = list(self._walk(self.tree.root_node))
        self._scope_cache: dict[tuple[int, str], int] = {}
        self._ops = 0
        self.deadline = time.monotonic() + budget_s

    # ------------------------------------------------------------- traversal helpers

    @staticmethod
    def _walk(root):
        stack = [root]
        while stack:
            n = stack.pop()
            yield n
            stack.extend(reversed(n.children))

    def t(self, node) -> str:
        return node.text.decode("utf-8", "replace") if node is not None else ""

    def scope_of(self, node) -> int:
        p = node.parent
        while p is not None:
            if p.type in FUNC_TYPES:
                return p.id
            p = p.parent
        return 0

    def enclosing_func(self, node):
        p = node.parent
        while p is not None:
            if p.type in FUNC_TYPES:
                return p
            p = p.parent
        return None

    def resolve_scope(self, node, name: str) -> int:
        key = (node.id, name)
        hit = self._scope_cache.get(key)
        if hit is not None:
            return hit
        p, sc = node, 0
        while p is not None:
            if p.type in FUNC_TYPES and name in self.declared.get(p.id, ()):
                sc = p.id
                break
            p = p.parent
        self._scope_cache[key] = sc
        return sc

    def _tick(self) -> None:
        self._ops += 1
        if self._ops & 0x3FF == 0 and time.monotonic() > self.deadline:
            raise AnalysisBudgetExceeded(self.path)

    # ------------------------------------------------------------- declarations / aliases

    def _param_names(self, fn) -> list:
        params = fn.child_by_field_name("parameters") or fn.child_by_field_name("parameter")
        if params is None:
            return []
        if params.type == "identifier":
            return [params]
        out = []
        for c in params.named_children:
            if c.type == "identifier":
                out.append(c)
            elif c.type == "assignment_pattern" and c.child_by_field_name("left") is not None:
                out.append(c.child_by_field_name("left"))
            else:
                out.append(None)
        return out

    def declare_pass(self) -> None:
        self.funcs: dict[str, object] = {}
        for n in self.nodes:
            if n.type in ("function_declaration", "generator_function_declaration") and n.child_by_field_name("name") is not None:
                self.funcs.setdefault(self.t(n.child_by_field_name("name")), n)
            elif n.type == "variable_declarator":
                v = n.child_by_field_name("value")
                nm = n.child_by_field_name("name")
                if v is not None and v.type in ("function_expression", "arrow_function") and nm is not None and nm.type == "identifier":
                    self.funcs.setdefault(self.t(nm), v)
        for n in self.nodes:
            if n.type in FUNC_TYPES:
                names = self.declared.setdefault(n.id, set())
                params = n.child_by_field_name("parameters") or n.child_by_field_name("parameter")
                if params is not None:
                    for p in self._walk(params):
                        if p.type in ("identifier", "shorthand_property_identifier_pattern"):
                            names.add(self.t(p))
            elif n.type == "variable_declarator":
                sc = self.scope_of(n)
                name = n.child_by_field_name("name")
                for p in self._walk(name):
                    if p.type in ("identifier", "shorthand_property_identifier_pattern"):
                        self.declared.setdefault(sc, set()).add(self.t(p))

    def _module_of_require(self, node) -> str | None:
        if node is None:
            return None
        if node.type == "await_expression" and node.named_child_count:
            node = node.named_children[0]
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if fn is not None and self.t(fn) in ("require", "import") and args is not None and args.named_child_count:
                return _str_value(args.named_children[0])
        return None

    def alias_pass(self) -> None:
        for n in self.nodes:
            if n.type == "import_statement":
                src = n.child_by_field_name("source")
                mod = _str_value(src)
                if not mod:
                    continue
                mod = mod.removeprefix("node:")
                for c in self._walk(n):
                    if c.type == "import_clause":
                        for cc in c.named_children:
                            if cc.type == "identifier":
                                self.aliases[(0, self.t(cc))] = mod
                            elif cc.type == "namespace_import":
                                for x in cc.named_children:
                                    if x.type == "identifier":
                                        self.aliases[(0, self.t(x))] = mod
                    elif c.type == "import_specifier":
                        name = c.child_by_field_name("name")
                        alias = c.child_by_field_name("alias") or name
                        self.aliases[(0, self.t(alias))] = f"{mod}.{self.t(name)}"
            elif n.type == "variable_declarator":
                name = n.child_by_field_name("name")
                value = n.child_by_field_name("value")
                sc = self.scope_of(n)
                mod = self._module_of_require(value)
                base = None
                if mod:
                    base = mod.removeprefix("node:")
                elif value is not None and value.type in (
                    "member_expression",
                    "identifier",
                    "new_expression",
                    "call_expression",
                    "await_expression",
                ):
                    base = self.qual(value)
                if base is None or name is None:
                    continue
                if name.type == "identifier":
                    if value is not None and value.type in ("call_expression", "new_expression", "await_expression") and not mod:
                        self.aliases[(sc, self.t(name))] = base if base.endswith("()") else base + "()"
                    else:
                        self.aliases[(sc, self.t(name))] = base
                elif name.type == "object_pattern":
                    for c in name.named_children:
                        if c.type == "shorthand_property_identifier_pattern":
                            self.aliases[(sc, self.t(c))] = f"{base}.{self.t(c)}"
                        elif c.type == "pair_pattern":
                            k, v = c.child_by_field_name("key"), c.child_by_field_name("value")
                            if v is not None and v.type == "identifier":
                                self.aliases[(sc, self.t(v))] = f"{base}.{self.t(k)}"
            elif n.type == "assignment_expression":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if left is not None and left.type == "identifier" and right is not None:
                    mod = self._module_of_require(right)
                    sc = self.resolve_scope(n, self.t(left))
                    if mod:
                        self.aliases[(sc, self.t(left))] = mod
                    elif right.type in ("call_expression", "new_expression"):
                        q = self.qual(right)
                        if q:
                            self.aliases[(sc, self.t(left))] = q if q.endswith("()") else q + "()"

    def qual(self, node) -> str | None:
        if node is None:
            return None
        t = node.type
        if t == "identifier":
            name = self.t(node)
            sc = self.resolve_scope(node, name)
            return self.aliases.get((sc, name)) or self.aliases.get((0, name)) or name
        if t == "member_expression":
            base = self.qual(node.child_by_field_name("object"))
            prop = node.child_by_field_name("property")
            if base is None or prop is None:
                return None
            if base in ("global", "globalThis", "window"):
                return self.t(prop)
            return f"{base}.{self.t(prop)}"
        if t == "subscript_expression":
            base = self.qual(node.child_by_field_name("object"))
            idx = _str_value(node.child_by_field_name("index"))
            if base and idx:
                return idx if base in ("global", "globalThis", "window") else f"{base}.{idx}"
            return f"{base}[]" if base else None
        if t == "call_expression":
            mod = self._module_of_require(node)
            if mod:
                return mod.removeprefix("node:")
            f = self.qual(node.child_by_field_name("function"))
            return f + "()" if f else None
        if t == "new_expression":
            f = self.qual(node.child_by_field_name("constructor"))
            return f + "()" if f else None
        if t == "parenthesized_expression" and node.named_child_count == 1:
            return self.qual(node.named_children[0])
        if t == "await_expression" and node.named_child_count:
            return self.qual(node.named_children[0])
        return None

    # ------------------------------------------------------------- labels

    def _env_label(self, node) -> str | None:
        p = node.parent
        if p is None:
            return "env:all"
        if p.type == "member_expression" and p.child_by_field_name("object") == node:
            prop = self.t(p.child_by_field_name("property"))
            return "env:secret" if SECRET_ENV_NAME.search(prop) else "env:var"
        if p.type == "subscript_expression" and p.child_by_field_name("object") == node:
            key = _str_value(p.child_by_field_name("index"))
            return "env:secret" if key and SECRET_ENV_NAME.search(key) else "env:var"
        if p.type in ("binary_expression",) and "in" in self.t(p):
            return None
        if p.type == "arguments" and p.parent is not None:
            fq = self.qual(p.parent.child_by_field_name("function")) or ""
            if fq == "Object.keys":
                return "env:var"
        if p.type == "pair" and self.t(p.child_by_field_name("key")) == "env":
            obj = p.parent
            call = obj.parent.parent if obj is not None and obj.parent is not None and obj.parent.type == "arguments" else None
            if call is not None and SHELL_SINK.search(self.qual(call.child_by_field_name("function")) or ""):
                return None  # spawn(cmd, {env: process.env}) passes env to a child, not exfil
        return "env:all"

    def labels(self, expr) -> set[str]:
        out: set[str] = set()
        if expr is None:
            return out
        for n in self._walk(expr):
            self._tick()
            t = n.type
            if t in ("identifier", "shorthand_property_identifier"):
                name = self.t(n)
                sc = self.resolve_scope(n, name)
                out |= self.taint.get((sc, name), set())
                if sc != 0:
                    continue
                out |= self.taint.get((0, name), set())
            elif t == "member_expression":
                q = self.qual(n)
                if q == "process.env":
                    lab = self._env_label(n)
                    if lab:
                        out.add(lab)
            elif t in ("call_expression", "new_expression"):
                out |= self._call_labels(n)
            elif t in ("string", "template_string"):
                s = self.t(n)
                if len(s) < 512 and SENSITIVE_PATH.search(s):
                    out.add("senspath")
        return out

    def _args(self, call):
        a = call.child_by_field_name("arguments")
        return [c for c in a.named_children if c.type != "comment"] if a is not None else []

    def _call_labels(self, call) -> set[str]:
        out: set[str] = set()
        fn = call.child_by_field_name("function") or call.child_by_field_name("constructor")
        q = self.qual(fn) or ""
        args = self._args(call)
        if q in SYSINFO:
            out.add("sysinfo")
        if q in DECODERS or q.endswith(("Decipheriv().update", "Decipher().update")):
            out.add("decoded")
        # fromCharCode is everywhere in lexers/encoders; a wall of numeric literals is the obfuscation idiom
        if q.endswith(".fromCharCode") and (
            sum(a.type == "number" for a in args) >= 8 or (args and args[0].type == "spread_element" and "[" in self.t(args[0])[:4])
        ):
            out.add("decoded")
        if q in ("Buffer.from", "Buffer") and len(args) > 1 and (_str_value(args[1]) or "").lower() in ("base64", "hex", "base64url"):
            out.add("decoded")
        if q.endswith(".reverse().join") or (q.endswith(".join") and ".reverse()" in q):
            out.add("decoded")
        if any(p.search(q) for p in NET_FETCH) or q.endswith((".json", ".text")) and "fetch" in q:
            out.add("remote")
        if FILE_READ.search(q):
            al = set()
            for a in args[:1]:
                al |= self.labels(a)
            if "senspath" in al:
                out.add("cred")
            if (
                args
                and any(self.qual(x) in ("os.homedir", "os.homedir()") for x in self._walk(args[0]) if x.type in ("call_expression",))
                and "readdir" in q
            ):
                out.add("userfiles")
        if fn is not None and fn.type == "identifier" and self.t(fn) in self.func_returns:
            out |= self.func_returns[self.t(fn)]
        return out

    # ------------------------------------------------------------- propagation

    def _bind(self, target, labels: set[str]) -> bool:
        if target is None or not labels:
            return False
        changed = False
        for n in self._walk(target):
            if n.type in ("identifier", "shorthand_property_identifier_pattern"):
                name = self.t(n)
                sc = self.resolve_scope(n, name)
                if sc == 0 and (name in JS_GLOBALS or self._is_module_alias(name)):
                    continue  # `process.stdout.write(x)` must not taint `process` itself
                lab = labels
                if sc == 0:
                    # parameter-derived (context-insensitive) labels stay inside their function
                    lab = {x for x in labels if not x.startswith("p:")}
                    if not lab:
                        continue
                key = (sc, name)
                cur = self.taint.setdefault(key, set())
                if not lab <= cur:
                    cur |= lab
                    changed = True
            if target.type == "member_expression":
                break
        return changed

    def _root_ident(self, node):
        while node is not None and node.type in ("member_expression", "subscript_expression"):
            node = node.child_by_field_name("object")
        return node if node is not None and node.type == "identifier" else None

    def propagate(self) -> bool:
        changed = False
        for n in self.nodes:
            t = n.type
            if t == "variable_declarator":
                changed |= self._bind(n.child_by_field_name("name"), self.labels(n.child_by_field_name("value")))
            elif t in ("assignment_expression", "augmented_assignment_expression"):
                left = n.child_by_field_name("left")
                lab = self.labels(n.child_by_field_name("right"))
                target = left if left is not None and left.type == "identifier" else self._root_ident(left)
                changed |= self._bind(target, lab)
            elif t in ("for_in_statement",):
                changed |= self._bind(n.child_by_field_name("left"), self.labels(n.child_by_field_name("right")))
            elif t == "call_expression":
                fn = n.child_by_field_name("function")
                q = self.qual(fn) or ""
                args = self._args(n)
                # call-site -> parameter binding for functions defined in this file (context-insensitive)
                if not self.bundle_mode and fn is not None and fn.type == "identifier" and self.t(fn) in self.funcs:
                    for p, a in zip(self._param_names(self.funcs[self.t(fn)]), args, strict=False):
                        if p is not None and a.type not in FUNC_TYPES:
                            tagged = {lab if lab.startswith("p:") else "p:" + lab for lab in self.labels(a) - {"senspath"}}
                            changed |= self._bind(p, tagged)
                # container mutation: arr.push(x), Object.assign(o, x)
                if (
                    not self.bundle_mode
                    and fn is not None
                    and fn.type == "member_expression"
                    and self.t(fn.child_by_field_name("property")) in ("push", "unshift", "set", "concat", "write", "append")
                ):
                    root = self._root_ident(fn.child_by_field_name("object"))
                    lab = set()
                    for a in args:
                        if a.type not in FUNC_TYPES:
                            lab |= self.labels(a)
                    changed |= self._bind(root, lab)
                if q == "Object.assign" and args:
                    lab = set()
                    for a in args[1:]:
                        lab |= self.labels(a)
                    changed |= self._bind(self._root_ident(args[0]) or (args[0] if args[0].type == "identifier" else None), lab)
                # callbacks inherit the labels of the call (and of its receiver)
                cb_labels = set(self._call_labels(n))
                if fn is not None and fn.type == "member_expression" and not self.bundle_mode:
                    cb_labels |= self.labels(fn.child_by_field_name("object"))
                if FILE_READ.search(q) and args:
                    if "senspath" in self.labels(args[0]):
                        cb_labels.add("cred")
                iterating = (
                    fn is not None
                    and fn.type == "member_expression"
                    and self.t(fn.child_by_field_name("property"))
                    in ("map", "forEach", "filter", "reduce", "flatMap", "some", "every", "find")
                )
                if not iterating:
                    cb_labels.discard("senspath")
                if cb_labels:
                    for a in args:
                        if a.type in FUNC_TYPES:
                            params = a.child_by_field_name("parameters") or a.child_by_field_name("parameter")
                            changed |= self._bind(params, cb_labels)
            elif t == "return_statement":
                f = self.enclosing_func(n)
                if f is not None:
                    name_node = f.child_by_field_name("name")
                    if name_node is None and f.parent is not None and f.parent.type == "variable_declarator":
                        name_node = f.parent.child_by_field_name("name")
                    if name_node is not None:
                        lab = set()
                        for c in n.named_children:
                            lab |= self.labels(c)
                        lab = {x for x in lab if not x.startswith("p:")}  # context-insensitive params must not flow back out
                        cur = self.func_returns.setdefault(self.t(name_node), set())
                        if not lab <= cur:
                            cur |= lab
                            changed = True
        return changed

    # ------------------------------------------------------------- sinks & findings

    def _arg_labels(self, call) -> set[str]:
        lab = set()
        for a in self._args(call):
            if a.type in FUNC_TYPES:
                continue
            lab |= self.sl(a)
        return lab

    def sl(self, expr) -> set[str]:
        """Labels for sink checks: parameter-derived labels (p:X) count as X."""
        return {lab[2:] if lab.startswith("p:") else lab for lab in self.labels(expr)}

    def add(self, rule, title, sev, cat, msg, node, conf=0.8, evidence=None):
        line = node.start_point[0] + 1
        if self.bundle_mode:
            sev = min(sev, Severity.MEDIUM)
            conf = round(conf * 0.7, 2)
            evidence = {**(evidence or {}), "bundle_mode": True}
            msg += " (large bundle: flow-insensitive evidence, verify manually)"
        key = (rule, line)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(
            Finding(
                rule,
                title,
                sev,
                cat,
                msg,
                file=self.path,
                line=line,
                column=node.start_point[1],
                snippet=snippet_at(self.text, line),
                confidence=conf,
                install_time=self.install_time,
                evidence=evidence or {},
            )
        )

    def _ctx_bump(self, sev: Severity, node, strong: bool) -> Severity:
        if self.install_time:
            return Severity.CRITICAL if strong else _bump(sev, 2)
        if self.import_time and self.scope_of(node) == 0:
            return _bump(sev, 1)
        return sev

    @staticmethod
    def _describe(labels: set[str]) -> str:
        names = {
            "cred": "credential/secret files",
            "env:all": "the entire environment",
            "env:secret": "secret environment variables",
            "env:var": "environment variables",
            "sysinfo": "host fingerprint (hostname/user)",
            "userfiles": "user home directory listing",
        }
        return ", ".join(names[lab] for lab in sorted(labels) if lab in names)

    def check(self) -> None:
        reported_exfil: set = set()
        for n in self.nodes:
            if n.type not in ("call_expression", "new_expression"):
                continue
            fn = n.child_by_field_name("function") or n.child_by_field_name("constructor")
            q = self.qual(fn) or ""
            args = self._args(n)
            is_net = any(p.search(q) for p in NET_SINK)
            if is_net and q.split(".")[0].split("(")[0] in LIB_SINK_ROOTS and not self._is_imported(q.split(".")[0].split("(")[0]):
                is_net = False  # a local function that happens to be called `request`
            if is_net or DNS_SINK.search(q):
                real = self._arg_labels(n) & REAL
                if real:
                    sev = (
                        Severity.HIGH
                        if real & STRONG
                        else Severity.MEDIUM
                        if "userfiles" in real
                        else Severity.LOW
                        if real & {"sysinfo", "env:secret"}
                        else Severity.INFO
                    )
                    sev = self._ctx_bump(sev, n, bool(real & (STRONG | {"env:secret"})))
                    dns = not is_net
                    if dns:
                        sev = _bump(sev)
                    key = (self.scope_of(n), frozenset(real), dns)
                    if sev > Severity.INFO and key not in reported_exfil:
                        reported_exfil.add(key)
                        self.add(
                            "JS-EXFIL-DNS" if dns else "JS-EXFIL",
                            "Data exfiltration via DNS" if dns else "Sensitive data sent over the network",
                            sev,
                            Category.EXFILTRATION,
                            f"{self._describe(real)} flows into {'DNS lookups' if dns else f'`{q}`'}"
                            + (" during npm install" if self.install_time else ""),
                            n,
                            conf=0.9 if real & STRONG else 0.75,
                            evidence={"sources": sorted(real), "sink": q},
                        )
            if q in EXEC_SINK or (fn is not None and self.t(fn) == "Function"):
                if q in ("setTimeout", "setInterval") and (
                    not args or args[0].type not in ("string", "template_string", "binary_expression")
                ):
                    continue
                lab = self.sl(args[0]) if args else set()
                if n.type == "new_expression" or q.startswith("Function"):
                    lab = set()
                    for a in args:
                        lab |= self.sl(a)
                if "remote" in lab:
                    self.add(
                        "JS-EXEC-REMOTE",
                        "Downloads and executes code",
                        Severity.CRITICAL,
                        Category.CODE_EXECUTION,
                        f"network content reaches `{q}`",
                        n,
                        conf=0.95,
                    )
                elif "decoded" in lab:
                    self.add(
                        "JS-EXEC-OBFUSCATED",
                        "Executes obfuscated code",
                        Severity.CRITICAL if self.install_time or self.import_time else Severity.HIGH,
                        Category.OBFUSCATION,
                        f"decoded data reaches `{q}`",
                        n,
                        conf=0.9,
                    )
                elif args and args[0].type not in ("string", "template_string"):
                    self.add(
                        "JS-EXEC-DYNAMIC",
                        "Dynamic code execution",
                        Severity.MEDIUM if self.install_time else Severity.LOW,
                        Category.CODE_EXECUTION,
                        f"`{q}` is called with a non-literal argument",
                        n,
                        conf=0.5,
                    )
            if SHELL_SINK.search(q):
                text = " ".join(
                    filter(None, (_str_value(x) for x in self._walk(n) if x.type in ("string", "template_string", "binary_expression")))
                )
                if not text:
                    text = self.t(n)
                lab = self._arg_labels(n)
                cmd_lab = set()
                argv_style = q.endswith(("spawn", "spawnSync", "execFile", "execFileSync", "fork"))
                for a in args[: 2 if argv_style else 1]:
                    cmd_lab |= self.sl(a)
                # only the command / argv can carry data out; the options object (env, cwd, stdio) configures the child
                lab = cmd_lab
                if lab & {"remote", "decoded"}:
                    self.add(
                        "JS-SHELL-OBFUSCATED",
                        "Runs a decoded or downloaded command",
                        Severity.CRITICAL,
                        Category.CODE_EXECUTION,
                        f"`{q}` executes decoded/downloaded data",
                        n,
                        conf=0.9,
                    )
                elif LOLBIN.search(text):
                    self.add(
                        "JS-LOLBIN",
                        "Runs a living-off-the-land binary",
                        Severity.CRITICAL if self.install_time else Severity.HIGH,
                        Category.CODE_EXECUTION,
                        f"`{q}` invokes {LOLBIN.search(text).group(0)!r}, a Windows binary abused to proxy execution",
                        n,
                        conf=0.8,
                    )
                elif SELF_PUBLISH.search(text):
                    self.add(
                        "JS-SELF-PUBLISH",
                        "Publishes packages from code",
                        Severity.HIGH if self.install_time or self.import_time else Severity.MEDIUM,
                        Category.PERSISTENCE,
                        f"`{q}` runs {SELF_PUBLISH.search(text).group(0)!r}: worm-style self-propagation or spam publishing",
                        n,
                        conf=0.7,
                    )
                elif SHELL_DOWNLOAD.search(text):
                    self.add(
                        "JS-SHELL-DOWNLOAD",
                        "Shell command downloads or connects out",
                        Severity.CRITICAL if self.install_time or self.import_time else Severity.HIGH,
                        Category.DOWNLOADER,
                        f"`{q}` runs: {text[:120]!r}",
                        n,
                        conf=0.85,
                        evidence={"command": text[:500]},
                    )
                elif lab & (STRONG | {"env:secret"}) and self.install_time:
                    self.add(
                        "JS-SHELL-EXFIL",
                        "Secrets passed to a subprocess at install time",
                        Severity.HIGH,
                        Category.EXFILTRATION,
                        f"{self._describe(lab & REAL)} reach `{q}`",
                        n,
                        conf=0.7,
                    )
            if SHELL_SINK.search(q) and self.install_time and re.search(r"detached\s*:\s*true", self.t(n)):
                self.add(
                    "JS-DETACHED-PROCESS",
                    "Spawns a detached background process during install",
                    Severity.HIGH,
                    Category.INSTALL_HOOK,
                    "a process is started with `detached: true` so it keeps running after npm exits",
                    n,
                    conf=0.75,
                )
            if FILE_WRITE.search(q) and args:
                path = " ".join(filter(None, (_str_value(x) for x in self._walk(args[0]) if x.type in ("string", "template_string"))))
                if PERSIST_PATH.search(path):
                    self.add(
                        "JS-PERSISTENCE",
                        "Modifies a persistence location",
                        Severity.CRITICAL if "authorized_keys" in path or self.install_time else Severity.HIGH,
                        Category.PERSISTENCE,
                        f"writes to {path!r}",
                        n,
                        conf=0.85,
                    )
                if len(args) > 1 and "remote" in self.sl(args[1]):
                    self.add(
                        "JS-DROPPER",
                        "Writes downloaded content to disk",
                        Severity.MEDIUM,
                        Category.DOWNLOADER,
                        "network data is written to a file",
                        n,
                        conf=0.7,
                    )
            idx_node = fn.child_by_field_name("index") if fn is not None and fn.type == "subscript_expression" else None
            # obj[decode("...")](...) is the obfuscation idiom; obj[key](...) with data-derived keys is ordinary dispatch
            if idx_node is not None and idx_node.type in ("call_expression", "binary_expression") and "decoded" in self.sl(idx_node):
                payload = set()
                for a in args:
                    payload |= self.sl(a)
                if "decoded" in payload or "remote" in payload:
                    self.add(
                        "JS-EXEC-OBFUSCATED",
                        "Decoded method invoked on decoded data",
                        Severity.CRITICAL,
                        Category.OBFUSCATION,
                        "a method whose name is decoded at runtime is called with decoded data (e.g. Module._compile on a decrypted payload)",
                        n,
                        conf=0.85,
                    )
                else:
                    self.add(
                        "JS-OBFUSCATED-CALL",
                        "Method name decoded at runtime",
                        Severity.MEDIUM,
                        Category.OBFUSCATION,
                        "a method is looked up by a name that is decoded at runtime",
                        n,
                        conf=0.7,
                    )
            if q.startswith("module.constructor") or q in ("Module._compile", "module._compile") or q.endswith("._compile"):
                self.add(
                    "JS-MODULE-COMPILE",
                    "Compiles code through Node's internal Module API",
                    Severity.HIGH if self.install_time else Severity.MEDIUM,
                    Category.CODE_EXECUTION,
                    "`new module.constructor()` / `_compile` evaluates a string as a module, bypassing eval detection",
                    n,
                    conf=0.8,
                )
            if (
                fn is not None
                and self.t(fn) == "require"
                and args
                and args[0].type == "binary_expression"
                and (_str_value(args[0]) or "").removeprefix("node:") in SENSITIVE_MODULES
            ):
                self.add(
                    "JS-OBFUSCATED-REQUIRE",
                    "Obfuscated require()",
                    Severity.HIGH,
                    Category.OBFUSCATION,
                    f"module name {_str_value(args[0])!r} is assembled from pieces to evade string matching",
                    n,
                    conf=0.85,
                )
            if q == "require" and args and args[0].type not in ("string", "template_string") and "decoded" in self.sl(args[0]):
                self.add(
                    "JS-OBFUSCATED-REQUIRE",
                    "Obfuscated require()",
                    Severity.HIGH,
                    Category.OBFUSCATION,
                    "module name is decoded at runtime",
                    n,
                    conf=0.85,
                )

    def _is_module_alias(self, name: str) -> bool:
        a = self.aliases.get((0, name))
        return a is not None and not a.endswith("()")

    def _is_imported(self, mod: str) -> bool:
        return mod in set(self.aliases.values()) or any(v.startswith(mod + ".") or v.startswith(mod + "(") for v in self.aliases.values())

    def run(self) -> None:
        self.declare_pass()
        self.alias_pass()
        for _ in range(6):
            if not self.propagate():
                break
        self.check()


class JavaScriptAnalyzer:
    name = "javascript"

    def __init__(self) -> None:
        self.errors: list[str] = []

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        if _LANG is None:
            self.errors.append("tree-sitter-javascript not installed; JavaScript taint analysis skipped")
            return []
        out: list[Finding] = []
        files = [f for f, _t in iter_text_files(ctx, (".js", ".mjs", ".cjs", ".jsx", ".ts")) if len(f.data) <= 3_000_000]
        # code that runs on install/import first, so the time budget is spent where it matters
        files.sort(key=lambda f: (not ctx.is_install_time(f.path), f.path not in ctx.import_time_files, len(f.data)))
        started, budget, skipped = time.monotonic(), 10.0, 0
        for f in files:
            critical = ctx.is_install_time(f.path) or f.path in ctx.import_time_files
            if time.monotonic() - started > PACKAGE_JS_BUDGET_S and not critical:
                skipped += 1
                continue
            try:
                install = ctx.is_install_time(f.path)
                a = JSFileAnalysis(
                    f.data, f.path, install, f.path in ctx.import_time_files, budget_s=budget, bundle_mode=not install and _is_bundle(f)
                )
                a.run()
                out += a.findings
            except RecursionError:
                self.errors.append(f"{f.path}: too deeply nested")
            except AnalysisBudgetExceeded:
                self.errors.append(f"{f.path}: taint analysis skipped (time budget exceeded); heuristic analyzers still ran")
            spent = time.monotonic() - started
            budget = max(2.0, min(10.0, PACKAGE_JS_BUDGET_S - spent))
        if skipped:
            self.errors.append(
                f"{skipped} JavaScript file(s) not taint-analysed: package time budget ({PACKAGE_JS_BUDGET_S:.0f}s) exhausted"
            )
        return out


def analyze_js_source(src: str, path: str = "index.js", install_time: bool = False, import_time: bool = False) -> list[Finding]:
    a = JSFileAnalysis(src.encode(), path, install_time, import_time)
    a.run()
    return a.findings
