# Architecture & design decisions

```
                ┌──────────────────────────── sniffdog CLI / GitHub Action ────────────────────────────┐
 spec / path ──▶│ registry.py ──▶ archive.py ──▶ ScanContext ──▶ analyzers ──▶ scanner post-process ──▶ scoring ──▶ reporters │
                │ (PyPI/npm,      (in-memory,    (ecosystem,      (9, run       (path trust,          (noisy-OR,   (text, JSON,
                │  hash-verified)  never on disk) entry points)    independently) suppressions, dedupe)  correlation) SARIF, MD, HTML)
                └───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
                     audit.py (lockfile parsers, typosquat + dependency confusion, parallel deep scan)   diff.py (behavioural delta)
```

## 1. Never extract attacker-controlled archives

`archive.py` reads every tar/zip member straight into memory under hard limits
(8 MiB per file, 256 MiB total, 25k members, compression-ratio guard). Path
traversal, absolute paths, escaping symlinks and device files are recorded as
*findings* (`ARCHIVE-*`) instead of being written anywhere. A scanner that
extracts a malicious package to disk has already lost.

## 2. Know *when* code runs

Most false positives in naive scanners come from treating all code equally. A
`subprocess` call in a CLI's `main()` is normal; the same call in `setup.py` runs
on every `pip install`. `ScanContext` computes:

- **install-time files**: `setup.py`, `.pth` files, and any script referenced
  by npm `preinstall`/`install`/`postinstall`. Also any `run()` method of a
  class that subclasses a setuptools command (`cmdclass`), wherever it lives.
- **import-time code**: top-level statements of package `__init__.py` or the
  npm `main` entry, plus functions *reachable* from them (a call graph from
  module scope, including `threading.Thread(target=f)`, decorators and
  instantiated classes' `__init__`). `if __name__ == "__main__":` is excluded.
- **script entry points**: install-time files are followed transitively to the files they launch
  (`spawn("bun", ["bun_environment.js"])`, `python -m pkg.utils.analyzer`). Python modules launched
  that way have their `if __name__ == "__main__":` block treated as executed.
- **low-trust paths**: `tests/`, `docs/`, `examples/`, `scripts/`, … are
  never executed by installing or importing a package, so findings there drop
  two severity levels.

Severity then depends on context: credentials → network is HIGH, at import
time CRITICAL, during install CRITICAL.

## 3. Taint analysis instead of keyword matching

`import requests` and `os.environ` both appear in thousands of benign
packages. What matters is whether *data* flows from one to the other.

**Labels.** Sources attach labels: `env:all` (the whole environment),
`env:secret` (one variable whose *name* looks secret), `cred` (contents of
`~/.ssh`, `~/.aws`, browser stores, wallets…), `sysinfo`, `userfiles`,
`decoded`, `remote`. `senspath` marks a *path* to a credential store; it only
becomes `cred` when it reaches a file reader. That two-step design is why
`".aws", "credentials"` passed as separate `joinpath` components is still caught.

**Python** (`python_taint.py`, stdlib `ast`):
- name resolution through `import x as y`, `from a import b`, `__import__("o"+"s")`, `getattr(mod, "sys"+"tem")`
- constructor typing, so `conn = http.client.HTTPSConnection(...)` makes `conn.request(...)` a sink
- flow-insensitive fixpoint per scope, so statement order can't hide a flow
- container mutation (`buf.append(x)`, `d.update(x)`, `self.items.append(x)`). File handles are excluded, and so are module objects: `sys.stdout.write(x)` must not taint `sys`.
- **function summaries**: which labels a function returns and which parameters
  reach which sinks. These are iterated to a global fixpoint, so
  `ship(collect())` is caught when `collect` reads secrets and `ship` posts its
  argument, including keyword and keyword-only arguments and methods on `self`.

**JavaScript** (`javascript.py`, tree-sitter): same label model. Call-site → parameter binding is
context-insensitive, so labels arriving through a parameter are tagged (`p:cred`). They still
trigger sinks inside the function but are stripped from return summaries and never stored in
module scope, which stops one legitimate `atob()` from smearing across a whole file. Plus
lexical scoping, `require`/ESM alias resolution (including destructuring),
object typing for `https.request()` objects, and **callback parameter
inheritance**. Node delivers data through callbacks
(`https.get(u, res => res.on("data", d => eval(d)))`), so a callback's
parameters inherit the labels of the call they are passed to. For array
iteration (`files.map(f => fs.readFileSync(f))`) they also inherit the
`senspath` label.

**Bundle mode.** Flow-insensitive analysis loses precision on 40k-line webpack/rollup outputs:
in vite's 1.4 MB dev-server chunk, 8 real sources ended up tainting 5,253 variables. Measured
ablations showed context-insensitive parameter binding was the largest contributor. Files over 256 KB
(or minified) that do **not** run at install time therefore get conservative propagation, and their
flows are reported as *capability evidence* capped at MEDIUM. Escalation then needs corroboration
(obfuscation or IOCs in the same file, via correlation). Install-time code always gets the full analysis.

**Budgets.** Each JS file has a 10 s taint budget and each package 45 s. Install-time and entry-point files
are analysed first, and anything skipped is reported, never silently dropped. A hostile 10 MB file can
cost seconds, not minutes.

## 4. Static deobfuscation

`_ConstFolder` evaluates constant expressions: string concatenation,
`[::-1]`, `"".join(chr(c) for c in [...])`, `base64/b32/b85/hex/zlib`,
`codecs.decode(..., "rot13")`, and single-assignment module constants. When a
decoded payload reaches `exec`, Sniffdog shows a preview, **parses the payload
and runs the full analysis on it** with the same install/import context. It
repeats this for up to three layers, with findings attributed to
`setup.py<layer2@L3>`. JS inline scripts in `package.json`
(`node -e "..."`) are parsed and analysed as install-time JavaScript.

## 5. Scoring: calibrated, explainable, correlated

Each finding has a severity and a confidence. The package score is a
noisy-OR: `1 − Π(1 − w(sev)·conf)`, where repeats of the same rule add with
diminishing returns, so 40 copies of a weak signal can't sum to "malicious".
Correlation rules add kill-chain findings when weak signals co-occur, for
example a typosquatted name plus exfiltration (`CORR-TYPOSQUAT-PAYLOAD`), or
obfuscation in the same file as network IOCs. Verdicts: `malicious`
(score ≥ 80 or a confident CRITICAL), `suspicious`, `low-risk`, `clean`.

## 6. Adversarial considerations

- Inline `# sniffdog: ignore` comments are honoured **only for local source
  trees**, never for downloaded artifacts. Otherwise malware could whitelist itself.
- Registry artifacts are verified against PyPI SHA-256 or npm SRI
  (`sha512-…`) before analysis, and again when read from the cache.
- Hard limits on recursion depth, folding depth, file sizes and fixpoint
  iterations keep hostile inputs from causing a DoS. A crashing analyzer is
  isolated and reported, and it never hides the other analyzers' results.
- Trojan Source (bidi overrides) and zero-width characters *in identifiers*
  (not in string literals, which Unicode tables legitimately contain) are
  flagged.

## 7. Calibration loop (and keeping it honest)

Every detection and false-positive change was driven by *tuning sets*: a seed-1 sample of real malware
and the top-300 most-downloaded packages. Reported numbers come from *held-out* sets the rules never
saw: a seed-7 malware sample and popularity ranks 301-800.


The false-positive fixes in this codebase each came from scanning real
top-downloaded packages and reading the code that fired. Examples:
- `sys.stdout.write()` tainting `sys`
- a temp-file name inheriting the file's contents
- vite's local `request()` helper being mistaken for the `request` library
- coverage's `.pth` doing `exec("literal")`
- a base64 PNG with an EXIF text chunk
- `../CONTRIBUTING.md` symlinks that stay inside the package

Each became a regression test in `tests/`.

## Known limitations

- Static analysis can be defeated by sufficiently dynamic code (runtime
  `eval` of computed strings that cannot be folded). Sniffdog then reports the
  *dynamic execution* itself (`*-EXEC-DYNAMIC`, `JS-OBFUSCATED-CALL`) rather
  than its payload.
- Taint is flow-insensitive within a scope (sound for detection, can
  over-approximate). Inter-procedural analysis is module-local: flows that cross
  files are only connected through module-level reachability.
- JavaScript files over 3 MB (huge bundles) skip taint analysis; the
  heuristic analyzers still run on them.
