"""sniffdog command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import Config, load_config
from .models import Severity

BANNER = "🐕 sniffdog — sniffs out malware hiding in your dependencies"


def _console(stderr: bool = False):
    from rich.console import Console

    return Console(stderr=stderr, highlight=False)


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        _console(stderr=True).print(f"[dim]wrote {output}[/dim]")
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def _apply_overrides(cfg: Config, args: argparse.Namespace) -> Config:
    if getattr(args, "fail_on", None):
        cfg.fail_on = Severity.parse(args.fail_on)
    if getattr(args, "min_severity", None):
        cfg.min_severity = Severity.parse(args.min_severity)
    if getattr(args, "artifact", None):
        cfg.artifact = args.artifact
    if getattr(args, "no_metadata", False):
        cfg.metadata = False
    for r in getattr(args, "ignore", None) or []:
        cfg.ignore_rules.append(r)
    for p in getattr(args, "internal_prefix", None) or []:
        cfg.internal_prefixes.append(p)
    return cfg


def cmd_scan(args: argparse.Namespace) -> int:
    from .registry import RegistryError
    from .reporters import render, render_terminal
    from .scanner import Scanner, exit_code

    cfg = _apply_overrides(load_config(args.config), args)
    scanner = Scanner(cfg)
    results, failed = [], False
    err = _console(stderr=True)
    for target in args.targets:
        try:
            if args.format == "text" and not Path(target).exists():
                with err.status(f"fetching {target} …"):
                    results += scanner.scan_target(target)
            else:
                results += scanner.scan_target(target)
        except (RegistryError, OSError, ValueError) as e:
            err.print(f"[red]error:[/red] {target}: {e}")
            failed = True
    if args.format == "text" and not args.output:
        render_terminal(results, _console(), verbose=args.verbose)
    else:
        _emit(render(results, args.format), args.output)
    if failed and not results:
        return 2
    return exit_code(results, cfg.fail_on) or (2 if failed else 0)


def cmd_diff(args: argparse.Namespace) -> int:
    from . import archive
    from .diff import diff_results
    from .registry import fetch, parse_spec
    from .reporters import render_diff_terminal, render_markdown
    from .scanner import Scanner

    cfg = _apply_overrides(load_config(args.config), args)
    scanner = Scanner(cfg)
    if args.new is None:  # diff A B where both are full specs/paths
        a, b = args.package, args.old
    else:
        spec = parse_spec(args.package)
        sep = "==" if spec.ecosystem == "pypi" else "@"
        a, b = f"{spec.ecosystem}:{spec.name}{sep}{args.old}", f"{spec.ecosystem}:{spec.name}{sep}{args.new}"

    def load(target: str):
        if Path(target).exists():
            return scanner.scan_path(target), set(archive.load(target).files)
        art = fetch(parse_spec(target), cfg.artifact)[0]
        return scanner.scan_artifact(art), set(archive.load_bytes(art.data, art.filename).files)

    with _console(stderr=True).status("scanning both versions …"):
        (old, of), (new, nf) = load(a), load(b)
    d = diff_results(old, new, of, nf)
    if args.format == "json":
        import json

        _emit(json.dumps(d.to_dict(), indent=2), args.output)
    elif args.format in ("md", "markdown"):
        _emit(render_markdown([new], diff=d), args.output)
    else:
        render_diff_terminal(d, _console(), verbose=args.verbose)
    return 1 if any(f.severity >= cfg.fail_on for f in d.added) else 0


def cmd_audit(args: argparse.Namespace) -> int:
    from .audit import audit, discover
    from .reporters import render, render_terminal
    from .scanner import exit_code

    cfg = _apply_overrides(load_config(args.config), args)
    paths: list[Path] = []
    for t in args.paths or ["."]:
        p = Path(t)
        paths += discover(p) if p.is_dir() else [p]
    if not paths:
        _console(stderr=True).print("[red]No dependency manifests found.[/red]")
        return 2
    err = _console(stderr=True)
    err.print(f"[dim]auditing {', '.join(str(p) for p in paths)}{' (deep scan)' if args.deep else ''}[/dim]")
    if args.deep and args.format == "text":
        from rich.progress import Progress

        from .audit import parse_manifest

        total = sum(len(parse_manifest(p)) for p in paths)
        with Progress(transient=True, console=err) as prog:
            task = prog.add_task("scanning dependencies", total=total)
            results = audit(paths, cfg, deep=True, workers=args.workers, progress=lambda _: prog.advance(task))
    else:
        results = audit(paths, cfg, deep=args.deep, workers=args.workers)
    if args.format == "text" and not args.output:
        flagged = [r for r in results if r.findings]
        render_terminal(flagged, _console(), verbose=args.verbose)
        c = _console()
        counts = {v: sum(1 for r in results if r.verdict == v) for v in ("malicious", "suspicious", "low-risk", "clean")}
        c.print(f"[bold]{len(results)} dependencies[/bold]: " + ", ".join(f"{n} {v}" for v, n in counts.items() if n))
    else:
        _emit(render(results, args.format), args.output)
    return exit_code(results, cfg.fail_on)


def cmd_typosquat(args: argparse.Namespace) -> int:
    from .analyzers.typosquat import check_name

    c = _console()
    hit = False
    for name in args.names:
        m = check_name(name, args.ecosystem)
        if m:
            hit = True
            c.print(f"[bold red]✗[/bold red] {name}: looks like [bold]{m.target}[/bold] (#{m.rank} on {args.ecosystem}) — {m.technique}")
        else:
            c.print(f"[green]✓[/green] {name}: no look-alike of a popular {args.ecosystem} package")
    return 1 if hit else 0


def cmd_rules(args: argparse.Namespace) -> int:
    from rich.table import Table

    from .reporters import rules_table

    t = Table("rule", "name", "ATT&CK", "description", show_lines=False)
    for rid, name, desc, attack in rules_table():
        t.add_row(rid, name, attack, desc)
    _console().print(t)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sniffdog",
        description=BANNER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
        "  sniffdog scan requests==2.32.3\n"
        "  sniffdog scan npm:event-stream@3.3.6 --format sarif -o results.sarif\n"
        "  sniffdog scan ./downloaded-package.tar.gz -v\n"
        "  sniffdog diff npm:ua-parser-js 0.7.28 0.7.29\n"
        "  sniffdog audit . --deep\n"
        "  sniffdog typosquat reqeusts colourama\n",
    )
    p.add_argument("--version", action="version", version=f"sniffdog {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp, formats=("text", "json", "sarif", "markdown", "html")):
        sp.add_argument("-f", "--format", choices=formats, default="text")
        sp.add_argument("-o", "--output", help="write report to a file")
        sp.add_argument("-v", "--verbose", action="store_true", help="show code snippets and decoded payloads")
        sp.add_argument("--config", help="path to sniffdog.toml / pyproject.toml")
        sp.add_argument(
            "--fail-on", choices=[s.name.lower() for s in Severity], help="exit 1 if any finding is at/above this severity (default: high)"
        )
        sp.add_argument(
            "--min-severity", choices=[s.name.lower() for s in Severity], help="hide findings below this severity (default: low)"
        )
        sp.add_argument("--ignore", action="append", metavar="RULE", help="ignore a rule id (glob ok); repeatable")

    s = sub.add_parser("scan", help="scan packages from PyPI/npm, archives, or directories")
    s.add_argument("targets", nargs="+", help="pypi:name==ver | npm:name@ver | name | path")
    s.add_argument("--artifact", choices=("sdist", "wheel", "all"), help="which PyPI artifact(s) to scan (default: sdist)")
    s.add_argument("--no-metadata", action="store_true", help="skip registry reputation signals")
    common(s)
    s.set_defaults(func=cmd_scan)

    d = sub.add_parser("diff", help="show behaviour introduced between two versions")
    d.add_argument("package", help="package spec (pypi:x / npm:x) or first artifact path/spec")
    d.add_argument("old", help="old version (or second artifact path/spec)")
    d.add_argument("new", nargs="?", help="new version")
    d.add_argument("--artifact", choices=("sdist", "wheel", "all"))
    common(d, formats=("text", "json", "markdown"))
    d.set_defaults(func=cmd_diff)

    a = sub.add_parser("audit", help="audit requirements/lockfiles (typosquats, dependency confusion, --deep scanning)")
    a.add_argument("paths", nargs="*", help="manifest files or project directories (default: .)")
    a.add_argument("--deep", action="store_true", help="download and fully scan every dependency")
    a.add_argument("--workers", type=int, default=8)
    a.add_argument("--internal-prefix", action="append", metavar="PREFIX", help="private package prefix for dependency-confusion checks")
    a.add_argument("--artifact", choices=("sdist", "wheel", "all"))
    common(a)
    a.set_defaults(func=cmd_audit)

    t = sub.add_parser("typosquat", help="check names against the most-downloaded packages")
    t.add_argument("names", nargs="+")
    t.add_argument("-e", "--ecosystem", choices=("pypi", "npm"), default="pypi")
    t.set_defaults(func=cmd_typosquat)

    r = sub.add_parser("rules", help="list detection rules")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as e:  # noqa: BLE001
        if getattr(args, "verbose", False):
            raise
        _console(stderr=True).print(f"[red]error:[/red] {e}")
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
