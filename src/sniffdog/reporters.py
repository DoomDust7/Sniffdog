"""Output formats: terminal, JSON, SARIF 2.1.0, Markdown, HTML."""

from __future__ import annotations

import html
import json
from collections.abc import Iterable
from datetime import UTC, datetime

from . import __version__
from .diff import DiffResult
from .models import Finding, ScanResult, Severity, sorted_findings
from .rules import RULES, describe

SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
VERDICT_STYLE = {
    "malicious": "bold white on red",
    "suspicious": "bold red",
    "low-risk": "yellow",
    "clean": "bold green",
    "allowed": "green",
}
VERDICT_EMOJI = {"malicious": "🚨", "suspicious": "⚠️", "low-risk": "🔎", "clean": "✅", "allowed": "✅"}


def _md(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def _loc(f: Finding) -> str:
    if not f.file:
        return "(package)"
    return f"{f.file}:{f.line}" if f.line else f.file


# --------------------------------------------------------------------------- terminal


def render_terminal(results: list[ScanResult], console=None, verbose: bool = False) -> None:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = console or Console()
    for r in results:
        pkg = r.package
        title = Text.assemble((f"{pkg.name}", "bold"), (f" {pkg.version or ''}", ""), (f"  [{pkg.ecosystem}]", "dim"))
        head = Text.assemble(
            ("verdict ", "dim"),
            (f" {r.verdict.upper()} ", VERDICT_STYLE.get(r.verdict, "")),
            ("   risk ", "dim"),
            (f"{r.score}/100", "bold"),
            ("   files ", "dim"),
            (f"{r.files_scanned}", ""),
            ("   time ", "dim"),
            (f"{r.duration_ms} ms", ""),
        )
        console.print(Panel(head, title=title, title_align="left", border_style=VERDICT_STYLE.get(r.verdict, "white").split()[-1]))
        if r.findings:
            t = Table(show_header=True, header_style="bold", box=None, pad_edge=False, expand=True)
            t.add_column("sev", width=9, no_wrap=True)
            t.add_column("rule", style="bold", no_wrap=True)
            t.add_column("finding", ratio=3)
            t.add_column("location", ratio=1, style="dim", overflow="fold")
            for f in sorted_findings(r.findings):
                msg = Text(f.message)
                if f.install_time:
                    msg.append("  [install-time]", style="magenta")
                if verbose and f.snippet:
                    msg.append(f"\n    {f.snippet}", style="dim italic")
                if verbose and f.evidence.get("decoded_preview"):
                    msg.append(f"\n    decoded: {f.evidence['decoded_preview'][:200]!r}", style="dim")
                t.add_row(Text(f.severity.name.lower(), style=SEV_STYLE[f.severity]), f.rule_id, msg, _loc(f))
            console.print(t)
        else:
            console.print("  [green]No findings.[/green]")
        for e in r.errors[:5]:
            console.print(f"  [dim]note: {e}[/dim]")
        if r.suppressed:
            console.print(f"  [dim]{r.suppressed} finding(s) suppressed by configuration[/dim]")
        console.print()


def render_diff_terminal(d: DiffResult, console=None, verbose: bool = False) -> None:
    from rich.console import Console

    console = console or Console()
    o, n = d.old, d.new
    arrow = "[red]▲[/red]" if d.score_delta > 0 else "[green]▼[/green]" if d.score_delta < 0 else "="
    console.print(
        f"[bold]{n.package.name}[/bold] {o.package.version} → {n.package.version}   risk {o.score} → {n.score} {arrow}   "
        f"verdict [{VERDICT_STYLE.get(n.verdict, '')}] {n.verdict.upper()} [/]"
    )
    if d.files_added:
        console.print(
            f"[dim]{len(d.files_added)} new file(s): {', '.join(d.files_added[:8])}{' …' if len(d.files_added) > 8 else ''}[/dim]"
        )
    if not d.added:
        console.print("[green]No new risky behaviour introduced by this version.[/green]")
    else:
        console.print(f"[bold red]{len(d.added)} new behaviour(s) introduced:[/bold red]")
        for f in sorted_findings(d.added):
            it = " [magenta][install-time][/magenta]" if f.install_time else ""
            console.print(
                f"  [{SEV_STYLE[f.severity]}]{f.severity.name.lower():8}[/] [bold]{f.rule_id}[/bold] {f.message}{it}  [dim]{_loc(f)}[/dim]"
            )
            if verbose and f.snippet:
                console.print(f"           [dim italic]{f.snippet}[/dim italic]")
    if d.removed:
        console.print(f"[dim]{len(d.removed)} finding(s) no longer present.[/dim]")


# --------------------------------------------------------------------------- json


def render_json(results: list[ScanResult]) -> str:
    return json.dumps(
        {
            "tool": {"name": "sniffdog", "version": __version__},
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "results": [r.to_dict() for r in results],
        },
        indent=2,
    )


# --------------------------------------------------------------------------- SARIF


SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "none"}
SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0", Severity.INFO: "0.0"}


def render_sarif(results: list[ScanResult]) -> str:
    used = sorted({f.rule_id for r in results for f in r.findings})
    rules = []
    for rid in used:
        name, desc, attack = describe(rid)
        rule = {
            "id": rid,
            "name": "".join(w.capitalize() for w in rid.lower().split("-")),
            "shortDescription": {"text": name},
            "fullDescription": {"text": desc or name},
            "helpUri": f"https://github.com/DoomDust7/sniffdog/blob/main/docs/rules.md#{rid.lower()}",
            "properties": {"tags": ["security", "supply-chain"] + ([f"external/mitre-attack/{attack}"] if attack else [])},
        }
        rules.append(rule)
    index = {r["id"]: i for i, r in enumerate(rules)}
    sarif_results = []
    for r in results:
        for f in sorted_findings(r.findings):
            loc_uri = f.file.split("<layer")[0] if f.file else (r.package.source or r.package.name)
            region = {"startLine": max(1, f.line or 1)}
            if f.column is not None:
                region["startColumn"] = f.column + 1
            if f.snippet:
                region["snippet"] = {"text": f.snippet}
            sarif_results.append(
                {
                    "ruleId": f.rule_id,
                    "ruleIndex": index[f.rule_id],
                    "level": SARIF_LEVEL[f.severity],
                    "message": {"text": f"[{r.package.name}{'@' + r.package.version if r.package.version else ''}] {f.message}"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": loc_uri}, "region": region}}],
                    "partialFingerprints": {"sniffdog/v1": f.fingerprint()},
                    "properties": {
                        "security-severity": SECURITY_SEVERITY[f.severity],
                        "confidence": f.confidence,
                        "install_time": f.install_time,
                        "package": r.package.name,
                        "risk_score": r.score,
                    },
                }
            )
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Sniffdog",
                            "version": __version__,
                            "semanticVersion": __version__,
                            "informationUri": "https://github.com/DoomDust7/sniffdog",
                            "rules": rules,
                        }
                    },
                    "results": sarif_results,
                }
            ],
        },
        indent=2,
    )


# --------------------------------------------------------------------------- markdown


def render_markdown(results: list[ScanResult], diff: DiffResult | None = None) -> str:
    lines = ["## 🐕 Sniffdog supply-chain report", ""]
    if diff is not None:
        lines += [
            f"**{diff.new.package.name}** `{diff.old.package.version}` → `{diff.new.package.version}` · risk {diff.old.score} → **{diff.new.score}**",
            "",
        ]
        if diff.added:
            lines += ["| Severity | Rule | New behaviour | Location |", "|---|---|---|---|"]
            for f in sorted_findings(diff.added):
                lines.append(f"| {f.severity.name.lower()} | `{f.rule_id}` | {_md(f.message)} | `{_loc(f)}` |")
        else:
            lines.append("✅ No new risky behaviour introduced.")
        return "\n".join(lines) + "\n"
    flagged = [r for r in results if r.verdict not in ("clean", "allowed")]
    lines += [
        f"Scanned **{len(results)}** package(s): "
        + ", ".join(
            f"{sum(1 for r in results if r.verdict == v)} {v}"
            for v in ("malicious", "suspicious", "low-risk", "clean")
            if any(r.verdict == v for r in results)
        ),
        "",
    ]
    if flagged:
        lines += ["| Package | Verdict | Risk | Top finding |", "|---|---|---|---|"]
        for r in flagged:
            top = sorted_findings(r.findings)[0] if r.findings else None
            lines.append(
                f"| `{r.package.name}` {r.package.version or ''} | {VERDICT_EMOJI.get(r.verdict, '')} {r.verdict} | {r.score} | "
                + (f"`{top.rule_id}` {_md(top.message)}" if top else "")
                + " |"
            )
        lines.append("")
        for r in flagged:
            lines += [
                f"<details><summary><b>{r.package.name}</b> — {len(r.findings)} finding(s)</summary>",
                "",
                "| Sev | Rule | Finding | Location |",
                "|---|---|---|---|",
            ]
            for f in sorted_findings(r.findings):
                lines.append(f"| {f.severity.name.lower()} | `{f.rule_id}` | {_md(f.message)} | `{_loc(f)}` |")
            lines += ["", "</details>", ""]
    else:
        lines.append("✅ Nothing suspicious found.")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- html


def render_html(results: list[ScanResult], title: str = "Sniffdog report") -> str:
    e = html.escape
    cards = []
    for r in results:
        rows = []
        for f in sorted_findings(r.findings):
            detail = ""
            if f.snippet:
                detail += f'<pre class="snip">{e(f.snippet)}</pre>'
            if f.evidence.get("decoded_preview"):
                detail += f'<div class="ev">decoded payload</div><pre class="snip">{e(str(f.evidence["decoded_preview"])[:400])}</pre>'
            if f.evidence.get("sources"):
                detail += f'<div class="ev">sources → sink: {e(", ".join(f.evidence["sources"]))} → <code>{e(str(f.evidence.get("sink")))}</code></div>'
            attack = describe(f.rule_id)[2]
            rows.append(
                f'<tr class="sev-{f.severity.name.lower()}"><td><span class="pill {f.severity.name.lower()}">{f.severity.name.lower()}</span></td>'
                f"<td><code>{e(f.rule_id)}</code>{f'<div class=att>ATT&amp;CK {attack}</div>' if attack else ''}</td>"
                f"<td><b>{e(f.title)}</b>{' <span class=it>install-time</span>' if f.install_time else ''}<div>{e(f.message)}</div>{detail}</td>"
                f'<td class="loc">{e(_loc(f))}</td></tr>'
            )
        table = (
            (
                "<table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Location</th></tr></thead><tbody>"
                + "".join(rows)
                + "</tbody></table>"
            )
            if rows
            else '<p class="ok">No findings.</p>'
        )
        pct = r.score
        cards.append(f"""
<section class="card">
  <header>
    <div><h2>{e(r.package.name)} <span class="ver">{e(r.package.version or "")}</span></h2>
    <div class="meta">{e(r.package.ecosystem)} · {r.files_scanned} files · {r.bytes_scanned:,} bytes · {r.duration_ms} ms{(" · sha256 " + e(r.package.sha256[:16]) + "…") if r.package.sha256 else ""}</div></div>
    <div class="score"><div class="gauge" style="--p:{pct}"><span>{pct}</span></div><div class="verdict v-{e(r.verdict)}">{e(r.verdict)}</div></div>
  </header>
  {table}
</section>""")
    counts = {v: sum(1 for r in results if r.verdict == v) for v in ("malicious", "suspicious", "low-risk", "clean")}
    summary = " ".join(f'<span class="chip v-{k}">{v} {k}</span>' for k, v in counts.items() if v)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title>
<style>
:root{{--bg:#f6f7f9;--card:#fff;--fg:#14171c;--mute:#5d6673;--line:#e3e6eb;--crit:#b4231a;--high:#d9480f;--med:#b7791f;--low:#2b6cb0;--info:#718096;--ok:#2f855a;--code:#f0f2f5}}
@media (prefers-color-scheme:dark){{:root:not([data-theme=light]){{--bg:#0f1115;--card:#171a21;--fg:#e6e9ee;--mute:#99a3b0;--line:#2a2f39;--code:#1f232c;--crit:#f05a50;--high:#ff8a4c;--med:#e3b341;--low:#63a4ff;--ok:#56c288}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:24px 16px}}h1{{font-size:22px;margin:0 0 4px}}.sub{{color:var(--mute);margin-bottom:18px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin:16px 0;overflow-x:auto}}
.card header{{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:10px}}h2{{margin:0;font-size:18px}}.ver{{color:var(--mute);font-weight:400}}
.meta{{color:var(--mute);font-size:12px}}.score{{display:flex;align-items:center;gap:10px}}
.gauge{{--c:var(--ok);width:52px;height:52px;border-radius:50%;background:conic-gradient(var(--c) calc(var(--p)*1%),var(--line) 0);display:grid;place-items:center}}
.gauge span{{background:var(--card);width:40px;height:40px;border-radius:50%;display:grid;place-items:center;font-weight:700}}
.verdict,.chip{{text-transform:uppercase;font-weight:700;font-size:12px;padding:3px 8px;border-radius:6px;letter-spacing:.04em}}
.v-malicious{{background:var(--crit);color:#fff}}.v-suspicious{{background:var(--high);color:#fff}}.v-low-risk{{background:var(--med);color:#111}}.v-clean,.v-allowed{{background:var(--ok);color:#fff}}
table{{width:100%;border-collapse:collapse}}th{{text-align:left;color:var(--mute);font-weight:600;font-size:12px;border-bottom:1px solid var(--line);padding:6px}}
td{{border-bottom:1px solid var(--line);padding:8px 6px;vertical-align:top}}td.loc{{font-family:ui-monospace,monospace;font-size:12px;color:var(--mute);word-break:break-all}}
.pill{{font-size:11px;font-weight:700;padding:2px 7px;border-radius:10px;color:#fff;text-transform:uppercase}}.critical{{background:var(--crit)}}.high{{background:var(--high)}}.medium{{background:var(--med);color:#111}}.low{{background:var(--low)}}.info{{background:var(--info)}}
pre.snip{{background:var(--code);padding:6px 8px;border-radius:6px;margin:6px 0 0;white-space:pre-wrap;word-break:break-all;font-size:12px}}
.ev,.att{{color:var(--mute);font-size:12px;margin-top:4px}}.it{{font-size:11px;color:#fff;background:#805ad5;border-radius:4px;padding:1px 5px}}.ok{{color:var(--ok)}}
code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}}
@media (max-width:640px){{.card header{{flex-direction:column;align-items:flex-start}}td.loc{{display:none}}}}
</style></head><body><main>
<h1>🐕 {e(title)}</h1><div class="sub">Sniffdog {__version__} · {datetime.now(UTC):%Y-%m-%d %H:%M UTC} · {summary}</div>
{"".join(cards)}
</main>
<script>document.querySelectorAll('.gauge').forEach(g=>{{const p=+g.style.getPropertyValue('--p');g.style.setProperty('--c',p>=80?'var(--crit)':p>=40?'var(--high)':p>=10?'var(--med)':'var(--ok)')}})</script>
</body></html>"""


def render(results: list[ScanResult], fmt: str) -> str:
    if fmt == "json":
        return render_json(results)
    if fmt == "sarif":
        return render_sarif(results)
    if fmt in ("md", "markdown"):
        return render_markdown(results)
    if fmt == "html":
        return render_html(results)
    raise ValueError(fmt)


def rules_table() -> Iterable[tuple[str, str, str, str]]:
    for rid, (name, desc, attack) in RULES.items():
        yield rid, name, desc, attack
