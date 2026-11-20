"""Turn findings into a 0-100 risk score, a verdict, and correlated kill-chain findings."""

from __future__ import annotations

from collections import defaultdict

from .models import Category, Finding, Severity

WEIGHT = {Severity.INFO: 0.0, Severity.LOW: 0.04, Severity.MEDIUM: 0.15, Severity.HIGH: 0.45, Severity.CRITICAL: 0.85}
BEHAVIOUR = {Category.EXFILTRATION, Category.CODE_EXECUTION, Category.DOWNLOADER, Category.OBFUSCATION, Category.PERSISTENCE}


def correlate(findings: list[Finding]) -> list[Finding]:
    """Individually weak signals that together describe a real attack."""
    out: list[Finding] = []
    squat = next((f for f in findings if f.category == Category.TYPOSQUAT), None)
    bad = [f for f in findings if f.category in BEHAVIOUR and f.severity >= Severity.MEDIUM and f.confidence >= 0.6]
    if squat and bad:
        worst = max(bad, key=lambda f: f.severity)
        out.append(
            Finding(
                "CORR-TYPOSQUAT-PAYLOAD",
                "Typosquat with malicious behaviour",
                Severity.CRITICAL,
                Category.TYPOSQUAT,
                f"{squat.message}, and it also contains: {worst.title.lower()}",
                file=worst.file,
                line=worst.line,
                snippet=worst.snippet,
                confidence=0.9,
                evidence={"typosquat": squat.evidence, "behaviour": worst.rule_id},
            )
        )
    by_file: dict[str | None, list[Finding]] = defaultdict(list)
    for f in findings:
        by_file[f.file].append(f)
    for file, fs in by_file.items():
        if file is None:
            continue
        obf = [f for f in fs if f.category == Category.OBFUSCATION and f.severity >= Severity.MEDIUM]
        net = [f for f in fs if f.category in (Category.EXFILTRATION, Category.IOC) and f.severity >= Severity.MEDIUM]
        if obf and net and not any(f.severity == Severity.CRITICAL for f in fs):
            out.append(
                Finding(
                    "CORR-OBFUSCATED-NETWORK",
                    "Obfuscation next to network activity",
                    Severity.HIGH,
                    Category.OBFUSCATION,
                    f"{obf[0].title.lower()} and {net[0].title.lower()} in the same file",
                    file=file,
                    line=obf[0].line,
                    snippet=obf[0].snippet,
                    confidence=0.75,
                )
            )
    beacon = [f for f in findings if f.category == Category.EXFILTRATION and f.install_time and f.severity >= Severity.MEDIUM]
    infra = [
        f
        for f in findings
        if f.rule_id in ("IOC-OAST", "IOC-TUNNEL", "IOC-RAW-IP-URL", "IOC-RAW-IP-SOCKET", "IOC-DISCORD-WEBHOOK", "IOC-TELEGRAM-BOT")
    ]
    if beacon and infra:
        out.append(
            Finding(
                "CORR-INSTALL-BEACON",
                "Install-time beacon to attacker infrastructure",
                Severity.CRITICAL,
                Category.EXFILTRATION,
                f"{beacon[0].message}; the package also contains {infra[0].title.lower()} ({infra[0].evidence.get('indicator', '')})",
                file=beacon[0].file,
                line=beacon[0].line,
                snippet=beacon[0].snippet,
                confidence=0.85,
                install_time=True,
            )
        )
    new = any(f.rule_id == "META-NEW-PACKAGE" for f in findings)
    hook = [f for f in findings if f.install_time and f.severity >= Severity.MEDIUM and f.category != Category.METADATA]
    if new and hook:
        out.append(
            Finding(
                "CORR-NEW-INSTALL-HOOK",
                "New package with install-time code",
                Severity.MEDIUM,
                Category.INSTALL_HOOK,
                "a package published within the last month runs code during installation",
                file=hook[0].file,
                line=hook[0].line,
                confidence=0.6,
            )
        )
    return out


def score(findings: list[Finding]) -> int:
    """Noisy-OR over findings; repeats of the same rule add with diminishing returns."""
    per_rule: dict[str, list[float]] = defaultdict(list)
    for f in findings:
        per_rule[f.rule_id].append(WEIGHT[f.severity] * f.confidence)
    keep = 1.0
    for probs in per_rule.values():
        probs.sort(reverse=True)
        for i, p in enumerate(probs[:10]):
            keep *= 1 - p * (0.5**i)
    return round(100 * (1 - keep))


def verdict(findings: list[Finding], s: int) -> str:
    if s >= 80 or any(f.severity == Severity.CRITICAL and f.confidence >= 0.75 for f in findings):
        return "malicious"
    if s >= 40 or any(f.severity >= Severity.HIGH and f.confidence >= 0.6 for f in findings):
        return "suspicious"
    if s >= 10:
        return "low-risk"
    return "clean"
