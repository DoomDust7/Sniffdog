"""Registry-metadata reputation signals. Weak on their own; they matter in combination."""

from __future__ import annotations

from ..models import Category, Finding, Severity
from ..registry import age_days
from .base import ScanContext


class MetadataAnalyzer:
    name = "metadata"

    def analyze(self, ctx: ScanContext) -> list[Finding]:
        md = ctx.package.metadata or {}
        if not md.get("registry"):
            return []
        out: list[Finding] = []
        age = age_days(md.get("first_release"))
        if age is not None and age < 30:
            out.append(
                Finding(
                    "META-NEW-PACKAGE",
                    "Very new package",
                    Severity.LOW,
                    Category.METADATA,
                    f"first published {age:.0f} days ago ({md.get('release_count', '?')} release(s)); most malicious packages live < 1 week",
                    confidence=0.5,
                    evidence={"age_days": round(age, 1)},
                )
            )
        rel_age = age_days(md.get("this_release"))
        if age is not None and age > 365 and rel_age is not None and rel_age < 7:
            out.append(
                Finding(
                    "META-DORMANT-REVIVED",
                    "Fresh release of a long-lived package",
                    Severity.INFO,
                    Category.METADATA,
                    f"this version was published {rel_age:.0f} days ago; account takeovers often push a new release of an established package",
                    confidence=0.3,
                )
            )
        if not md.get("repository") and not md.get("home_page"):
            out.append(
                Finding(
                    "META-NO-SOURCE",
                    "No source repository linked",
                    Severity.INFO,
                    Category.METADATA,
                    "the published package cannot be compared with a public source repository",
                    confidence=0.4,
                )
            )
        if not (md.get("summary") or "").strip():
            out.append(
                Finding(
                    "META-NO-DESCRIPTION",
                    "Empty description",
                    Severity.INFO,
                    Category.METADATA,
                    "package has no description",
                    confidence=0.3,
                )
            )
        return out
