"""Regenerate docs/rules.md from the rule catalog: python docs/gen_rules.py"""

from pathlib import Path

from sniffdog.rules import RULES

GROUPS = [("PY-", "Python data-flow & behaviour"), ("JS-", "JavaScript data-flow & behaviour"), ("NPM-", "Install manifests"),
          ("OBF-", "Obfuscation"), ("IOC-", "Indicators of compromise"), ("BIN-", "Binaries"), ("ARCHIVE-", "Archive anomalies"),
          ("TYPOSQUAT", "Name-based attacks"), ("DEP-", "Name-based attacks"), ("META-", "Registry reputation"), ("CORR-", "Correlation (kill-chain) rules")]

out = ["# Detection rules", "", f"Sniffdog ships **{len(RULES)} rules**. Generated from `src/sniffdog/rules.py`.", ""]
seen_heading = set()
for prefix, heading in GROUPS:
    rows = [(k, v) for k, v in RULES.items() if k.startswith(prefix)]
    if not rows:
        continue
    if heading not in seen_heading:
        out += [f"## {heading}", "", "| Rule | Name | MITRE ATT&CK | Description |", "|---|---|---|---|"]
        seen_heading.add(heading)
    for rid, (name, desc, attack) in rows:
        link = f"[{attack}](https://attack.mitre.org/techniques/{attack.replace('.', '/')}/)" if attack else ""
        out.append(f'| <a id="{rid.lower()}"></a>`{rid}` | {name} | {link} | {desc} |')
    out.append("")
Path(__file__).with_name("rules.md").write_text("\n".join(out))
print(f"wrote {len(RULES)} rules")
