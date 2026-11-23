| Dataset | Scanned | Detected (malicious + suspicious) | Malicious | Suspicious | Low-risk | Clean | Errors |
|---|---|---|---|---|---|---|---|
| npm/compromised_lib | 150 | 108 (72.0%) | 47 | 61 | 15 | 27 | 0 |
| npm/malicious_intent | 150 | 80 (53.3%) | 59 | 21 | 35 | 35 | 0 |
| pypi/compromised_lib | 17 | 7 (41.2%) | 2 | 5 | 2 | 8 | 0 |
| pypi/malicious_intent | 150 | 99 (66.0%) | 89 | 10 | 12 | 39 | 0 |
| **all** | 467 | 294 (63.0%) | 197 | 97 | 64 | 109 | 0 |

5 sample(s) are git checkouts of the source repository rather than the published artifact (no payload present). Excluding them: **294/462 detected (63.6%)**.

Median scan time 22 ms, p95 9341 ms.

Most frequent medium+ rules: `NPM-INSTALL-SCRIPT` (183), `IOC-OAST` (100), `OBF-JS-OBFUSCATOR` (87), `NPM-LARGE-INSTALL-PAYLOAD` (85), `JS-EXFIL` (58), `CORR-INSTALL-BEACON` (57), `PY-SHELL-DOWNLOAD` (48), `PY-DETACHED-PROCESS` (41), `JS-SELF-PUBLISH` (36), `OBF-ENCODED-CODE` (21), `PY-EXFIL` (21), `CORR-TYPOSQUAT-PAYLOAD` (17)
