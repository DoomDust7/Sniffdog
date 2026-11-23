| Dataset | Scanned | Detected (malicious + suspicious) | Malicious | Suspicious | Low-risk | Clean | Errors |
|---|---|---|---|---|---|---|---|
| npm/popular | 500 | 1 (0.2%) | 0 | 1 | 8 | 491 | 0 |
| pypi/popular | 492 | 9 (1.8%) | 4 | 5 | 18 | 465 | 8 |
| **all** | 992 | 10 (1.0%) | 4 | 6 | 26 | 956 | 8 |

Median scan time 119 ms, p95 6929 ms.

Most frequent medium+ rules: `OBF-BIDI` (8), `PY-EXEC-DYNAMIC` (7), `JS-MODULE-COMPILE` (6), `PY-EXFIL-DNS` (5), `PY-SURVEILLANCE` (4), `OBF-INVISIBLE-CHARS` (3), `PY-EXEC-REMOTE` (2), `PY-SHELL-OBFUSCATED` (2), `IOC-RAW-IP-URL` (2), `PY-DROPPER` (2), `OBF-HEX-ESCAPES` (2), `NPM-INSTALL-SCRIPT` (2)

False positives (verdict suspicious or malicious):

- `multiprocess` 0.70.19 — malicious (93): PY-EXEC-REMOTE: py3.10/multiprocess/managers.py:989 content fetched from the network is passed to `exec` (via MakeProxyType() line 961); PY-EXEC-REMOTE: py3.11/multiprocess/managers.py:993 content fetched from the network is passed to `exec` (via MakeProxyType() line 965)
- `billiard` 4.3.2 — malicious (82): PY-EXEC-REMOTE: billiard/managers.py:917 content fetched from the network is passed to `exec` (via MakeProxyType() line 889); PY-EXEC-DYNAMIC: billiard/managers.py:889 `exec` is called with a non-literal argument
- `future` 1.0.0 — suspicious (49): IOC-RAW-IP-URL: tests/test_future/test_urlparse.py:388 URL pointing at a raw public IP address: http://12.34.56.78:5432/; PY-EXFIL-DNS: src/future/backports/urllib/request.py:1432 host fingerprint (hostname/user) flows into DNS lookups
- `widgetsnbextension` 4.0.16 — suspicious (36): OBF-BIDI: widgetsnbextension/static/extension.js:2 Unicode direction overrides make code render differently from how it executes (CVE-2021-42574)
- `curl-cffi` 0.17.0 — malicious (80): CORR-INSTALL-BEACON: scripts/build.py:134 environment variables flows into `urllib.request.urlretrieve` during package installation; the packa; PY-EXFIL: scripts/build.py:134 environment variables flows into `urllib.request.urlretrieve` during package installation
- `xgboost` 3.4.1 — malicious (79): PY-SHELL-OBFUSCATED: cpp_src/dmlc-core/tracker/dmlc_tracker/tracker.py:393 `subprocess.check_call` executes data that was decoded or downloaded; PY-EXFIL-DNS: cpp_src/dmlc-core/tracker/dmlc_tracker/tracker.py:435 host fingerprint (hostname/user) flows into DNS lookups
- `bandit` 1.9.4 — suspicious (37): OBF-BIDI: bandit/plugins/trojansource.py:22 Unicode direction overrides make code render differently from how it executes (CVE-2021-42574); OBF-BIDI: examples/trojansource.py:4 Unicode direction overrides make code render differently from how it executes (CVE-2021-42574)
- `awscrt` 0.38.2 — suspicious (33): PY-SHELL-EXFIL: setup.py:485 secret environment variables, environment variables reach `subprocess.check_call` during installatio; PY-SETUP-CMDCLASS: setup.py:368 class awscrt_build_ext overrides the `build_ext` command; its run() executes during `pip install`
- `pydeck` 0.9.3 — suspicious (38): NPM-LARGE-INSTALL-PAYLOAD: pydeck/nbextension/static/index.js:None pydeck/nbextension/static/index.js (4,269,385 bytes) runs during `npm install`; PY-SETUP-CMDCLASS: setup.py:58 class ExitHookDevelop overrides the `develop` command; its run() executes during `pip install`
- `effect` 4.1.5 — suspicious (49): OBF-BIDI: dist/http-api/internal/httpApiScalar.js:6 Unicode direction overrides make code render differently from how it executes (CVE-2021-42574); OBF-BIDI: src/http-api/internal/httpApiScalar.ts:11 Unicode direction overrides make code render differently from how it executes (CVE-2021-42574)
