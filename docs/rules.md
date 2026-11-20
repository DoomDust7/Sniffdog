# Detection rules

Sniffdog ships **83 rules**. Generated from `src/sniffdog/rules.py`.

## Python data-flow & behaviour

| Rule | Name | MITRE ATT&CK | Description |
|---|---|---|---|
| <a id="py-exfil"></a>`PY-EXFIL` | Sensitive data sent over the network | [T1041](https://attack.mitre.org/techniques/T1041/) | Taint analysis traced credentials, the environment, or host fingerprint data into an HTTP/socket/SMTP sink. |
| <a id="py-exfil-dns"></a>`PY-EXFIL-DNS` | Data exfiltration via DNS | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Tainted data is embedded in a hostname that gets resolved, a channel that bypasses most egress proxies. |
| <a id="py-exec-remote"></a>`PY-EXEC-REMOTE` | Downloads and executes code | [T1105](https://attack.mitre.org/techniques/T1105/) | Content fetched from the network reaches exec/eval/compile. |
| <a id="py-exec-obfuscated"></a>`PY-EXEC-OBFUSCATED` | Executes obfuscated code | [T1027](https://attack.mitre.org/techniques/T1027/) | Base64/zlib/hex/marshal/reversed data reaches exec/eval. Sniffdog statically unpacks constant payloads and analyses each layer. |
| <a id="py-exec-dynamic"></a>`PY-EXEC-DYNAMIC` | Dynamic code execution | [T1059.006](https://attack.mitre.org/techniques/T1059/006/) | exec/eval with a non-literal argument. |
| <a id="py-shell-download"></a>`PY-SHELL-DOWNLOAD` | Shell command downloads or connects out | [T1059](https://attack.mitre.org/techniques/T1059/) | A subprocess/os.system command contains curl|wget|PowerShell download cradles or reverse-shell idioms. |
| <a id="py-shell-obfuscated"></a>`PY-SHELL-OBFUSCATED` | Runs a decoded or downloaded command | [T1059](https://attack.mitre.org/techniques/T1059/) | Decoded or downloaded data is passed to a shell. |
| <a id="py-shell-exfil"></a>`PY-SHELL-EXFIL` | Secrets passed to a subprocess | [T1041](https://attack.mitre.org/techniques/T1041/) | Secrets or host data reach a shell command at install time. |
| <a id="py-install-subprocess"></a>`PY-INSTALL-SUBPROCESS` | Spawns a process during installation |  | Informational: setup.py runs a subprocess. |
| <a id="py-detached-process"></a>`PY-DETACHED-PROCESS` | Detached background process during install | [T1059](https://attack.mitre.org/techniques/T1059/) | A process that outlives pip is started from setup.py. |
| <a id="py-download-execute"></a>`PY-DOWNLOAD-EXECUTE` | Downloads and runs an executable | [T1105](https://attack.mitre.org/techniques/T1105/) | A file fetched from the network is executed in the same install/import-time function. |
| <a id="py-dropper"></a>`PY-DROPPER` | Writes downloaded content to disk | [T1105](https://attack.mitre.org/techniques/T1105/) | Downloaded bytes are written to a file (stage-2 dropper). |
| <a id="py-persistence"></a>`PY-PERSISTENCE` | Modifies a persistence location | [T1547](https://attack.mitre.org/techniques/T1547/) | Writes shell rc files, cron, LaunchAgents, Startup folder, Run keys, systemd units or authorized_keys. |
| <a id="py-obfuscated-api"></a>`PY-OBFUSCATED-API` | Obfuscated access to a dangerous function | [T1027](https://attack.mitre.org/techniques/T1027/) | getattr() with a computed name that resolves to system/exec/eval/... |
| <a id="py-obfuscated-import"></a>`PY-OBFUSCATED-IMPORT` | Obfuscated import | [T1027](https://attack.mitre.org/techniques/T1027/) | __import__/import_module with a computed or decoded module name. |
| <a id="py-lolbin"></a>`PY-LOLBIN` | Living-off-the-land binary | [T1218](https://attack.mitre.org/techniques/T1218/) | Runs rundll32/regsvr32/mshta/certutil/... to proxy execution. |
| <a id="py-self-publish"></a>`PY-SELF-PUBLISH` | Publishes packages from code | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Runs npm publish / twine upload: worm propagation or spam. |
| <a id="py-shellcode"></a>`PY-SHELLCODE` | Shellcode loader primitives | [T1055](https://attack.mitre.org/techniques/T1055/) | ctypes VirtualAlloc/CreateThread/RtlMoveMemory usage. |
| <a id="py-surveillance"></a>`PY-SURVEILLANCE` | Surveillance capability | [T1056](https://attack.mitre.org/techniques/T1056/) | Keylogging, screen capture, browser cookie or password decryption APIs. |
| <a id="py-pth-exec"></a>`PY-PTH-EXEC` | Executable .pth file | [T1546](https://attack.mitre.org/techniques/T1546/) | .pth lines beginning with `import` run on every Python start-up. |
| <a id="py-setup-cmdclass"></a>`PY-SETUP-CMDCLASS` | Custom install command |  | setup.py overrides an install/develop/egg_info command. |
| <a id="py-intree-backend"></a>`PY-INTREE-BACKEND` | In-tree build backend |  | pyproject.toml uses backend-path to run bundled build code. |

## JavaScript data-flow & behaviour

| Rule | Name | MITRE ATT&CK | Description |
|---|---|---|---|
| <a id="js-exfil"></a>`JS-EXFIL` | Sensitive data sent over the network | [T1041](https://attack.mitre.org/techniques/T1041/) | process.env, credential files or host data flow into http(s)/fetch/axios/net sinks. |
| <a id="js-exfil-dns"></a>`JS-EXFIL-DNS` | Data exfiltration via DNS | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Tainted data flows into dns.lookup/resolve. |
| <a id="js-exec-remote"></a>`JS-EXEC-REMOTE` | Downloads and executes code | [T1105](https://attack.mitre.org/techniques/T1105/) | Network data reaches eval/Function/vm. |
| <a id="js-exec-obfuscated"></a>`JS-EXEC-OBFUSCATED` | Executes obfuscated code | [T1027](https://attack.mitre.org/techniques/T1027/) | Buffer.from(...,'base64')/atob/fromCharCode output reaches eval/Function/vm. |
| <a id="js-exec-dynamic"></a>`JS-EXEC-DYNAMIC` | Dynamic code execution | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | eval/Function with a non-literal argument. |
| <a id="js-shell-download"></a>`JS-SHELL-DOWNLOAD` | Shell command downloads or connects out | [T1059](https://attack.mitre.org/techniques/T1059/) | child_process runs a download cradle or reverse shell. |
| <a id="js-shell-obfuscated"></a>`JS-SHELL-OBFUSCATED` | Runs a decoded or downloaded command | [T1059](https://attack.mitre.org/techniques/T1059/) | child_process executes decoded or downloaded data. |
| <a id="js-shell-exfil"></a>`JS-SHELL-EXFIL` | Secrets passed to a subprocess | [T1041](https://attack.mitre.org/techniques/T1041/) | Secrets reach child_process during npm install. |
| <a id="js-lolbin"></a>`JS-LOLBIN` | Living-off-the-land binary | [T1218](https://attack.mitre.org/techniques/T1218/) | child_process runs rundll32/regsvr32/mshta/certutil/... |
| <a id="js-self-publish"></a>`JS-SELF-PUBLISH` | Publishes packages from code | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | child_process runs npm publish: worm propagation (Shai-Hulud) or spam. |
| <a id="js-detached-process"></a>`JS-DETACHED-PROCESS` | Detached process during install | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | spawn(..., {detached: true}) from an install script outlives npm. |
| <a id="js-persistence"></a>`JS-PERSISTENCE` | Modifies a persistence location | [T1547](https://attack.mitre.org/techniques/T1547/) | fs writes to shell rc files, autostart locations or authorized_keys. |
| <a id="js-dropper"></a>`JS-DROPPER` | Writes downloaded content to disk | [T1105](https://attack.mitre.org/techniques/T1105/) | Network data written to a file. |
| <a id="js-module-compile"></a>`JS-MODULE-COMPILE` | Compiles code via Node's Module API | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | new module.constructor()/_compile evaluates strings as modules (event-stream technique). |
| <a id="js-obfuscated-call"></a>`JS-OBFUSCATED-CALL` | Method name decoded at runtime | [T1027](https://attack.mitre.org/techniques/T1027/) | obj[decode(x)](...) dynamic dispatch hides which API is called. |
| <a id="js-obfuscated-require"></a>`JS-OBFUSCATED-REQUIRE` | Obfuscated require() | [T1027](https://attack.mitre.org/techniques/T1027/) | Module name is decoded at runtime. |

## Install manifests

| Rule | Name | MITRE ATT&CK | Description |
|---|---|---|---|
| <a id="npm-install-script"></a>`NPM-INSTALL-SCRIPT` | npm lifecycle script |  | preinstall/install/postinstall hooks run arbitrary code on `npm install`. |
| <a id="npm-script-download"></a>`NPM-SCRIPT-DOWNLOAD` | Install script downloads or connects out | [T1105](https://attack.mitre.org/techniques/T1105/) | A lifecycle script pipes curl/wget output to a shell or similar. |
| <a id="npm-script-inline"></a>`NPM-SCRIPT-INLINE` | Install script runs inline code | [T1027](https://attack.mitre.org/techniques/T1027/) | A lifecycle script uses node -e / eval / base64. |
| <a id="npm-large-install-payload"></a>`NPM-LARGE-INSTALL-PAYLOAD` | Large bundle executed at install time | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | A >1 MB script runs on npm install; critical when it references token/credential stores (Shai-Hulud). |
| <a id="npm-remote-dependency"></a>`NPM-REMOTE-DEPENDENCY` | Dependency fetched from a URL | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | A dependency bypasses the registry (git/http URL). |

## Obfuscation

| Rule | Name | MITRE ATT&CK | Description |
|---|---|---|---|
| <a id="obf-encoded-code"></a>`OBF-ENCODED-CODE` | Encoded code embedded in source | [T1027](https://attack.mitre.org/techniques/T1027/) | A long base64 string decodes to executable code. |
| <a id="obf-high-entropy"></a>`OBF-HIGH-ENTROPY` | High-entropy string | [T1027](https://attack.mitre.org/techniques/T1027/) | Packed or encrypted data embedded in source. |
| <a id="obf-hex-escapes"></a>`OBF-HEX-ESCAPES` | Long hex-escaped string | [T1027](https://attack.mitre.org/techniques/T1027/) | A long run of \xNN escapes hides string content. |
| <a id="obf-js-obfuscator"></a>`OBF-JS-OBFUSCATOR` | javascript-obfuscator output | [T1027](https://attack.mitre.org/techniques/T1027/) | _0x-style identifiers produced by javascript-obfuscator. |
| <a id="obf-whitespace-hiding"></a>`OBF-WHITESPACE-HIDING` | Code hidden off-screen | [T1027](https://attack.mitre.org/techniques/T1027/) | Code padded with hundreds of spaces to hide it from reviewers. |
| <a id="obf-bidi"></a>`OBF-BIDI` | Trojan Source | [T1027](https://attack.mitre.org/techniques/T1027/) | Unicode bidi overrides (CVE-2021-42574). |
| <a id="obf-invisible-chars"></a>`OBF-INVISIBLE-CHARS` | Invisible characters in code | [T1027](https://attack.mitre.org/techniques/T1027/) | Zero-width characters that create look-alike identifiers. |

## Indicators of compromise

| Rule | Name | MITRE ATT&CK | Description |
|---|---|---|---|
| <a id="ioc-discord-webhook"></a>`IOC-DISCORD-WEBHOOK` | Discord webhook | [T1567](https://attack.mitre.org/techniques/T1567/) | Common exfiltration drop for stealers. |
| <a id="ioc-telegram-bot"></a>`IOC-TELEGRAM-BOT` | Telegram bot API | [T1567](https://attack.mitre.org/techniques/T1567/) | Embedded bot token used as an exfiltration channel. |
| <a id="ioc-paste-site"></a>`IOC-PASTE-SITE` | Raw paste-site URL | [T1102](https://attack.mitre.org/techniques/T1102/) | Paste sites host second-stage payloads. |
| <a id="ioc-tunnel"></a>`IOC-TUNNEL` | Ephemeral tunnel endpoint | [T1572](https://attack.mitre.org/techniques/T1572/) | ngrok/serveo/trycloudflare endpoints hide attacker infrastructure. |
| <a id="ioc-oast"></a>`IOC-OAST` | Out-of-band interaction service | [T1041](https://attack.mitre.org/techniques/T1041/) | Burp Collaborator/interactsh/webhook.site style callbacks (dependency-confusion beacons). |
| <a id="ioc-file-drop"></a>`IOC-FILE-DROP` | Anonymous file-sharing service | [T1567](https://attack.mitre.org/techniques/T1567/) | transfer.sh/file.io style uploads. |
| <a id="ioc-onion"></a>`IOC-ONION` | Tor hidden service | [T1090.003](https://attack.mitre.org/techniques/T1090/003/) | Embedded .onion address. |
| <a id="ioc-raw-ip-socket"></a>`IOC-RAW-IP-SOCKET` | Hard-coded IP with raw sockets | [T1095](https://attack.mitre.org/techniques/T1095/) | Public IP literal in a file that opens raw TCP/UDP sockets. |
| <a id="ioc-raw-ip-url"></a>`IOC-RAW-IP-URL` | URL with a raw public IP | [T1071](https://attack.mitre.org/techniques/T1071/) | Hard-coded IP-address endpoints. |
| <a id="ioc-discord-token-regex"></a>`IOC-DISCORD-TOKEN-REGEX` | Discord token grabber | [T1528](https://attack.mitre.org/techniques/T1528/) | Regex used to scrape Discord auth tokens. |
| <a id="ioc-crypto-clipper"></a>`IOC-CRYPTO-CLIPPER` | Cryptocurrency clipper | [T1115](https://attack.mitre.org/techniques/T1115/) | Wallet address combined with clipboard access. |

## Binaries

| Rule | Name | MITRE ATT&CK | Description |
|---|---|---|---|
| <a id="bin-disguised"></a>`BIN-DISGUISED` | Executable disguised as another file type | [T1036](https://attack.mitre.org/techniques/T1036/) | ELF/PE/Mach-O binary with an image/text extension. |
| <a id="bin-loaded-at-install"></a>`BIN-LOADED-AT-INSTALL` | Install script runs a bundled binary | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | An install-time script references a shipped PE/ELF/Mach-O file (e.g. rundll32 node-gyp.dll). |
| <a id="bin-executable"></a>`BIN-EXECUTABLE` | Bundled executable | [T1204](https://attack.mitre.org/techniques/T1204/) | Package ships a standalone executable. |
| <a id="bin-prebuilt-in-sdist"></a>`BIN-PREBUILT-IN-SDIST` | Prebuilt binary in source distribution |  | Compiled library shipped in an sdist. |

## Archive anomalies

| Rule | Name | MITRE ATT&CK | Description |
|---|---|---|---|
| <a id="archive-path-traversal"></a>`ARCHIVE-PATH-TRAVERSAL` | Archive path traversal | [T1222](https://attack.mitre.org/techniques/T1222/) | Member path contains `..` (zip-slip). |
| <a id="archive-absolute-path"></a>`ARCHIVE-ABSOLUTE-PATH` | Archive absolute path | [T1222](https://attack.mitre.org/techniques/T1222/) | Member path is absolute. |
| <a id="archive-link-escapes-package"></a>`ARCHIVE-LINK-ESCAPES-PACKAGE` | Symlink escapes package | [T1222](https://attack.mitre.org/techniques/T1222/) | Link target points outside the package. |
| <a id="archive-device-file"></a>`ARCHIVE-DEVICE-FILE` | Device file in archive |  | Character/block device or FIFO member. |
| <a id="archive-decompression-bomb"></a>`ARCHIVE-DECOMPRESSION-BOMB` | Decompression bomb | [T1499](https://attack.mitre.org/techniques/T1499/) | Extreme compression ratio. |
| <a id="archive-symlink"></a>`ARCHIVE-SYMLINK` | Symlink |  | Symbolic link in package directory. |
| <a id="archive-unreadable-member"></a>`ARCHIVE-UNREADABLE-MEMBER` | Unreadable member |  | Archive member could not be decompressed. |
| <a id="archive-limit"></a>`ARCHIVE-LIMIT` | Scan limits reached |  | Part of the artifact was not analysed. |

## Name-based attacks

| Rule | Name | MITRE ATT&CK | Description |
|---|---|---|---|
| <a id="typosquat"></a>`TYPOSQUAT` | Possible typosquat | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | Name imitates a top-downloaded package (edit distance, homoglyphs, separators, affixes, token order, npm scopes). |

| <a id="dep-confusion"></a>`DEP-CONFUSION` | Dependency confusion | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | An internal package name also exists on the public registry. |

## Registry reputation

| Rule | Name | MITRE ATT&CK | Description |
|---|---|---|---|
| <a id="meta-new-package"></a>`META-NEW-PACKAGE` | Very new package |  | First published less than 30 days ago. |
| <a id="meta-dormant-revived"></a>`META-DORMANT-REVIVED` | Fresh release of an old package |  | New version of an established package. |
| <a id="meta-no-source"></a>`META-NO-SOURCE` | No source repository |  | No repository/homepage in metadata. |
| <a id="meta-no-description"></a>`META-NO-DESCRIPTION` | Empty description |  | No package description. |

## Correlation (kill-chain) rules

| Rule | Name | MITRE ATT&CK | Description |
|---|---|---|---|
| <a id="corr-typosquat-payload"></a>`CORR-TYPOSQUAT-PAYLOAD` | Typosquat with malicious behaviour | [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | A look-alike name combined with exfiltration, obfuscation or remote execution. |
| <a id="corr-obfuscated-network"></a>`CORR-OBFUSCATED-NETWORK` | Obfuscation next to network activity | [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated code and exfiltration/IOCs in the same file. |
| <a id="corr-install-beacon"></a>`CORR-INSTALL-BEACON` | Install-time beacon to attacker infrastructure | [T1041](https://attack.mitre.org/techniques/T1041/) | Data exfiltrated during install plus an OAST/tunnel/raw-IP/webhook endpoint in the package. |
| <a id="corr-new-install-hook"></a>`CORR-NEW-INSTALL-HOOK` | New package with install-time code | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Brand-new package that runs code during installation. |
