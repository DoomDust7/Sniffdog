"""Catalog of every rule Sniffdog can emit (used by `sniffdog rules`, SARIF and the docs)."""

from __future__ import annotations

# rule id -> (short name, description, MITRE ATT&CK technique or "")
RULES: dict[str, tuple[str, str, str]] = {
    # --- Python data-flow
    "PY-EXFIL": (
        "Sensitive data sent over the network",
        "Taint analysis traced credentials, the environment, or host fingerprint data into an HTTP/socket/SMTP sink.",
        "T1041",
    ),
    "PY-EXFIL-DNS": (
        "Data exfiltration via DNS",
        "Tainted data is embedded in a hostname that gets resolved, a channel that bypasses most egress proxies.",
        "T1048.003",
    ),
    "PY-EXEC-REMOTE": ("Downloads and executes code", "Content fetched from the network reaches exec/eval/compile.", "T1105"),
    "PY-EXEC-OBFUSCATED": (
        "Executes obfuscated code",
        "Base64/zlib/hex/marshal/reversed data reaches exec/eval. Sniffdog statically unpacks constant payloads and analyses each layer.",
        "T1027",
    ),
    "PY-EXEC-DYNAMIC": ("Dynamic code execution", "exec/eval with a non-literal argument.", "T1059.006"),
    "PY-SHELL-DOWNLOAD": (
        "Shell command downloads or connects out",
        "A subprocess/os.system command contains curl|wget|PowerShell download cradles or reverse-shell idioms.",
        "T1059",
    ),
    "PY-SHELL-OBFUSCATED": ("Runs a decoded or downloaded command", "Decoded or downloaded data is passed to a shell.", "T1059"),
    "PY-SHELL-EXFIL": ("Secrets passed to a subprocess", "Secrets or host data reach a shell command at install time.", "T1041"),
    "PY-INSTALL-SUBPROCESS": ("Spawns a process during installation", "Informational: setup.py runs a subprocess.", ""),
    "PY-DETACHED-PROCESS": ("Detached background process during install", "A process that outlives pip is started from setup.py.", "T1059"),
    "PY-DOWNLOAD-EXECUTE": (
        "Downloads and runs an executable",
        "A file fetched from the network is executed in the same install/import-time function.",
        "T1105",
    ),
    "PY-DROPPER": ("Writes downloaded content to disk", "Downloaded bytes are written to a file (stage-2 dropper).", "T1105"),
    "PY-PERSISTENCE": (
        "Modifies a persistence location",
        "Writes shell rc files, cron, LaunchAgents, Startup folder, Run keys, systemd units or authorized_keys.",
        "T1547",
    ),
    "PY-OBFUSCATED-API": (
        "Obfuscated access to a dangerous function",
        "getattr() with a computed name that resolves to system/exec/eval/...",
        "T1027",
    ),
    "PY-OBFUSCATED-IMPORT": ("Obfuscated import", "__import__/import_module with a computed or decoded module name.", "T1027"),
    "PY-LOLBIN": ("Living-off-the-land binary", "Runs rundll32/regsvr32/mshta/certutil/... to proxy execution.", "T1218"),
    "PY-SELF-PUBLISH": ("Publishes packages from code", "Runs npm publish / twine upload: worm propagation or spam.", "T1195.002"),
    "PY-SHELLCODE": ("Shellcode loader primitives", "ctypes VirtualAlloc/CreateThread/RtlMoveMemory usage.", "T1055"),
    "PY-SURVEILLANCE": ("Surveillance capability", "Keylogging, screen capture, browser cookie or password decryption APIs.", "T1056"),
    "PY-PTH-EXEC": ("Executable .pth file", ".pth lines beginning with `import` run on every Python start-up.", "T1546"),
    "PY-SETUP-CMDCLASS": ("Custom install command", "setup.py overrides an install/develop/egg_info command.", ""),
    "PY-INTREE-BACKEND": ("In-tree build backend", "pyproject.toml uses backend-path to run bundled build code.", ""),
    # --- JavaScript data-flow
    "JS-EXFIL": (
        "Sensitive data sent over the network",
        "process.env, credential files or host data flow into http(s)/fetch/axios/net sinks.",
        "T1041",
    ),
    "JS-EXFIL-DNS": ("Data exfiltration via DNS", "Tainted data flows into dns.lookup/resolve.", "T1048.003"),
    "JS-EXEC-REMOTE": ("Downloads and executes code", "Network data reaches eval/Function/vm.", "T1105"),
    "JS-EXEC-OBFUSCATED": (
        "Executes obfuscated code",
        "Buffer.from(...,'base64')/atob/fromCharCode output reaches eval/Function/vm.",
        "T1027",
    ),
    "JS-EXEC-DYNAMIC": ("Dynamic code execution", "eval/Function with a non-literal argument.", "T1059.007"),
    "JS-SHELL-DOWNLOAD": ("Shell command downloads or connects out", "child_process runs a download cradle or reverse shell.", "T1059"),
    "JS-SHELL-OBFUSCATED": ("Runs a decoded or downloaded command", "child_process executes decoded or downloaded data.", "T1059"),
    "JS-SHELL-EXFIL": ("Secrets passed to a subprocess", "Secrets reach child_process during npm install.", "T1041"),
    "JS-LOLBIN": ("Living-off-the-land binary", "child_process runs rundll32/regsvr32/mshta/certutil/...", "T1218"),
    "JS-SELF-PUBLISH": (
        "Publishes packages from code",
        "child_process runs npm publish: worm propagation (Shai-Hulud) or spam.",
        "T1195.002",
    ),
    "JS-DETACHED-PROCESS": (
        "Detached process during install",
        "spawn(..., {detached: true}) from an install script outlives npm.",
        "T1059.007",
    ),
    "JS-PERSISTENCE": ("Modifies a persistence location", "fs writes to shell rc files, autostart locations or authorized_keys.", "T1547"),
    "JS-DROPPER": ("Writes downloaded content to disk", "Network data written to a file.", "T1105"),
    "JS-MODULE-COMPILE": (
        "Compiles code via Node's Module API",
        "new module.constructor()/_compile evaluates strings as modules (event-stream technique).",
        "T1059.007",
    ),
    "JS-OBFUSCATED-CALL": ("Method name decoded at runtime", "obj[decode(x)](...) dynamic dispatch hides which API is called.", "T1027"),
    "JS-OBFUSCATED-REQUIRE": ("Obfuscated require()", "Module name is decoded at runtime.", "T1027"),
    # --- manifests
    "NPM-INSTALL-SCRIPT": ("npm lifecycle script", "preinstall/install/postinstall hooks run arbitrary code on `npm install`.", ""),
    "NPM-SCRIPT-DOWNLOAD": (
        "Install script downloads or connects out",
        "A lifecycle script pipes curl/wget output to a shell or similar.",
        "T1105",
    ),
    "NPM-SCRIPT-INLINE": ("Install script runs inline code", "A lifecycle script uses node -e / eval / base64.", "T1027"),
    "NPM-LARGE-INSTALL-PAYLOAD": (
        "Large bundle executed at install time",
        "A >1 MB script runs on npm install; critical when it references token/credential stores (Shai-Hulud).",
        "T1195.002",
    ),
    "NPM-REMOTE-DEPENDENCY": ("Dependency fetched from a URL", "A dependency bypasses the registry (git/http URL).", "T1195.001"),
    # --- obfuscation
    "OBF-ENCODED-CODE": ("Encoded code embedded in source", "A long base64 string decodes to executable code.", "T1027"),
    "OBF-HIGH-ENTROPY": ("High-entropy string", "Packed or encrypted data embedded in source.", "T1027"),
    "OBF-HEX-ESCAPES": ("Long hex-escaped string", "A long run of \\xNN escapes hides string content.", "T1027"),
    "OBF-JS-OBFUSCATOR": ("javascript-obfuscator output", "_0x-style identifiers produced by javascript-obfuscator.", "T1027"),
    "OBF-WHITESPACE-HIDING": ("Code hidden off-screen", "Code padded with hundreds of spaces to hide it from reviewers.", "T1027"),
    "OBF-BIDI": ("Trojan Source", "Unicode bidi overrides (CVE-2021-42574).", "T1027"),
    "OBF-INVISIBLE-CHARS": ("Invisible characters in code", "Zero-width characters that create look-alike identifiers.", "T1027"),
    # --- indicators
    "IOC-DISCORD-WEBHOOK": ("Discord webhook", "Common exfiltration drop for stealers.", "T1567"),
    "IOC-TELEGRAM-BOT": ("Telegram bot API", "Embedded bot token used as an exfiltration channel.", "T1567"),
    "IOC-PASTE-SITE": ("Raw paste-site URL", "Paste sites host second-stage payloads.", "T1102"),
    "IOC-TUNNEL": ("Ephemeral tunnel endpoint", "ngrok/serveo/trycloudflare endpoints hide attacker infrastructure.", "T1572"),
    "IOC-OAST": (
        "Out-of-band interaction service",
        "Burp Collaborator/interactsh/webhook.site style callbacks (dependency-confusion beacons).",
        "T1041",
    ),
    "IOC-FILE-DROP": ("Anonymous file-sharing service", "transfer.sh/file.io style uploads.", "T1567"),
    "IOC-ONION": ("Tor hidden service", "Embedded .onion address.", "T1090.003"),
    "IOC-RAW-IP-SOCKET": ("Hard-coded IP with raw sockets", "Public IP literal in a file that opens raw TCP/UDP sockets.", "T1095"),
    "IOC-RAW-IP-URL": ("URL with a raw public IP", "Hard-coded IP-address endpoints.", "T1071"),
    "IOC-DISCORD-TOKEN-REGEX": ("Discord token grabber", "Regex used to scrape Discord auth tokens.", "T1528"),
    "IOC-CRYPTO-CLIPPER": ("Cryptocurrency clipper", "Wallet address combined with clipboard access.", "T1115"),
    # --- binaries / archive / metadata
    "BIN-DISGUISED": ("Executable disguised as another file type", "ELF/PE/Mach-O binary with an image/text extension.", "T1036"),
    "BIN-LOADED-AT-INSTALL": (
        "Install script runs a bundled binary",
        "An install-time script references a shipped PE/ELF/Mach-O file (e.g. rundll32 node-gyp.dll).",
        "T1218.011",
    ),
    "BIN-EXECUTABLE": ("Bundled executable", "Package ships a standalone executable.", "T1204"),
    "BIN-PREBUILT-IN-SDIST": ("Prebuilt binary in source distribution", "Compiled library shipped in an sdist.", ""),
    "ARCHIVE-PATH-TRAVERSAL": ("Archive path traversal", "Member path contains `..` (zip-slip).", "T1222"),
    "ARCHIVE-ABSOLUTE-PATH": ("Archive absolute path", "Member path is absolute.", "T1222"),
    "ARCHIVE-LINK-ESCAPES-PACKAGE": ("Symlink escapes package", "Link target points outside the package.", "T1222"),
    "ARCHIVE-DEVICE-FILE": ("Device file in archive", "Character/block device or FIFO member.", ""),
    "ARCHIVE-DECOMPRESSION-BOMB": ("Decompression bomb", "Extreme compression ratio.", "T1499"),
    "ARCHIVE-SYMLINK": ("Symlink", "Symbolic link in package directory.", ""),
    "ARCHIVE-UNREADABLE-MEMBER": ("Unreadable member", "Archive member could not be decompressed.", ""),
    "ARCHIVE-LIMIT": ("Scan limits reached", "Part of the artifact was not analysed.", ""),
    "TYPOSQUAT": (
        "Possible typosquat",
        "Name imitates a top-downloaded package (edit distance, homoglyphs, separators, affixes, token order, npm scopes).",
        "T1195.001",
    ),
    "DEP-CONFUSION": ("Dependency confusion", "An internal package name also exists on the public registry.", "T1195.001"),
    "META-NEW-PACKAGE": ("Very new package", "First published less than 30 days ago.", ""),
    "META-DORMANT-REVIVED": ("Fresh release of an old package", "New version of an established package.", ""),
    "META-NO-SOURCE": ("No source repository", "No repository/homepage in metadata.", ""),
    "META-NO-DESCRIPTION": ("Empty description", "No package description.", ""),
    # --- correlation
    "CORR-TYPOSQUAT-PAYLOAD": (
        "Typosquat with malicious behaviour",
        "A look-alike name combined with exfiltration, obfuscation or remote execution.",
        "T1195.001",
    ),
    "CORR-OBFUSCATED-NETWORK": ("Obfuscation next to network activity", "Obfuscated code and exfiltration/IOCs in the same file.", "T1027"),
    "CORR-INSTALL-BEACON": (
        "Install-time beacon to attacker infrastructure",
        "Data exfiltrated during install plus an OAST/tunnel/raw-IP/webhook endpoint in the package.",
        "T1041",
    ),
    "CORR-NEW-INSTALL-HOOK": ("New package with install-time code", "Brand-new package that runs code during installation.", "T1195.002"),
}


def describe(rule_id: str) -> tuple[str, str, str]:
    return RULES.get(rule_id, (rule_id, "", ""))
