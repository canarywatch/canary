"""The rules. Static analysis of a package's files, nothing is ever executed.

Every rule returns Findings with the file, the line and the matched snippet, so a catch on the
wall always carries its evidence. Scores add up; the verdict thresholds live in `verdict()`.

The rules are deliberately conservative on well-known packages: a package with a long history
and real download numbers is never put on the wall by heuristics alone (see `is_established`),
only when a public advisory confirms it. New and unknown packages are where supply-chain
attacks live, and that is where the heuristics bite.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from typing import Iterable

# ---------------------------------------------------------------- what a package looks like here

@dataclass
class File:
    path: str
    data: bytes

    @property
    def text(self) -> str:
        try:
            return self.data.decode("utf-8")
        except UnicodeDecodeError:
            return self.data.decode("latin-1", errors="replace")


@dataclass
class Package:
    ecosystem: str              # "npm" | "pypi"
    name: str
    version: str
    files: list[File]
    manifest: dict = field(default_factory=dict)      # package.json / pypi json "info"
    age_days: float | None = None                     # since the first ever release
    version_age_h: float | None = None                # since this version was published
    weekly_downloads: int | None = None
    repository: str | None = None


@dataclass
class Finding:
    rule: str                   # short id, e.g. "install-hook"
    weight: int
    file: str
    line: int
    snippet: str
    note: str = ""

    def to_json(self) -> dict:
        return {"rule": self.rule, "weight": self.weight, "file": self.file, "line": self.line,
                "snippet": self.snippet[:240], "note": self.note}


# ---------------------------------------------------------------- helpers

CODE_EXT = (".js", ".cjs", ".mjs", ".ts", ".jsx", ".tsx", ".json", ".sh", ".py", ".cfg", ".toml", ".pth", ".ps1", ".bat", ".cmd")
TEXT_MAX = 2_000_000           # bytes of one file we bother reading
SNIP = 160


def _lines(text: str) -> Iterable[tuple[int, str]]:
    for i, ln in enumerate(text.split("\n"), 1):
        yield i, ln


_PY_TRIPLE = re.compile(r'"""|\'\'\'')
_PY_DOC_START = ('"""', "\'\'\'", 'r"""', "r\'\'\'", 'u"""', "u\'\'\'", 'R"""', 'U"""')


def _code_lines(text: str, path: str = "") -> Iterable[tuple[int, str]]:
    """only the lines that can run: no comment lines, no python docstrings, no js block comments.
    a triple-quoted string that is assigned or passed (x = \"\"\"...) is kept, since exec() can read it."""
    p = path.lower().split("#", 1)[0]
    py = p.endswith((".py", ".pth", ".pyi"))
    in_doc = False
    in_block = False
    for i, ln in enumerate(text.split("\n"), 1):
        st = ln.lstrip()
        if not st:
            continue
        if py:
            n = len(_PY_TRIPLE.findall(ln))
            if in_doc:
                if n % 2 == 1:
                    in_doc = False
                continue
            if st.startswith(_PY_DOC_START):
                if n % 2 == 1:
                    in_doc = True
                continue
        else:
            if in_block:
                if "*/" in ln:
                    in_block = False
                continue
            if st.startswith("/*"):
                if "*/" not in ln:
                    in_block = True
                continue
        if _comment(ln):
            continue
        yield i, ln


def _in_string(ln: str, pos: int) -> bool:
    """is position pos inside a quoted string on this line (odd number of unescaped quotes before it)"""
    head = ln[:pos]
    for q in ('"', "'", "`"):
        if len(re.findall(r"(?<!\\)" + q, head)) % 2 == 1:
            return True
    return False


def _snip(ln: str, m: re.Match | None = None) -> str:
    if m is None:
        return ln.strip()[:SNIP]
    a = max(0, m.start() - 50)
    return ln[a:a + SNIP].strip()


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _comment(ln: str) -> bool:
    return ln.lstrip().startswith(("#", "//", "*", "/*", '"""', "\'\'\'", "<!--"))


AUX_DIRS = {"test", "tests", "__tests__", "spec", "specs", "docs", "doc", "examples", "example", "fixtures", "fixture", "benchmark", "benchmarks", "samples", "sample", "scripts"}


def _is_aux(path: str) -> bool:
    """tests, docs, examples and dot-directories (.github, .devcontainer, .vscode): full of throwaway ips,
    fake secrets and ci commands, and nothing runs them on install"""
    return any(part.lower() in AUX_DIRS or part.startswith(".") for part in path.split("/")[:-1])


def _pattern_line(ln: str) -> bool:
    """a line that defines a regex or a word list (a scanner's own rules) is not a command"""
    st = ln.lstrip()
    return "re.compile(" in ln or ln.count("|") >= 15 or st.startswith(('(r"', "(r'", 'r"', "r'", "[r'", '[r"', "/^", "new RegExp("))


def hooked(pkg: Package) -> set[str]:
    """files an install script points at: those are never 'just tests', wherever they sit"""
    cached = pkg.__dict__.get("_hooked")
    if cached is not None:
        return cached
    out: set[str] = set()
    scripts = (pkg.manifest.get("scripts") or {}) if isinstance(pkg.manifest, dict) else {}
    text = " ".join(str(v) for k, v in scripts.items() if k in ("preinstall", "install", "postinstall", "prepare", "preuninstall", "postuninstall"))
    paths = {f.path for f in pkg.files}
    for tok in re.findall(r"[\w./@-]+", text):
        tok = tok.lstrip("./")
        for cand in (tok, tok + ".js", tok + ".mjs", tok + ".cjs", tok + ".py", tok + "/index.js"):
            if cand in paths:
                out.add(cand)
    pkg.__dict__["_hooked"] = out
    return out


def _aux(pkg: Package, path: str) -> bool:
    return _is_aux(path) and path.split("#", 1)[0] not in hooked(pkg)


def _decoded_code(blob: str) -> str | None:
    """base64 that decodes to readable code; images, fonts, wasm and sourcemaps decode to noise"""
    try:
        dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)[:4000]
    except Exception:  # noqa: BLE001
        return None
    if dec[:2] == b"\x1f\x8b":
        try:
            dec = gzip.decompress(dec)[:4000]
        except Exception:  # noqa: BLE001
            return None
    try:
        dt = dec.decode("utf-8")
    except UnicodeDecodeError:
        return None
    head = dt[:2000]
    if not head or sum(ch.isprintable() or ch in "\n\r\t" for ch in head) < len(head) * 0.95:
        return None
    if re.search(r"require\(|import\s|process\.|child_process|exec\(|eval\(|fetch\(|https?://|subprocess|os\.system|powershell|/bin/sh", dt, re.I):
        return dt
    return None


def _is_text(data: bytes) -> bool:
    return b"\x00" not in data[:4096]


def _is_code(path: str) -> bool:
    p = path.lower()
    return p.endswith(CODE_EXT) or "/bin/" in p or p.endswith("setup.py") or p.endswith("<decoded>")


def _is_minified_vendor(path: str, text: str) -> bool:
    """bundled/minified third-party code is noisy and not where supply-chain payloads hide.
    we still scan it for the strong signals (exfil, webhooks), but not for obfuscation shape."""
    p = path.lower().split("#", 1)[0]
    if ".min." in p or re.search(r"(^|/)(dist|vendor|build|umd|assets|chunks|static|public|_next|\.next|node_modules)/", p):
        return True
    if p.endswith((".bundle.js", ".chunk.js", ".umd.js", ".esm.js", ".iife.js", ".cjs.js")):
        return True
    m = re.search(r"[-.]([a-z0-9_]{8})\.m?js$", p)          # vite / webpack content hashes: app-BU3dzTBu.js
    if m and any(ch.isdigit() for ch in m.group(1)):
        return True
    lines = text.count("\n") + 1
    return len(text) > 20_000 and len(text) / lines > 400


# ---------------------------------------------------------------- the patterns

RX_EVAL = re.compile(r"\b(eval|Function)\s*\(\s*(atob|Buffer\.from|unescape|decodeURIComponent|String\.fromCharCode|[a-zA-Z_$][\w$]*\s*\()", re.I)
RX_EVAL_DECODE = re.compile(r"\b(eval|Function)\s*\(\s*(atob|Buffer\.from|unescape|decodeURIComponent|String\.fromCharCode)", re.I)
RX_FROMCHARCODE = re.compile(r"String\.fromCharCode\((\s*\d+\s*,\s*){8,}")
RX_HEX_RUN = re.compile(r"(\\x[0-9a-fA-F]{2}){12,}")
RX_B64_BLOB = re.compile(r"['\"`]([A-Za-z0-9+/=]{200,})['\"`]")
RX_ENV = re.compile(r"process\.env\b|os\.environ\b|os\.getenv\(|\$\{?HOME\b|os\.homedir\(|homedir\(|expanduser\(")
RX_SECRET_PATHS = re.compile(r"\.ssh/|id_rsa\b|id_ed25519\b|\.npmrc\b|\.pypirc\b|\.aws/credentials|\.docker/config\.json|\.git-credentials|\.netrc\b|\.kube/config|\.gnupg/|\.config/solana|solana/id\.json|Local Storage/leveldb|/Exodus/|/Electrum/|\.bitcoin/|wallet\.dat|Login Data|\.bash_history|/etc/shadow", re.I)
RX_READ = re.compile(r"\bopen\s*\(|readFileSync|readFile\b|read_text\(|read_bytes\(|\.read\(|createReadStream|copyFile|copyfile|shutil\.copy|\bcat\s|Get-Content|\btype\s+[\w\\%]|os\.listdir|glob\.glob|readdirSync|walk\(|xcopy|\bcp\s+-r", re.I)
RX_NET = re.compile(r"https?\.request\(|https?\.get\(|\bfetch\(|axios[.(]|got\(|node-fetch|XMLHttpRequest|net\.connect\(|dgram\.|dns\.resolve|\brequests\.(post|get|put)\(|urllib\.request|urlopen\(|http\.client|socket\.socket\(|curl\s|wget\s|Invoke-WebRequest|Net\.WebClient", re.I)
RX_WEBHOOK = re.compile(r"discord(app)?\.com/api/webhooks/\d+|api\.telegram\.org/bot\d+:|hooks\.slack\.com/services/T|pastebin\.com/raw/|burpcollaborator\.net|oastify\.com|interact\.sh\b(?![\w])|webhook\.site/", re.I)
RX_SHELL = re.compile(r"child_process|execSync\(|spawnSync\(|\bexec\(\s*['\"]|subprocess\.(run|call|Popen|check_output)|os\.system\(|os\.popen\(", re.I)
RX_DOWNLOAD_EXEC = re.compile(r"(curl|wget|Invoke-WebRequest|iwr|certutil\s+-urlcache|bitsadmin)[^\n]{0,200}(\|\s*(sh|bash|zsh|python3?|node|powershell|pwsh)\b|&&\s*(chmod\s+\+x|sh |bash |\./|python|node ))|powershell[^\n]{0,80}(-enc|-e |EncodedCommand|hidden)", re.I)
KNOWN_INSTALLERS = re.compile(r"https?://(?:[\w-]+\.)*(astral\.sh|get\.docker\.com|(deb|rpm)\.nodesource\.com|sh\.rustup\.rs|rustup\.rs|get\.pnpm\.io|bun\.sh|deno\.land|brew\.sh|raw\.githubusercontent\.com/(Homebrew|nvm-sh|creationix|ohmyzsh|rbenv|pyenv)|install\.python-poetry\.org|get\.sdkman\.io|nvm\.sh|get\.helm\.sh|claude\.ai/install|cli\.github\.com|pyenv\.run|get\.volta\.sh|mise\.run|ollama\.com/install|tailscale\.com/install|get\.k3s\.io|getcomposer\.org|fnm\.vercel\.app|install\.determinate\.systems|nixos\.org/nix|yarnpkg\.com/install|get\.jetify\.com|install\.ohmyz\.sh|get\.rvm\.io|cursor\.com/install|repo\.anaconda\.com|dl\.k8s\.io|get\.rke2\.io|get\.opentofu\.org|releases\.hashicorp\.com|dl\.google\.com|go\.dev/dl|sdk\.cloud\.google\.com|aka\.ms|dot\.net|packages\.microsoft\.com|get\.pulumi\.com|install\.ruff\.rs|uv\.astral\.sh|bootstrap\.pypa\.io|raw\.githubusercontent\.com/pypa|get\.pdm-project\.org|pixi\.sh|conda\.io|downloads\.python\.org|nodejs\.org/dist|npmjs\.com/install)", re.I)
RX_CHMOD_RUN = re.compile(r"\bchmod\s+\+x\b[^\n]{0,120}&&\s*\./", re.I)
RX_REVSHELL = re.compile(r"/bin/(ba)?sh\s+-i\s*[<>&|]|\bnc(\.traditional)?\s+(-e|-c)\s|\bncat\s[^\n]*(-e|--exec)|/dev/(tcp|udp)/(?!localhost|127\.|0\.0\.0\.0)|socket\.socket\([^)]*\)[^\n]{0,200}(dup2|pty\.spawn)|\bmkfifo\s[^\n]{0,120}\|\s*(/bin/)?(nc|sh|bash)\b|bash\s+-c\s*['\"][^'\"]*\$\(", re.I)
RX_PERSIST = re.compile(r"crontab\s+-|/etc/cron\.|schtasks\s+/create|CurrentVersion\\\\Run\b|Library/LaunchAgents/[^\n]*\.plist|\.config/systemd/user/|/Startup/|(>>|\btee\b|open\(|write|append)[^\n]{0,80}(~|HOME|homedir\(\))[^\n]{0,40}/\.(bashrc|zshrc|profile|bash_profile)\b|(~|HOME|homedir\(\))[^\n]{0,40}/\.(bashrc|zshrc|profile|bash_profile)\b[^\n]{0,40}(>>|\btee\b|'a'|\"a\"|append)", re.I)
RX_CLIPBOARD = re.compile(r"clipboardy|clipboard\.(read|write)|navigator\.clipboard|pyperclip|xclip|pbpaste|pbcopy|Get-Clipboard|Set-Clipboard", re.I)
RX_ETH = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
RX_SOL_BTC = re.compile(r"\b(bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|[1-9A-HJ-NP-Za-km-z]{43,44})\b")
RX_WALLET_WORDS = re.compile(r"metamask|phantom wallet|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|exodus|electrum|atomic ?wallet|seed ?phrase|mnemonic phrase|wallet\.dat", re.I)
RX_BROWSER_STEAL = re.compile(r"Login Data|Web Data|/Local State\b|Local Storage/leveldb|os_crypt|encrypted_key|/Cookies\b|cookies\.sqlite|logins\.json|key4\.db", re.I)
RX_DECRYPT = re.compile(r"CryptUnprotectData|DPAPI|master_key", re.I)
RX_PY_INSTALL_CLS = re.compile(r"class\s+\w+\((install|develop|egg_info|bdist_egg|install_lib|install_scripts)\)|cmdclass\s*=\s*\{[^}]*['\"](install|develop|egg_info)['\"]", re.I)
RX_PY_SETUP_HOOK = re.compile(r"cmdclass\s*=\s*\{|class\s+\w+\((install|develop|egg_info|build_py|bdist_egg)\)|def\s+run\s*\(\s*self\s*\)", re.I)
RX_PY_EXEC_DECODE = re.compile(r"exec\s*\(\s*(base64\.b64decode|bytes\.fromhex|zlib\.decompress|marshal\.loads|codecs\.decode|__import__\s*\(\s*['\"]base64)|eval\s*\(\s*(base64\.b64decode|bytes\.fromhex|zlib\.decompress)|__import__\s*\(\s*['\"]builtins['\"]\s*\)\.exec", re.I)
RX_PTH = re.compile(r"^import\s+\w+\s*;", re.M)
RX_URL = re.compile(r"https?://[^\s'\"`<>)]+", re.I)
RX_IP_BARE = re.compile(r"['\"](?!(?:10|127|0)\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|255\.)(\d{1,3}\.){3}\d{1,3}['\"]")
RX_IP_URL = re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}(:\d+)?/", re.I)
RX_SUS_TLD = re.compile(r"https?://[^\s'\"`/]+\.(xyz|top|icu|cfd|click|lol|buzz|monster|tk|ml|ga|cf|gq|pw|onion)(/|['\"`\s]|$)", re.I)


# ---------------------------------------------------------------- rules

def rule_install_hook(pkg: Package) -> list[Finding]:
    out: list[Finding] = []
    if pkg.ecosystem == "npm":
        scripts = (pkg.manifest.get("scripts") or {}) if isinstance(pkg.manifest, dict) else {}
        for k in ("preinstall", "install", "postinstall", "prepare", "preuninstall", "postuninstall"):
            v = scripts.get(k)
            if not v:
                continue
            w = 2
            note = f"{k} script"
            if re.search(r"node\s+\S+\.c?m?js|node\s+-e\b", v):
                w = 3; note += ", runs js at install"
            if RX_DOWNLOAD_EXEC.search(v) or re.search(r"curl|wget|powershell|Invoke-WebRequest|certutil", v, re.I):
                w = 5; note += ", downloads at install"
            if re.search(r"node-gyp|prebuild-install|node-pre-gyp|husky|patch-package|tsc\b|rimraf|opencollective", v):
                w = max(1, w - 2); note += " (common tooling)"
            out.append(Finding("install-hook", w, "package.json", 0, f"{k}: {v}", note))
    elif pkg.ecosystem == "pypi":
        for f in pkg.files:
            if _aux(pkg, f.path):
                continue
            if f.path.endswith("setup.py"):
                t = f.text[:TEXT_MAX]
                for i, ln in _code_lines(t, f.path):
                    m = RX_PY_INSTALL_CLS.search(ln)
                    if m and not _comment(ln):
                        out.append(Finding("install-hook", 3, f.path, i, _snip(ln, m), "setup.py overrides the install step"))
                        break
                else:
                    for i, ln in _code_lines(t, f.path):
                        m = RX_PY_SETUP_HOOK.search(ln)
                        if m and not _comment(ln):
                            out.append(Finding("install-hook", 1, f.path, i, _snip(ln, m), "setup.py has a custom build step (normal for native code)"))
                            break
            if f.path.endswith(".pth"):
                t = f.text[:TEXT_MAX]
                if RX_PTH.search(t) or "exec(" in t or "import " in t and ";" in t:
                    if "_getframe(1).f_locals['sitedir']" in t or "types.ModuleType" in t:
                        out.append(Finding("install-hook", 1, f.path, 1, _snip(t.split("\n")[0]), ".pth namespace shim (setuptools boilerplate)"))
                    else:
                        out.append(Finding("install-hook", 5, f.path, 1, _snip(t.split("\n")[0]), ".pth file runs code on every python start"))
    return out


def rule_obfuscation(pkg: Package) -> list[Finding]:
    out: list[Finding] = []
    for f in pkg.files:
        if not _is_code(f.path) or len(f.data) > TEXT_MAX or not _is_text(f.data):
            continue
        if _aux(pkg, f.path):
            continue
        t = f.text
        vendor = _is_minified_vendor(f.path, t)
        for i, ln in _code_lines(t, f.path):
            m = RX_EVAL.search(ln)
            if m and not vendor and not _in_string(ln, m.start()):
                if RX_EVAL_DECODE.search(ln):
                    out.append(Finding("obfuscation", 3, f.path, i, _snip(ln, m), "eval / Function over decoded data"))
                else:
                    out.append(Finding("obfuscation", 2, f.path, i, _snip(ln, m), "eval / Function over a computed value"))
                break
        for i, ln in _code_lines(t, f.path):
            m = RX_FROMCHARCODE.search(ln)
            if m and not _comment(ln):
                out.append(Finding("obfuscation", 2, f.path, i, _snip(ln, m), "string built char by char"))
                break
        for i, ln in _code_lines(t, f.path):
            m = RX_HEX_RUN.search(ln)
            if m and not vendor and not _comment(ln):
                out.append(Finding("obfuscation", 2, f.path, i, _snip(ln, m), "long run of hex-escaped characters"))
                break
        for i, ln in _code_lines(t, f.path):
            m = RX_B64_BLOB.search(ln)
            if m and _decoded_code(m.group(1)):
                # base64 that decodes to code is the signal; images, fonts, wasm and sourcemaps are not
                out.append(Finding("obfuscation", 4, f.path, i, _snip(ln, m)[:100] + "…", "base64 blob that decodes to code"))
                break
        if not vendor:
            for i, ln in _code_lines(t, f.path):
                st = ln.lstrip()
                bundle = st.startswith(("import{", "import ", "export ", "!function", "(function", "(()=>", "(() =>", '"use strict"', "'use strict'", "/*!", "var __", "(self.webpackChunk", "(globalThis.webpackChunk", "!(function", "define(", "{\"", "[{", "module.exports", "Object.defineProperty")) and not re.search(r"_0x[0-9a-f]{3,}", ln[:400])
                if len(ln) > 6000 and entropy(ln) > 5.2 and not bundle and not st.startswith(("//", "/*", "*", "data:")) and "sourceMappingURL" not in ln:
                    out.append(Finding("obfuscation", 2, f.path, i, ln[:100] + "…", f"{len(ln)} chars on one line, entropy {entropy(ln):.1f}"))
                    break
        if pkg.ecosystem == "pypi":
            for i, ln in _code_lines(t, f.path):
                m = RX_PY_EXEC_DECODE.search(ln)
                if m:
                    if re.search(r"b64decode\(\s*[\"'][A-Za-z0-9+/=]{40,}|fromhex\(\s*[\"'][0-9a-fA-F]{40,}", ln):
                        out.append(Finding("obfuscation", 5, f.path, i, _snip(ln, m), "exec over a payload decoded from a literal blob"))
                    else:
                        out.append(Finding("obfuscation", 3, f.path, i, _snip(ln, m), "exec over bytes decoded at runtime (a transport, or a wrapper)"))
                    break
    return out


def rule_exfil(pkg: Package) -> list[Finding]:
    """reads secrets AND talks to the network, in the same package. either alone is normal."""
    reads: list[Finding] = []
    sends: list[Finding] = []
    for f in pkg.files:
        if not _is_code(f.path) or len(f.data) > TEXT_MAX or not _is_text(f.data):
            continue
        t = f.text
        aux = _aux(pkg, f.path)
        data_file = f.path.lower().split("#", 1)[0].endswith((".json", ".toml", ".cfg", ".md", ".txt", ".yaml", ".yml"))
        raw = t.split("\n")
        for i, ln in _code_lines(t, f.path):
            m = RX_SECRET_PATHS.search(ln)
            if not m or aux or data_file or re.search(r"\.env\.example|dotenv|README|gitignore", ln, re.I):
                continue
            if len(RX_SECRET_PATHS.findall(ln)) >= 3 and not RX_READ.search(ln):
                continue                                    # a list of names (a deny-list, a scanner's catalog), not a read
            near = "\n".join(raw[max(0, i - 3):i + 3])
            if RX_READ.search(near) or RX_NET.search(ln):
                reads.append(Finding("exfil", 0, f.path, i, _snip(ln, m), "reads secret files"))
                break
        for i, ln in _code_lines(t, f.path):
            m = RX_WEBHOOK.search(ln)
            if m and not aux and not _placeholder_url(ln[m.start():m.start() + 120]):
                sends.append(Finding("exfil", 0, f.path, i, _snip(ln, m), "posts to a webhook / collaborator"))
                break
        if aux:
            continue
        for i, ln in _code_lines(t, f.path):
            m = RX_IP_URL.search(ln) or RX_SUS_TLD.search(ln)
            if not m:
                b = RX_IP_BARE.search(ln)
                if b and (RX_NET.search(ln) or re.search(r"\b(host|hostname|address|ip)\s*[:=]|connect\(|createConnection|\bsocket\b", ln, re.I)):
                    m = b
            if m and not _comment(ln) and not re.search(r"127\.0\.0\.1|0\.0\.0\.0|localhost|192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.|example\.|169\.254\.", ln):
                sends.append(Finding("exfil", 0, f.path, i, _snip(ln, m), "talks to a raw ip or a throwaway domain"))
                break
    env_and_net: list[Finding] = []
    for f in pkg.files:
        if not _is_code(f.path) or len(f.data) > TEXT_MAX or not _is_text(f.data):
            continue
        t = f.text
        if not _aux(pkg, f.path) and not f.path.lower().endswith((".json", ".toml", ".cfg", ".md")) and RX_ENV.search(t) and RX_NET.search(t) and RX_SECRET_PATHS.search(t):
            for i, ln in _code_lines(t, f.path):
                m = RX_NET.search(ln)
                if m and not _comment(ln):
                    env_and_net.append(Finding("exfil", 0, f.path, i, _snip(ln, m), "env + secret paths + network in one file"))
                    break
    out: list[Finding] = []
    if reads and sends:
        # a stealer reads and sends in one place. across files the pair is weaker, unless the send is a webhook
        same = next(((r, x) for r in reads for x in sends if r.file == x.file), None)
        hook = next((x for x in sends if "webhook" in x.note), None)
        if same:
            r, x = same; w = 5
        elif hook:
            r, x = reads[0], hook; w = 5
        elif any("raw ip" in x.note and RX_IP_URL.search(x.snippet) for x in sends):
            r = reads[0]; x = next(x for x in sends if RX_IP_URL.search(x.snippet)); w = 4
        else:
            r, x = reads[0], sends[0]; w = 3
        out.append(Finding("exfil", w, r.file, r.line, r.snippet, r.note + ", and " + x.note + ("" if same else " (in another file)")))
        out.append(Finding("exfil", 0, x.file, x.line, x.snippet, x.note))
    elif sends and any("webhook" in s.note for s in sends):
        s = next(s for s in sends if "webhook" in s.note)
        out.append(Finding("exfil", 4, s.file, s.line, s.snippet, s.note))
    elif env_and_net:
        e = env_and_net[0]
        out.append(Finding("exfil", 3, e.file, e.line, e.snippet, e.note))
    elif sends:
        s = sends[0]
        out.append(Finding("exfil", 1, s.file, s.line, s.snippet, s.note))
    return out


def rule_wallets(pkg: Package) -> list[Finding]:
    """hardcoded wallet addresses next to clipboard access or wallet-stealing words."""
    out: list[Finding] = []
    for f in pkg.files:
        if not _is_code(f.path) or len(f.data) > TEXT_MAX or not _is_text(f.data) or _aux(pkg, f.path):
            continue
        t = f.text
        has_clip = bool(RX_CLIPBOARD.search(t))
        has_words = bool(RX_WALLET_WORDS.search(t))
        has_browser = bool(RX_BROWSER_STEAL.search(t))
        for i, ln in _code_lines(t, f.path):
            m = RX_ETH.search(ln)
            if m and (has_clip or RX_CLIPBOARD.search(ln)):
                out.append(Finding("wallet", 5, f.path, i, _snip(ln, m), "hardcoded address with clipboard access (clipper)"))
                break
        if has_browser:
            raw = t.split("\n")
            placed = []                                   # marker lines that build or read a path, not bare names in a list
            for i, ln in _code_lines(t, f.path):
                m = RX_BROWSER_STEAL.search(ln)
                if not m:
                    continue
                near = "\n".join(raw[max(0, i - 3):i + 2])
                if re.search(r"path\.join|\bjoin\(|expanduser|homedir|APPDATA|LOCALAPPDATA|os\.path|User Data|/Google/|/Chrome|/BraveSoftware|/Mozilla|\\\\", ln) or RX_READ.search(near):
                    placed.append((i, ln, m))
            markers = {m.group(0).lower() for _, _, m in placed}
            if placed and (len(markers) >= 2 or RX_DECRYPT.search(t) or (has_words and RX_NET.search(t))):
                i, ln, m = placed[0]
                out.append(Finding("wallet", 5, f.path, i, _snip(ln, m), "reaches into browser / wallet storage"))
        if has_words and RX_SECRET_PATHS.search(t) and RX_NET.search(t):
            for i, ln in _code_lines(t, f.path):
                m = RX_WALLET_WORDS.search(ln)
                if m and RX_SECRET_PATHS.search(ln):
                    out.append(Finding("wallet", 4, f.path, i, _snip(ln, m), "wallet files + network"))
                    break
    return out


def _own_host(pkg: Package, ln: str) -> bool:
    """the url on this line lives on the package's own domain (name or repository host)"""
    hosts = {m.group(1).lower() for m in re.finditer(r"https?://([\w.-]+)", ln)}
    if not hosts:
        return False
    parts = [re.sub(r"[^a-z0-9]", "", x) for x in pkg.name.lower().lstrip("@").split("/")]
    owns = [x for x in parts if len(x) >= 4]
    repo_host = ""
    if pkg.repository:
        rm = re.search(r"https?://([\w.-]+)|@([\w.-]+):", pkg.repository)
        repo_host = ((rm.group(1) or rm.group(2)) if rm else "").lower()
    for h in hosts:
        if any(own in h.replace("-", "").replace(".", "") for own in owns):
            return True
        if repo_host and h == repo_host and "github" not in h:
            return True
    return False


_MSG_PREFIX = re.compile(r"^\s*(console\.(log|error|warn|info)\(|print\(|println!?\(|echo\s|logger?\.\w+\(|log\.\w+\(|return\s+[\"'`]|\+\s*[\"'`]|\w+\.push\([\"'`]|help\s*[:=]|usage\s*[:=]|message\s*[:=]|hint\s*[:=]|description\s*[:=])", re.I)
_RUN_WORDS = re.compile(r"\b(run|install|installed|setup|get started|to install|try|please|then|first|visit|see|no|never|avoid|don't|do not|warning|dangerous|attack|unsafe|forbid|forbidden|disallow)\b|:\s*curl|\bcurl\b[^\n]*\|[^\n]*(\\n|\"\s*\+|'\s*\+|,\s*$)", re.I)


def _is_message(ln: str, pos: int) -> bool:
    """the command sits inside text shown to a person (a help line, a hint), not in something that runs it"""
    if not _in_string(ln, pos):
        return False
    if re.search(r"(os\.system|subprocess|execSync|spawnSync|\bexec\(|\bspawn\(|child_process|popen|Invoke-Expression|\biex\b|sh -c|bash -c)", ln, re.I):
        return False
    if _MSG_PREFIX.match(ln) or _RUN_WORDS.search(ln[:pos]):
        return True
    if re.search(r"`[^`]*$", ln[:pos]) and "`" in ln[pos:]:       # a command quoted in backticks inside prose
        return True
    # a bare string fragment is prose only when it reads like prose: joined with +, or carrying a newline
    st = ln.strip()
    return st[:1] in "\"'`" and (st.endswith("+") or "\\n" in st)


def _placeholder_url(u: str) -> bool:
    """a webhook that is obviously a stand-in (docs, tests, templates), not a live one"""
    return bool(re.search(r"0{6,}|X{5,}|x{5,}|example|/123456789|your[_-]?(webhook|token|id)|<[\w_-]+>|\{\w+\}|\$\{|%s|TOKEN\b|REPLACE|xxx|placeholder", u, re.I))


def _download_weight(pkg: Package, ln: str) -> tuple[int, str]:
    if RX_IP_URL.search(ln) or RX_SUS_TLD.search(ln) or RX_WEBHOOK.search(ln) or re.search(r"pastebin|transfer\.sh|0x0\.st|ngrok|trycloudflare", ln, re.I):
        return 5, "download and run from a raw ip, a throwaway domain or a paste site"
    if re.search(r"powershell[^\n]{0,80}(-enc|-e |EncodedCommand|hidden)", ln, re.I):
        if re.search(r"(-enc\w*|-e |EncodedCommand)\s+[A-Za-z0-9+/=]{40,}", ln, re.I):
            return 5, "powershell with an encoded payload inline"
        return 3, "builds an encoded or hidden powershell command"
    if KNOWN_INSTALLERS.search(ln):
        return 1, "installs a well-known tool (its official installer)"
    if _own_host(pkg, ln):
        return 2, "the package's own installer, on its own domain"
    return 4, "download and run"


def rule_shell(pkg: Package) -> list[Finding]:
    out: list[Finding] = []
    for f in pkg.files:
        if not _is_code(f.path) or len(f.data) > TEXT_MAX or not _is_text(f.data):
            continue
        if _aux(pkg, f.path):
            continue
        t = f.text
        for i, ln in _code_lines(t, f.path):
            m = RX_REVSHELL.search(ln)
            if m and not _comment(ln) and not _pattern_line(ln):
                out.append(Finding("shell", 5, f.path, i, _snip(ln, m), "reverse shell shape"))
                break
        for i, ln in _code_lines(t, f.path):
            m = RX_DOWNLOAD_EXEC.search(ln)
            if m and not _pattern_line(ln):
                w, note = _download_weight(pkg, ln)
                if w <= 4 and _is_message(ln, m.start()):
                    w, note = 1, "a message that tells the user how to install something"
                out.append(Finding("shell", w, f.path, i, _snip(ln, m), note))
                break
        for i, ln in _code_lines(t, f.path):
            m = RX_CHMOD_RUN.search(ln)
            if m and not _comment(ln) and not _pattern_line(ln):
                out.append(Finding("shell", 3, f.path, i, _snip(ln, m), "makes a file executable and runs it"))
                break
        for i, ln in _code_lines(t, f.path):
            m = RX_PERSIST.search(ln)
            if m and not _pattern_line(ln) and not _is_message(ln, m.start()) and RX_SHELL.search(t):
                out.append(Finding("shell", 3, f.path, i, _snip(ln, m), "persistence (cron / startup / rc files) with a shell"))
                break
    return out


def rule_binaries(pkg: Package) -> list[Finding]:
    out: list[Finding] = []
    WIN = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs")
    bins = [f for f in pkg.files if not _aux(pkg, f.path) and not f.path.lower().endswith("make.bat")
            and (f.path.lower().endswith(WIN) or f.data[:2] == b"MZ" or (f.data[:4] == b"\x7fELF" and not f.path.lower().endswith((".so", ".node"))))]
    if not bins:
        return out
    hooks = rule_install_hook(pkg)
    declared_native = pkg.ecosystem == "npm" and any(k in (pkg.manifest.get("dependencies") or {}) | (pkg.manifest.get("devDependencies") or {}) for k in ("node-gyp", "node-addon-api", "prebuild-install", "node-pre-gyp", "cmake-js"))
    if hooks and not declared_native:
        b = bins[0]
        out.append(Finding("binary", 3, b.path, 0, b.path, f"{len(bins)} executable file(s) plus an install hook, no native build declared"))
    elif pkg.ecosystem == "pypi" and any(b.path.lower().endswith((".exe", ".dll", ".vbs", ".scr")) or b.data[:2] == b"MZ" for b in bins):
        b = next(b for b in bins if b.path.lower().endswith((".exe", ".dll", ".vbs", ".scr")) or b.data[:2] == b"MZ")
        out.append(Finding("binary", 2, b.path, 0, b.path, "windows executable inside a python package"))
    return out


def levenshtein(a: str, b: str, cap: int = 3) -> int:
    """optimal string alignment distance: an adjacent swap (lodahs / lodash) costs 1, like a typo does."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        row_min = cap + 1
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            v = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                v = min(v, d[i - 2][j - 2] + 1)
            d[i][j] = v
            row_min = min(row_min, v)
        if row_min > cap:
            return cap + 1
    return min(d[la][lb], cap + 1)


def rule_typosquat(pkg: Package, popular: Iterable[str]) -> list[Finding]:
    """a NEW package whose name sits one keystroke from a popular one. established packages never trip this."""
    if is_established(pkg):
        return []
    name = pkg.name.lower()
    scoped = name.startswith("@")
    base = name
    out: list[Finding] = []
    for p in popular:
        p = p.lower()
        if p == name:
            continue
        if p.startswith("@") != scoped:          # @scope/tools can never be installed by mistake for toolz
            continue
        pb = p
        d = levenshtein(base, pb, 2)
        close = d == 1 or (d == 2 and len(pb) >= 8)
        # also: popular name with a swapped separator or a prefix/suffix like "-js", "js", "node-", "2"
        if not close:
            stripped = re.sub(r"^(node|py|python|js|the|lib)[-_.]?|[-_.]?(js|node|py|python|lib|dev|cli|2|3)$", "", base)
            close = stripped != base and stripped == pb
        if close:
            w = 3
            note = f"one keystroke from '{p}'"
            if pkg.ecosystem == "npm" and (pkg.manifest.get("scripts") or {}).keys() & {"preinstall", "install", "postinstall"}:
                w = 4; note += ", with an install hook"
            out.append(Finding("typosquat", w, "package name", 0, f"{pkg.name} ~ {p}", note))
            break
    return out


def is_established(pkg: Package) -> bool:
    """old enough (or downloaded enough) that heuristics alone must not put it on the wall."""
    age_ok = pkg.age_days is not None and pkg.age_days > 365
    dl_ok = pkg.weekly_downloads is not None and pkg.weekly_downloads > 50_000
    return bool(age_ok or dl_ok)


# ---------------------------------------------------------------- verdict

try:
    RULES_VERSION = hashlib.sha1(open(__file__, "rb").read()).hexdigest()[:10]
except OSError:  # pragma: no cover
    RULES_VERSION = "unknown"
TRIP = 7          # score at which a new package goes on the wall as "tripped"
WATCH = 3         # kept in the quiet list, never shown as a catch
STRONG = 5        # one finding this heavy, in a version younger than FRESH_H, trips even an established package
FRESH_H = 72

RULE_TABLE = [
    {"id": "install-hook", "weight": "1-5", "what": "a script that runs at install time (preinstall, postinstall, setup.py install override, a .pth file)",
     "why": "2 for any hook, 3 when it runs js, 5 when it downloads something or is a .pth; husky, node-gyp and the like count 1"},
    {"id": "obfuscation", "weight": "2-5", "what": "eval over decoded data, strings built char by char, long hex runs, base64 that decodes to code, python exec over decoded bytes",
     "why": "minified vendor bundles are skipped for shape, not for content; images, fonts and wasm in base64 do not count"},
    {"id": "exfil", "weight": "1-5", "what": "reads secret files (.ssh, .npmrc, .aws, wallets, browser stores) and sends somewhere in the same package",
     "why": "5 when both halves are there, 4 for a webhook or collaborator domain alone, 3 for env + secret paths + network in one file, 1 for a raw ip or throwaway domain alone"},
    {"id": "wallet", "weight": "4-5", "what": "a hardcoded address next to clipboard access (a clipper), or code that reaches into wallet / browser credential storage",
     "why": "two storage markers, or one marker plus wallet words plus a network call; never from comment lines"},
    {"id": "shell", "weight": "3-5", "what": "reverse shell shapes, download-and-run one-liners, persistence (cron, rc files, startup) next to a shell call",
     "why": "chmod +x && ./run counts 3; a scanner's own pattern lists and comments are skipped"},
    {"id": "binary", "weight": "2-3", "what": "windows executables, MZ or ELF files shipped with an install hook and no native build declared",
     "why": "a python package carrying an .exe with no hook counts 2"},
    {"id": "typosquat", "weight": "2-4", "what": "a new name one keystroke, one swap or one suffix away from a popular one",
     "why": "popular lists come from the registries themselves; established packages are exempt"},
]


def decoded_layers(pkg: Package) -> list[File]:
    """base64 blobs that decode to code become virtual files, so the exfil / shell / wallet rules
    read through the first layer of wrapping. the path says where the blob came from."""
    out: list[File] = []
    for f in pkg.files:
        if not _is_code(f.path) or len(f.data) > TEXT_MAX or not _is_text(f.data):
            continue
        for i, ln in _lines(f.text):
            for m in RX_B64_BLOB.finditer(ln):
                blob = m.group(1)
                try:
                    dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)[:200_000]
                except Exception:  # noqa: BLE001
                    continue
                if dec[:2] in (b"\x1f\x8b",):
                    try:
                        dec = gzip.decompress(dec)[:200_000]
                    except Exception:  # noqa: BLE001
                        pass
                try:
                    dt = dec.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if sum(ch.isprintable() or ch in "\n\r\t" for ch in dt[:2000]) < len(dt[:2000]) * 0.95:
                    continue
                if re.search(r"require\(|import\s|process\.|child_process|exec|eval|fetch\(|http|subprocess|os\.system|powershell|/bin/sh", dt, re.I):
                    out.append(File(f"{f.path}#L{i}<decoded>", dt.encode()))
                if len(out) >= 20:
                    return out
    return out


def analyze(pkg: Package, popular: Iterable[str] = ()) -> list[Finding]:
    findings: list[Finding] = []
    layers = decoded_layers(pkg)
    deep = Package(pkg.ecosystem, pkg.name, pkg.version, pkg.files + layers, pkg.manifest, pkg.age_days, pkg.version_age_h, pkg.weekly_downloads, pkg.repository) if layers else pkg
    for rule in (rule_install_hook, rule_obfuscation):
        findings.extend(rule(pkg))
    for rule in (rule_exfil, rule_wallets, rule_shell, rule_binaries):
        findings.extend(rule(deep))
    findings.extend(rule_typosquat(pkg, popular))
    return findings


def score(findings: list[Finding]) -> int:
    # one rule counts once at its strongest hit; two weak rules do not add up to a catch on their own
    best: dict[str, int] = {}
    for f in findings:
        best[f.rule] = max(best.get(f.rule, 0), f.weight)
    return sum(best.values())


def verdict(pkg: Package, findings: list[Finding], confirmed: bool = False) -> str:
    """confirmed | tripped | watch | clean"""
    if confirmed:
        return "confirmed"
    s = score(findings)
    if is_established(pkg):
        # the hijack case: a fresh version of a trusted name with one unmistakable signal
        fresh = pkg.version_age_h is not None and pkg.version_age_h < FRESH_H
        strong = any(f.weight >= STRONG for f in findings)
        if fresh and strong and s >= TRIP:
            return "tripped"
        return "watch" if s >= WATCH else "clean"      # otherwise never shamed by heuristics alone
    if s >= TRIP and any(f.weight >= 4 for f in findings):      # three weak hits never make a catch
        return "tripped"
    if s >= WATCH:
        return "watch"
    return "clean"


def summary(pkg: Package, findings: list[Finding], confirmed: bool = False) -> dict:
    v = verdict(pkg, findings, confirmed)
    return {
        "ecosystem": pkg.ecosystem, "name": pkg.name, "version": pkg.version, "verdict": v, "score": score(findings),
        "rules": sorted({f.rule for f in findings if f.weight > 0}),
        "evidence": [f.to_json() for f in findings][:12],
        "age_days": None if pkg.age_days is None else round(pkg.age_days, 1),
        "version_age_h": None if pkg.version_age_h is None else round(pkg.version_age_h, 1),
        "weekly_downloads": pkg.weekly_downloads, "repository": pkg.repository,
        "files": len(pkg.files), "rules_version": RULES_VERSION,
    }


def manifest_of(files: list[File]) -> dict:
    for f in files:
        if f.path.endswith("package.json") and f.path.count("/") <= 1:
            try:
                return json.loads(f.text)
            except Exception:  # noqa: BLE001
                return {}
    return {}
