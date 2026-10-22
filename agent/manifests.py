"""Reading a dependency list out of whatever a person pastes.

Understood: package.json, package-lock.json (v1-v3), yarn.lock, pnpm-lock.yaml, requirements.txt,
pyproject.toml ([project] and [tool.poetry]), Pipfile, and a plain list of names (one per line, or
comma separated). The format is guessed from the content; nothing is executed or written.

Returns (ecosystem, [(name, exact_version_or_None), ...]) with names normalised and de-duplicated.
"""

from __future__ import annotations

import json
import re

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

NPM_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
PYPI_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
MAX_NAMES = 500
EXACT = re.compile(r"^(==|=)?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")


def valid_name(ecosystem: str, name: str) -> bool:
    if not name or len(name) > 214:
        return False
    return bool(NPM_NAME.match(name)) if ecosystem == "npm" else bool(PYPI_NAME.match(name))


def norm_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _exact(spec: str | None) -> str | None:
    if not spec:
        return None
    m = EXACT.match(spec.strip())
    return m.group(2) if m else None


def _dedupe(ecosystem: str, pairs: list[tuple[str, str | None]]) -> list[tuple[str, str | None]]:
    out: dict[str, str | None] = {}
    for name, ver in pairs:
        name = name.strip()
        if ecosystem == "pypi":
            name = norm_pypi(name)
        if not valid_name(ecosystem, name):
            continue
        if name not in out or (out[name] is None and ver):
            out[name] = ver
        if len(out) >= MAX_NAMES:
            break
    return list(out.items())


# ---------------------------------------------------------------- npm

def _package_json(doc: dict) -> list[tuple[str, str | None]]:
    pairs = []
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = doc.get(key)
        if isinstance(deps, dict):
            for n, spec in deps.items():
                pairs.append((str(n), _exact(spec if isinstance(spec, str) else None)))
    return pairs


def _package_lock(doc: dict) -> list[tuple[str, str | None]]:
    pairs = []
    pk = doc.get("packages")
    if isinstance(pk, dict):                                   # lockfile v2/v3
        for path, meta in pk.items():
            if not path or "node_modules/" not in path or not isinstance(meta, dict):
                continue
            name = meta.get("name") or path.rsplit("node_modules/", 1)[1]
            pairs.append((str(name), _exact(meta.get("version"))))
    deps = doc.get("dependencies")
    if isinstance(deps, dict):                                 # lockfile v1 (and v2 keeps it too)
        def walk(d: dict):
            for n, meta in d.items():
                if isinstance(meta, dict):
                    pairs.append((str(n), _exact(meta.get("version"))))
                    if isinstance(meta.get("dependencies"), dict):
                        walk(meta["dependencies"])
        walk(deps)
    return pairs


YARN_ENTRY = re.compile(r'^"?((?:@[^@\s/"]+/)?[^@\s/"]+)@[^\n]*:\s*$', re.M)
YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', re.M)


def _yarn_lock(text: str) -> list[tuple[str, str | None]]:
    pairs = []
    blocks = re.split(r"\n(?=\S)", text)
    for b in blocks:
        m = YARN_ENTRY.match(b.strip("\n") + "\n") or YARN_ENTRY.search(b)
        if not m:
            continue
        v = YARN_VERSION.search(b)
        pairs.append((m.group(1), _exact(v.group(1)) if v else None))
    return pairs


PNPM_ENTRY = re.compile(r"^\s{2}/?('?)((?:@[^@\s/']+/)?[^@\s/']+)@([^\s(:']+)", re.M)


def _pnpm_lock(text: str) -> list[tuple[str, str | None]]:
    pairs = []
    in_packages = False
    for line in text.splitlines():
        if re.match(r"^(packages|snapshots):\s*$", line):
            in_packages = True
            continue
        if in_packages and line and not line.startswith(" "):
            in_packages = False
        if in_packages:
            m = PNPM_ENTRY.match(line)
            if m:
                pairs.append((m.group(2), _exact(m.group(3))))
    return pairs


# ---------------------------------------------------------------- python

REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(==\s*([^\s;#,]+))?")


def _requirements(text: str) -> list[tuple[str, str | None]]:
    pairs = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://", "file:", ".", "/")):
            continue
        if "@" in line and "://" in line:          # pep 508 url
            continue
        m = REQ_LINE.match(line)
        if m:
            pairs.append((m.group(1), m.group(4).strip() if m.group(4) else None))
    return pairs


def _pep508_list(items) -> list[tuple[str, str | None]]:
    out = []
    for it in items or []:
        if isinstance(it, str):
            out.extend(_requirements(it))
    return out


def _pyproject(doc: dict) -> list[tuple[str, str | None]]:
    pairs = []
    proj = doc.get("project") or {}
    pairs += _pep508_list(proj.get("dependencies"))
    for group in (proj.get("optional-dependencies") or {}).values():
        pairs += _pep508_list(group)
    for group in (doc.get("dependency-groups") or {}).values():
        pairs += _pep508_list([g for g in group if isinstance(g, str)])
    poetry = (doc.get("tool") or {}).get("poetry") or {}
    for key in ("dependencies", "dev-dependencies"):
        for n, spec in (poetry.get(key) or {}).items():
            if n.lower() == "python":
                continue
            v = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else None)
            pairs.append((n, _exact(v)))
    for grp in (poetry.get("group") or {}).values():
        for n, spec in ((grp or {}).get("dependencies") or {}).items():
            v = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else None)
            pairs.append((n, _exact(v)))
    return pairs


def _pipfile(doc: dict) -> list[tuple[str, str | None]]:
    pairs = []
    for key in ("packages", "dev-packages"):
        for n, spec in (doc.get(key) or {}).items():
            v = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else None)
            pairs.append((n, _exact(v)))
    return pairs


# ---------------------------------------------------------------- the guess

def parse(text: str, ecosystem: str = "auto") -> tuple[str, list[tuple[str, str | None]], str]:
    """-> (ecosystem, pairs, format). raises ValueError when nothing usable is in the text."""
    text = text.strip()
    if not text:
        raise ValueError("empty")
    if len(text) > 2_000_000:
        raise ValueError("too big")

    # json first: package.json / package-lock.json
    if text.startswith("{"):
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"json: {e.msg} at line {e.lineno}") from None
        if not isinstance(doc, dict):
            raise ValueError("json is not an object")
        if "lockfileVersion" in doc or ("packages" in doc and isinstance(doc.get("packages"), dict) and "" in doc["packages"]):
            return "npm", _dedupe("npm", _package_lock(doc)), "package-lock.json"
        pairs = _package_json(doc)
        if pairs or any(k in doc for k in ("name", "version", "scripts")):
            return "npm", _dedupe("npm", pairs), "package.json"
        raise ValueError("json has no dependencies")

    # yarn / pnpm
    if "# yarn lockfile" in text[:200] or "__metadata:" in text[:400] or YARN_VERSION.search(text) and YARN_ENTRY.search(text):
        return "npm", _dedupe("npm", _yarn_lock(text)), "yarn.lock"
    if text.startswith("lockfileVersion") or "\npackages:\n" in text and "pnpm" in text[:400].lower():
        return "npm", _dedupe("npm", _pnpm_lock(text)), "pnpm-lock.yaml"

    # toml: pyproject / Pipfile
    if re.search(r"^\[(project|tool\.poetry|build-system|packages|dev-packages|dependency-groups)\]", text, re.M):
        try:
            doc = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise ValueError(f"toml: {e}") from None
        if "packages" in doc or "dev-packages" in doc:
            return "pypi", _dedupe("pypi", _pipfile(doc)), "Pipfile"
        return "pypi", _dedupe("pypi", _pyproject(doc)), "pyproject.toml"

    # requirements.txt, or a bare list
    if ecosystem in ("auto", "pypi"):
        pairs = _requirements(text)
        looks_py = ecosystem == "pypi" or re.search(r"==|>=|~=|<=|\[[a-z]", text) or not re.search(r"[A-Z@/]", text)
        if pairs and looks_py:
            return "pypi", _dedupe("pypi", pairs), "requirements.txt"
    # bare names, npm style (scopes, slashes) or anything the caller called npm
    names = [n.strip() for n in re.split(r"[\s,]+", text) if n.strip()]
    eco = "npm" if ecosystem == "auto" else ecosystem
    pairs = []
    for n in names:
        n = n.split("#", 1)[0]
        name, _, ver = n.rpartition("@") if n.count("@") > (1 if n.startswith("@") else 0) else (n, "", "")
        pairs.append((name or n, _exact(ver) if ver else None))
    out = _dedupe(eco, pairs)
    if not out:
        raise ValueError("no package names found")
    return eco, out, "list"
