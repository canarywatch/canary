"""Getting a package's files without ever running them.

npm: the packument from registry.npmjs.org, then the version's tarball (.tgz).
pypi: the project json, then the sdist (.tar.gz) or, failing that, the wheel (.zip).

Extraction is defensive: no absolute paths, no `..`, no symlinks, no device files, a cap on
file count and total bytes, and only the bytes are kept. Nothing is written to disk, nothing is
imported, nothing is executed.
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import tarfile
import time
import zipfile
from datetime import datetime, timezone

import requests

from .rules import File, Package

log = logging.getLogger("canary.fetch")

UA = {"User-Agent": "canary-agent/0.1 (+https://github.com/wallpadSOL) static analysis, never installs"}
NPM = "https://registry.npmjs.org"
NPM_DL = "https://api.npmjs.org/downloads/point/last-week"
PYPI = "https://pypi.org/pypi"

MAX_TARBALL = 12 * 1024 * 1024       # bigger than this we skip (and say so)
MAX_FILES = 4000
MAX_TOTAL = 40 * 1024 * 1024
MAX_FILE = 4 * 1024 * 1024


class SkipPackage(Exception):
    pass


def _get(url: str, timeout: int = 30, **kw) -> requests.Response:
    r = requests.get(url, headers=UA, timeout=timeout, **kw)
    r.raise_for_status()
    return r


def _safe_name(name: str) -> str | None:
    n = name.replace("\\", "/")
    while n.startswith("./"):
        n = n[2:]
    if n.startswith("/") or ".." in n.split("/") or not n:
        return None
    return n


def extract_tar(data: bytes) -> list[File]:
    out: list[File] = []
    total = 0
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except (tarfile.TarError, EOFError, gzip.BadGzipFile) as e:
        raise SkipPackage(f"not a tarball: {e}") from e
    with tf:
        for m in tf:
            if len(out) >= MAX_FILES:
                break
            if not m.isreg():                 # symlinks, devices, dirs: ignored
                continue
            name = _safe_name(m.name)
            if name is None or m.size > MAX_FILE:
                continue
            total += m.size
            if total > MAX_TOTAL:
                break
            f = tf.extractfile(m)
            if f is None:
                continue
            out.append(File(name, f.read(MAX_FILE)))
    return out


def extract_zip(data: bytes) -> list[File]:
    out: list[File] = []
    total = 0
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise SkipPackage(f"not a zip: {e}") from e
    with zf:
        for info in zf.infolist():
            if len(out) >= MAX_FILES:
                break
            if info.is_dir() or info.file_size > MAX_FILE:
                continue
            name = _safe_name(info.filename)
            if name is None:
                continue
            total += info.file_size
            if total > MAX_TOTAL:
                break
            with zf.open(info) as f:
                out.append(File(name, f.read(MAX_FILE)))
    return out


def _strip_root(files: list[File]) -> list[File]:
    """npm tarballs live under package/, sdists under name-version/. drop that first segment."""
    if not files:
        return files
    roots = {f.path.split("/", 1)[0] for f in files}
    if len(roots) == 1 and all("/" in f.path for f in files):
        return [File(f.path.split("/", 1)[1], f.data) for f in files]
    return files


def _age_days(first_iso: str | None) -> float | None:
    if not first_iso:
        return None
    try:
        t = datetime.fromisoformat(first_iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - t).total_seconds() / 86400
    except ValueError:
        return None


# ---------------------------------------------------------------- npm

def npm_packument(name: str) -> dict:
    return _get(f"{NPM}/{requests.utils.quote(name, safe='@')}", timeout=20).json()


def npm_downloads(name: str) -> int | None:
    try:
        r = requests.get(f"{NPM_DL}/{requests.utils.quote(name, safe='@')}", headers=UA, timeout=15)
        if r.status_code == 200:
            return int(r.json().get("downloads", 0))
    except Exception:  # noqa: BLE001
        pass
    return None


def npm_package(name: str, version: str | None = None, doc: dict | None = None, downloads: bool = True) -> Package:
    doc = doc or npm_packument(name)
    if not version:
        version = (doc.get("dist-tags") or {}).get("latest")
    if not version or version not in (doc.get("versions") or {}):
        raise SkipPackage(f"{name}: version {version} not in packument")
    v = doc["versions"][version]
    tarball = (v.get("dist") or {}).get("tarball")
    if not tarball:
        raise SkipPackage(f"{name}@{version}: no tarball")
    size = (v.get("dist") or {}).get("unpackedSize") or 0
    if size and size > MAX_TOTAL:
        raise SkipPackage(f"{name}@{version}: unpacked {size} bytes, over the cap")
    r = _get(tarball, timeout=60, stream=True)
    data = r.raw.read(MAX_TARBALL + 1, decode_content=True)
    if len(data) > MAX_TARBALL:
        raise SkipPackage(f"{name}@{version}: tarball over {MAX_TARBALL} bytes")
    files = _strip_root(extract_tar(data))
    times = doc.get("time") or {}
    created = times.get("created") or min((t for k, t in times.items() if k not in ("created", "modified")), default=None)
    repo = v.get("repository")
    if isinstance(repo, dict):
        repo = repo.get("url")
    vtime = times.get(version)
    return Package(
        ecosystem="npm", name=name, version=version, files=files, manifest=v,
        age_days=_age_days(created), version_age_h=(None if _age_days(vtime) is None else _age_days(vtime) * 24),
        weekly_downloads=npm_downloads(name) if downloads else None,
        repository=repo if isinstance(repo, str) else None,
    )


# ---------------------------------------------------------------- pypi

def pypi_json(name: str, version: str | None = None) -> dict:
    url = f"{PYPI}/{name}/json" if not version else f"{PYPI}/{name}/{version}/json"
    return _get(url, timeout=20).json()


def pypi_package(name: str, version: str | None = None, doc: dict | None = None) -> Package:
    # always the project-level json: it carries every release's upload time, which is how we know the
    # package's age (the version-level json does not have that)
    doc = doc or pypi_json(name)
    info = doc.get("info") or {}
    releases = doc.get("releases") or {}
    if version and version not in releases:
        raise SkipPackage(f"{name}=={version}: no such release")
    version = version or info.get("version")
    urls = releases.get(version) or (doc.get("urls") if version == info.get("version") else None) or []
    sdist = next((u for u in urls if u.get("packagetype") == "sdist"), None)
    wheel = next((u for u in urls if u.get("packagetype") == "bdist_wheel"), None)
    pick = sdist or wheel
    if not pick:
        raise SkipPackage(f"{name}=={version}: no files")
    if (pick.get("size") or 0) > MAX_TARBALL:
        raise SkipPackage(f"{name}=={version}: file over the cap")
    r = _get(pick["url"], timeout=60, stream=True)
    data = r.raw.read(MAX_TARBALL + 1, decode_content=True)
    if len(data) > MAX_TARBALL:
        raise SkipPackage(f"{name}=={version}: file over {MAX_TARBALL} bytes")
    files = _strip_root(extract_tar(data)) if pick is sdist and not pick["filename"].endswith(".zip") else extract_zip(data)
    # first release time: the oldest upload across releases, when the full json is there
    first = None
    for files_of in (doc.get("releases") or {}).values():
        for u in files_of:
            t = u.get("upload_time_iso_8601") or u.get("upload_time")
            if t and (first is None or t < first):
                first = t
    repo = None
    for k, v in (info.get("project_urls") or {}).items():
        if re_source(k) and isinstance(v, str):
            repo = v; break
    this = None
    for u in urls:
        t = u.get("upload_time_iso_8601") or u.get("upload_time")
        if t and (this is None or t < this):
            this = t
    return Package(
        ecosystem="pypi", name=name, version=version or "", files=files, manifest=info,
        age_days=_age_days(first), version_age_h=(None if _age_days(this) is None else _age_days(this) * 24),
        weekly_downloads=None, repository=repo or info.get("home_page") or None,
    )


def re_source(k: str) -> bool:
    k = k.lower()
    return "source" in k or "repository" in k or "github" in k or k == "code"


# ---------------------------------------------------------------- the new-release feeds

class NpmChanges:
    """replicate.npmjs.com/_changes, polled with `since`. one change per package touched.
    the endpoint only takes a numeric seq, so a fresh start first asks the root for update_seq."""
    URL = "https://replicate.npmjs.com/_changes"
    ROOT = "https://replicate.npmjs.com/"

    def __init__(self, since: str | int | None = None):
        self.since: int | None = int(since) if since is not None and str(since).isdigit() else None
        self.ok = True
        self.last_error = ""

    def _resolve(self) -> bool:
        try:
            r = requests.get(self.ROOT, headers=UA, timeout=20)
            r.raise_for_status()
            self.since = int(r.json()["update_seq"])
            return True
        except Exception as e:  # noqa: BLE001
            self.ok = False; self.last_error = str(e)[:200]
            log.warning("npm changes: cannot read update_seq: %s", e)
            return False

    def poll(self, limit: int = 200) -> list[str]:
        if self.since is None and not self._resolve():
            return []
        try:
            r = requests.get(self.URL, params={"since": self.since, "limit": limit}, headers=UA, timeout=40)
            r.raise_for_status()
            doc = r.json()
        except Exception as e:  # noqa: BLE001
            self.ok = False; self.last_error = str(e)[:200]
            log.warning("npm changes: %s", e)
            return []
        self.ok = True; self.last_error = ""
        last = doc.get("last_seq")
        if isinstance(last, int) or (isinstance(last, str) and last.isdigit()):
            self.since = int(last)
        return [c.get("id") for c in doc.get("results", []) if c.get("id") and not c.get("deleted") and not str(c.get("id")).startswith("_design")]


class PypiUpdates:
    """pypi's rss of latest updates + newest projects. dedupes on (name, version)."""
    URLS = ("https://pypi.org/rss/updates.xml", "https://pypi.org/rss/packages.xml")

    def __init__(self):
        self.seen: dict[tuple[str, str], float] = {}
        self.ok = True
        self.last_error = ""

    def poll(self) -> list[tuple[str, str]]:
        import xml.etree.ElementTree as ET
        out: list[tuple[str, str]] = []
        failed = 0
        for url in self.URLS:
            try:
                r = _get(url, timeout=30)
                root = ET.fromstring(r.content)
            except Exception as e:  # noqa: BLE001
                log.warning("pypi rss: %s", e)
                failed += 1; self.last_error = str(e)[:200]
                continue
            for item in root.iter("item"):
                link = (item.findtext("link") or "").rstrip("/")
                parts = link.split("/")
                if "project" not in parts:
                    continue
                i = parts.index("project")
                name = parts[i + 1] if len(parts) > i + 1 else ""
                version = parts[i + 2] if len(parts) > i + 2 else ""
                if not name:
                    continue
                key = (name, version)
                if key in self.seen:
                    continue
                self.seen[key] = time.time()
                out.append(key)
        self.ok = failed < len(self.URLS)
        if self.ok:
            self.last_error = ""
        # forget old keys
        cut = time.time() - 6 * 3600
        self.seen = {k: t for k, t in self.seen.items() if t > cut}
        return out


# ---------------------------------------------------------------- popular names, for the typosquat rule

def popular_npm(n: int = 1500) -> list[str]:
    """the most depended-upon names, from the registry search ranked by popularity. cached by the caller."""
    names: list[str] = []
    for frm in range(0, n, 250):
        try:
            r = _get(f"{NPM}/-/v1/search", timeout=30, params={"text": "boost-exact:false", "size": 250, "from": frm, "popularity": 1.0, "quality": 0.0, "maintenance": 0.0})
            for o in r.json().get("objects", []):
                names.append(o["package"]["name"])
        except Exception as e:  # noqa: BLE001
            log.warning("popular npm: %s", e)
            break
    return names


def popular_pypi() -> list[str]:
    """hugovk's top-pypi-packages (public json, monthly)."""
    try:
        r = _get("https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json", timeout=30)
        rows = r.json().get("rows", [])
        return [x["project"] for x in rows[:2000]]
    except Exception as e:  # noqa: BLE001
        log.warning("popular pypi: %s", e)
        return []


def save_json(path: str, doc) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, ensure_ascii=False)
    import os
    os.replace(tmp, path)
