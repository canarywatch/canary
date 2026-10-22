"""canary: the command line.

    python -m agent run                          watch npm + pypi, serve the files
    python -m agent scan npm some-package [ver]  fetch one package, print the verdict and the lines
    python -m agent check package.json           read a dependency file, say which names are on the record
    python -m agent status                       print the wall from state.json
    python -m agent doctor                       what works from this machine

Config: ./config.toml, or -c path. See config.example.toml.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

from . import fetch, manifests, rules
from .main import Agent, Config
from .osv import Osv


def load_config(path: str | None) -> Config:
    doc: dict = {}
    if path and os.path.exists(path):
        with open(path, "rb") as f:
            doc = tomllib.load(f)
    elif path and path != "config.toml":
        sys.exit(f"no config at {path}")
    a, s = doc.get("agent", {}), doc.get("server", {})
    return Config(
        data_dir=a.get("data_dir", "./data"), npm=bool(a.get("npm", True)), pypi=bool(a.get("pypi", True)),
        workers=int(a.get("workers", 4)), poll_s=int(a.get("poll_s", 20)),
        max_catches=int(a.get("max_catches", 600)), max_watch=int(a.get("max_watch", 400)),
        recheck_days=int(a.get("recheck_days", 30)), popular_refresh_h=int(a.get("popular_refresh_h", 24)),
        extra_popular=list(a.get("extra_popular", [])),
        host=s.get("host", "127.0.0.1"), port=int(s.get("port", 8791)), cors=s.get("cors", "*"),
        links=dict(doc.get("links", {})),
    )


def print_summary(s: dict) -> None:
    tag = {"confirmed": "CONFIRMED", "tripped": "TRIPPED", "watch": "watch", "clean": "clean", "cleared": "cleared"}[s["verdict"]]
    print(f"{tag}  {s['ecosystem']}:{s['name']}@{s['version']}  score {s['score']}  rules {', '.join(s['rules']) or '-'}")
    meta = []
    if s.get("age_days") is not None:
        meta.append(f"first release {s['age_days']:.0f} d ago")
    if s.get("version_age_h") is not None:
        meta.append(f"this version {s['version_age_h']:.0f} h old")
    if s.get("weekly_downloads") is not None:
        meta.append(f"{s['weekly_downloads']:,} downloads/week")
    if meta:
        print("  " + ", ".join(meta))
    for a in s.get("advisories", []):
        print(f"  advisory {a['id']}  {a['url']}")
    for e in s.get("evidence", []):
        if e.get("weight", 0) <= 0:
            continue
        print(f"  [{e['rule']} +{e['weight']}] {e['file']}:{e['line']}  {e['snippet']}")
        if e.get("note"):
            print(f"      {e['note']}")


def cmd_scan(args) -> int:
    cfg = load_config(args.config)
    popular = set(json.load(open(os.path.join(cfg.data_dir, "popular.json")))) if os.path.exists(os.path.join(cfg.data_dir, "popular.json")) else set()
    eco = args.ecosystem
    name = manifests.norm_pypi(args.name) if eco == "pypi" else args.name
    try:
        pkg = fetch.npm_package(name, args.version) if eco == "npm" else fetch.pypi_package(name, args.version)
    except fetch.SkipPackage as e:
        print(f"skipped: {e}")
        return 2
    findings = rules.analyze(pkg, popular)
    ids = Osv().malware_ids(eco, pkg.name, pkg.version) if not args.offline else []
    s = rules.summary(pkg, findings, bool(ids))
    s["advisories"] = [{"id": i, "url": f"https://osv.dev/vulnerability/{i}"} for i in ids]
    if args.json:
        print(json.dumps(s, indent=1))
    else:
        print_summary(s)
    return 0 if s["verdict"] in ("clean", "watch") else 1


def cmd_check(args) -> int:
    text = sys.stdin.read() if args.file == "-" else open(args.file).read()
    cfg = load_config(args.config)
    from .server import Store
    agent = None
    if not args.offline:
        import threading
        from types import SimpleNamespace
        agent = SimpleNamespace(osv=Osv(), checks_total=0, lock=threading.Lock())   # just enough of an agent for Store.check
    store = Store(cfg.data_dir, agent=agent)
    try:
        out = store.check(text, args.ecosystem)
    except ValueError as e:
        print(f"could not read that: {e}")
        return 2
    if args.json:
        print(json.dumps(out, indent=1))
        return 1 if out["flagged"] else 0
    print(f"{out['format']}: {out['parsed']} {out['ecosystem']} packages, osv {'ok' if out['osv_ok'] else 'unreachable'}")
    for r in out["flagged"]:
        line = f"  {r['status'].upper():14} {r['name']}" + (f"@{r['version']}" if r.get("version") else "")
        if r.get("versions"):
            line += f"  (on the wall: {', '.join(r['versions'])})"
        if r.get("ids"):
            line += "  " + ", ".join(r["ids"][:3])
        print(line)
    if not out["flagged"]:
        print("  nothing on the record")
    return 1 if out["flagged"] else 0


def cmd_status(args) -> int:
    cfg = load_config(args.config)
    st = json.load(open(os.path.join(cfg.data_dir, "state.json")))
    catches = json.load(open(os.path.join(cfg.data_dir, "catches.json")))
    age = int(time.time()) - st.get("updated", 0)
    print(f"updated {age}s ago, up {st.get('uptime_s', 0) // 3600}h, scanned {st.get('scanned_total', 0)} ({st.get('scanned_last_h', 0)}/h), checks {st.get('checks_total', 0)}")
    print(f"wall: {st.get('catches_total', 0)} catches ({st.get('confirmed_24h', 0)} confirmed + {st.get('tripped_24h', 0)} tripped in 24h), watch {st.get('watch_24h', 0)}/24h, cleared {st.get('cleared_total', 0)}")
    r = st.get("recall", {})
    if r.get("confirmed_seen"):
        print(f"recall: {r['rules_tripped']} of {r['confirmed_seen']} confirmed packages were tripped by the rules first, {r['rules_watched']} watched, {r['rules_missed']} missed")
    f = st.get("feeds", {})
    print(f"feeds: npm {'ok' if f.get('npm', {}).get('ok') else 'DOWN'} seq {f.get('npm', {}).get('seq')}, pypi {'ok' if f.get('pypi', {}).get('ok') else 'DOWN'}, osv {'ok' if f.get('osv', {}).get('ok') else 'DOWN ' + str(f.get('osv', {}).get('error'))}")
    for c in catches[:15]:
        print(f"  {c['verdict']:9} {c['ecosystem']}:{c['name']}@{c['version']}  {', '.join(c.get('rules', []))}")
    return 0


def _npm_feed_ok() -> bool:
    f = fetch.NpmChanges()
    if not f._resolve():
        return False
    f.since = max(0, f.since - 50)
    f.poll(limit=1)
    return f.ok


def cmd_doctor(args) -> int:
    import requests
    checks = [
        ("npm registry", lambda: fetch._get("https://registry.npmjs.org/left-pad", timeout=15).status_code == 200),
        ("npm changes feed", _npm_feed_ok),
        ("npm downloads api", lambda: fetch.npm_downloads("left-pad") is not None),
        ("pypi json", lambda: fetch._get("https://pypi.org/pypi/requests/json", timeout=15).ok),
        ("pypi rss", lambda: fetch._get("https://pypi.org/rss/updates.xml", timeout=15).ok),
        ("osv", lambda: Osv().malware_ids("npm", "left-pad") == [] and Osv().ok),
        ("popular npm", lambda: len(fetch.popular_npm(250)) > 100),
        ("popular pypi", lambda: len(fetch.popular_pypi()) > 100),
    ]
    bad = 0
    for label, fn in checks:
        t0 = time.time()
        try:
            ok = bool(fn())
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"  {label:18} FAIL  {str(e)[:120]}")
        else:
            print(f"  {label:18} {'ok' if ok else 'FAIL'}  {time.time() - t0:.1f}s")
        bad += not ok
    cfg = load_config(args.config)
    print(f"  data dir           {os.path.abspath(cfg.data_dir)}  {'exists' if os.path.isdir(cfg.data_dir) else 'will be created'}")
    try:
        import curl_cffi  # noqa: F401
        print("  curl_cffi          ok (optional)")
    except ModuleNotFoundError:
        print("  curl_cffi          not installed (optional)")
    print("nothing is ever installed or executed by this agent; a FAIL above only means that source is unreachable from here")
    return 1 if bad else 0


def cmd_run(args) -> int:
    cfg = load_config(args.config)
    Agent(cfg).run()
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="canary", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-c", "--config", default="config.toml")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run")
    p = sub.add_parser("scan")
    p.add_argument("ecosystem", choices=["npm", "pypi"]); p.add_argument("name"); p.add_argument("version", nargs="?")
    p.add_argument("--json", action="store_true"); p.add_argument("--offline", action="store_true")
    p = sub.add_parser("check")
    p.add_argument("file", help="package.json, package-lock.json, yarn.lock, requirements.txt, pyproject.toml, Pipfile, or - for stdin")
    p.add_argument("--ecosystem", default="auto", choices=["auto", "npm", "pypi"])
    p.add_argument("--json", action="store_true"); p.add_argument("--offline", action="store_true")
    sub.add_parser("status")
    sub.add_parser("doctor")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    return {"run": cmd_run, "scan": cmd_scan, "check": cmd_check, "status": cmd_status, "doctor": cmd_doctor}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
