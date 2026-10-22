"""The loop. Watch the registries, fetch what is new, run the rules, ask the public record, write the wall.

Everything the site shows is a file in data_dir:
    state.json     counters, rates, feed health, the recall number, the last packages seen
    catches.json   the wall: confirmed and tripped packages, newest first, with evidence
    watch.json     the quiet list: packages that tripped something but not enough. never shown as catches
    events.json    the live feed of what the agent did
    rules.json     the method, as the site prints it
    cleared.json   written by a person: catches that turned out to be wrong, with the reason

Hard limits, by construction: nothing is installed or executed, ever (fetch.py keeps bytes only);
a name is never on the wall without the lines that put it there; "confirmed" only comes from
OSV / OpenSSF; the agent never posts anywhere.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import fetch, rules
from .osv import Osv

log = logging.getLogger("canary")

NPM_URL = "https://www.npmjs.com/package/{name}/v/{version}"
PYPI_URL = "https://pypi.org/project/{name}/{version}/"
OSV_URL = "https://osv.dev/vulnerability/{id}"


@dataclass
class Config:
    data_dir: str = "./data"
    npm: bool = True
    pypi: bool = True
    workers: int = 4
    poll_s: int = 20
    max_catches: int = 600
    max_watch: int = 400
    recheck_days: int = 30
    host: str = "127.0.0.1"
    port: int = 8791
    cors: str = "*"
    popular_refresh_h: int = 24
    extra_popular: list[str] = field(default_factory=list)
    links: dict = field(default_factory=dict)          # token mint, x, github, site: shown by the site, set in config


def read_json(path: str, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return default


def write_json(path: str, doc) -> None:
    fetch.save_json(path, doc)


class Agent:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        os.makedirs(cfg.data_dir, exist_ok=True)
        self.lock = threading.Lock()
        self.osv = Osv()
        self.catches: list[dict] = read_json(self.p("catches.json"), [])
        self.watch: list[dict] = read_json(self.p("watch.json"), [])
        st = read_json(self.p("state.json"), {})
        self.events: deque = deque(read_json(self.p("events.json"), {}).get("events", []), maxlen=300)
        self.scanned_total = int(st.get("scanned_total", 0))
        self.checks_total = int(st.get("checks_total", 0))
        self.requested_total = int(st.get("requested_total", 0))
        self.recall = st.get("recall") or {"confirmed_seen": 0, "rules_tripped": 0, "rules_watched": 0, "rules_missed": 0}
        self.recent: deque = deque(maxlen=40)
        self.cleanlog: deque = deque(maxlen=2000)      # clean summaries, so a repeated /scan answers without a refetch
        self.times: deque = deque(maxlen=5000)         # timestamps of scans, for rates
        self.npm_feed = fetch.NpmChanges(st.get("npm_seq"))
        self.pypi_feed = fetch.PypiUpdates()
        self.popular: set[str] = set()
        self.popular_at = 0.0
        self.seen: dict[str, float] = {}               # name@version -> ts, skip repeats for a day
        self.inflight: set[str] = set()
        self.pool = ThreadPoolExecutor(max_workers=cfg.workers, thread_name_prefix="scan")
        self.started = time.time()
        self.event("boot", text="agent started")
        write_json(self.p("rules.json"), {"version": rules.RULES_VERSION, "rules": rules.RULE_TABLE, "trip": rules.TRIP, "watch": rules.WATCH, "strong": rules.STRONG, "fresh_h": rules.FRESH_H,
                                           "established": "first release over a year ago, or over 50k weekly downloads: heuristics alone never put it on the wall",
                                           "never": ["installs or runs a package", "posts anywhere", "names a package without the lines that tripped", "calls anything confirmed without a public advisory"]})

    # ------------------------------------------------------------ small helpers
    def p(self, name: str) -> str:
        return os.path.join(self.cfg.data_dir, name)

    def event(self, kind: str, **data) -> None:
        rec = {"ts": int(time.time()), "kind": kind}
        rec.update(data)
        with self.lock:
            self.events.append(rec)

    def refresh_popular(self) -> None:
        if time.time() - self.popular_at < self.cfg.popular_refresh_h * 3600 and self.popular:
            return
        names = set(self.cfg.extra_popular)
        if self.cfg.npm:
            names.update(fetch.popular_npm())
        if self.cfg.pypi:
            names.update(fetch.popular_pypi())
        if names:
            self.popular = names
            self.popular_at = time.time()
            write_json(self.p("popular.json"), sorted(names))
            log.info("popular names: %d", len(names))
        elif not self.popular:
            self.popular = set(read_json(self.p("popular.json"), []))

    def cleared(self) -> dict:
        return read_json(self.p("cleared.json"), {})

    # ------------------------------------------------------------ one package
    def scan(self, ecosystem: str, name: str, version: str | None = None) -> None:
        key = f"{ecosystem}:{name}@{version or 'latest'}"
        with self.lock:
            if key in self.inflight:
                return
            self.inflight.add(key)
        try:
            self._scan(ecosystem, name, version)
        except fetch.SkipPackage as e:
            log.info("skip %s: %s", key, e)
        except Exception as e:  # noqa: BLE001
            log.warning("scan %s failed: %s", key, e)
        finally:
            with self.lock:
                self.inflight.discard(key)

    def scan_now(self, ecosystem: str, name: str, version: str | None) -> dict:
        """a scan somebody asked for (POST /scan or the cli): returns the summary, raises LookupError when the
        registry has no such package, and still puts a tripped or confirmed result on the wall."""
        import requests
        try:
            s = self._scan(ecosystem, name, version, source="request")
        except fetch.SkipPackage as e:
            raise LookupError(str(e)) from e
        except requests.HTTPError as e:
            code = getattr(e.response, "status_code", 0)
            if code == 404:
                raise LookupError(f"{name}: not in the {ecosystem} registry") from e
            raise
        if s is None:                        # seen within the day: hand back what the wall already knows
            s = self.known(ecosystem, name, version) or self._scan(ecosystem, name, version, source="request", force=True)
        with self.lock:
            self.requested_total += 1
        return s

    def known(self, ecosystem: str, name: str, version: str | None) -> dict | None:
        with self.lock:
            for pool in (self.catches, self.watch, list(self.cleanlog)):
                for c in pool:
                    if c.get("ecosystem") == ecosystem and c.get("name") == name and (version is None or c.get("version") == version):
                        return dict(c)
        return None

    def _scan(self, ecosystem: str, name: str, version: str | None, source: str = "feed", force: bool = False) -> dict | None:
        pkg = fetch.npm_package(name, version) if ecosystem == "npm" else fetch.pypi_package(name, version)
        key = f"{ecosystem}:{pkg.name}@{pkg.version}"
        now = time.time()
        with self.lock:
            if not force and now - self.seen.get(key, 0) < 86400:
                return None
            self.seen[key] = now
            if len(self.seen) > 100_000:
                cut = now - 86400
                self.seen = {k: t for k, t in self.seen.items() if t > cut}
        findings = rules.analyze(pkg, self.popular)
        ids = self.osv.malware_ids(ecosystem, pkg.name, pkg.version)
        confirmed = bool(ids)
        s = rules.summary(pkg, findings, confirmed)
        s["ts"] = int(now)
        s["source"] = source
        s["url"] = (NPM_URL if ecosystem == "npm" else PYPI_URL).format(name=pkg.name, version=pkg.version)
        s["advisories"] = [{"id": i, "url": OSV_URL.format(id=i)} for i in ids]
        with self.lock:
            self.scanned_total += 1
            self.times.append(now)
            self.recent.appendleft({"ecosystem": ecosystem, "name": pkg.name, "version": pkg.version, "verdict": s["verdict"], "score": s["score"], "ts": int(now)})
            if s["verdict"] == "clean":
                self.cleanlog.appendleft(s)
        if s["verdict"] == "confirmed":
            # the recall number: would the rules have caught it on their own?
            with self.lock:
                self.recall["confirmed_seen"] += 1
                v_rules = rules.verdict(pkg, findings, confirmed=False)
                self.recall["rules_tripped" if v_rules == "tripped" else "rules_watched" if v_rules == "watch" else "rules_missed"] += 1
            s["rules_verdict"] = v_rules
            self.add_catch(s)
            self.event("confirm", **self._bits(s), ids=ids, rules=s["rules"])
        elif s["verdict"] == "tripped":
            self.add_catch(s)
            self.event("catch", **self._bits(s), rules=s["rules"], score=s["score"])
        else:
            with self.lock:
                before = len(self.catches)
                self.catches = [c for c in self.catches if not (c["ecosystem"] == ecosystem and c["name"] == pkg.name and c["version"] == pkg.version and c.get("verdict") != "confirmed")]
                dropped = before - len(self.catches)
                self.watch = [w for w in self.watch if not (w["ecosystem"] == ecosystem and w["name"] == pkg.name and w["version"] == pkg.version)]
                if s["verdict"] == "watch":
                    self.watch.insert(0, s)
                    del self.watch[self.cfg.max_watch:]
            if dropped:
                self.event("drop", **self._bits(s), score=s["score"], text=f"re-read under rules {rules.RULES_VERSION}: {s['verdict']} (score {s['score']}), taken off the wall")
        log.info("%s %s score %d rules %s", key, s["verdict"], s["score"], ",".join(s["rules"]))
        return s

    def _bits(self, s: dict) -> dict:
        return {"ecosystem": s["ecosystem"], "name": s["name"], "version": s["version"], "url": s["url"]}

    def add_catch(self, s: dict) -> None:
        cl = self.cleared()
        k = f"{s['ecosystem']}:{s['name']}@{s['version']}"
        if k in cl:
            s["verdict"] = "cleared"; s["cleared_reason"] = str(cl[k])[:300]
        with self.lock:
            self.catches = [c for c in self.catches if not (c["ecosystem"] == s["ecosystem"] and c["name"] == s["name"] and c["version"] == s["version"])]
            self.catches.insert(0, s)
            del self.catches[self.cfg.max_catches:]

    # ------------------------------------------------------------ the record catching up with us
    def recheck(self) -> None:
        """tripped catches get re-asked at OSV: a later confirmation is the best thing that can happen to a catch."""
        cut = time.time() - self.cfg.recheck_days * 86400
        todo = [c for c in self.catches if c.get("verdict") == "tripped" and c.get("ts", 0) > cut and time.time() - c.get("rechecked", 0) > 6 * 3600]
        for c in todo[:40]:
            ids = self.osv.malware_ids(c["ecosystem"], c["name"], c["version"])
            c["rechecked"] = int(time.time())
            if ids:
                c["verdict"] = "confirmed"
                c["confirmed_ts"] = int(time.time())
                c["advisories"] = [{"id": i, "url": OSV_URL.format(id=i)} for i in ids]
                c["rules_verdict"] = "tripped"
                with self.lock:
                    self.recall["confirmed_seen"] += 1
                    self.recall["rules_tripped"] += 1
                hours = (c["confirmed_ts"] - c["ts"]) / 3600
                self.event("confirm", **self._bits(c), ids=ids, rules=c["rules"], after_h=round(hours, 1), text=f"the record caught up {hours:.0f} h after the rules did")
        # cleared.json is a person's word; apply it to anything on the wall
        cl = self.cleared()
        for c in self.catches:
            k = f"{c['ecosystem']}:{c['name']}@{c['version']}"
            if k in cl and c.get("verdict") != "cleared":
                c["verdict"] = "cleared"; c["cleared_reason"] = str(cl[k])[:300]
                self.event("clear", **self._bits(c), reason=c["cleared_reason"])

    # ------------------------------------------------------------ feeds
    def poll_feeds(self) -> None:
        if self.cfg.npm:
            ids = self.npm_feed.poll()
            for name in ids:
                if name.startswith("@types/"):      # a mountain of generated d.ts, no payloads
                    continue
                self.pool.submit(self.scan, "npm", name, None)
        if self.cfg.pypi:
            for name, version in self.pypi_feed.poll():
                self.pool.submit(self.scan, "pypi", name, version or None)

    # ------------------------------------------------------------ files for the site
    def write_all(self) -> None:
        now = time.time()
        with self.lock:
            last_min = sum(1 for t in self.times if now - t < 60)
            last_h = sum(1 for t in self.times if now - t < 3600)
            catches = list(self.catches)
            watch = list(self.watch)
            events = list(self.events)
            recent = list(self.recent)
            recall = dict(self.recall)
        day = now - 86400
        shown = [c for c in catches if c.get("verdict") in ("confirmed", "tripped", "cleared")]
        state = {
            "updated": int(now), "uptime_s": int(now - self.started),
            "scanned_total": self.scanned_total, "scanned_last_min": last_min, "scanned_last_h": last_h,
            "checks_total": self.checks_total, "requested_total": self.requested_total,
            "catches_24h": sum(1 for c in shown if c["ts"] > day and c["verdict"] != "cleared"),
            "confirmed_24h": sum(1 for c in shown if c["ts"] > day and c["verdict"] == "confirmed"),
            "tripped_24h": sum(1 for c in shown if c["ts"] > day and c["verdict"] == "tripped"),
            "catches_total": sum(1 for c in shown if c["verdict"] != "cleared"),
            "cleared_total": sum(1 for c in shown if c["verdict"] == "cleared"),
            "watch_24h": sum(1 for w in watch if w["ts"] > day),
            "by_ecosystem": {e: sum(1 for c in shown if c["ecosystem"] == e and c["verdict"] != "cleared") for e in ("npm", "pypi")},
            "feeds": {"npm": {"on": self.cfg.npm, "ok": self.npm_feed.ok, "seq": str(self.npm_feed.since), "error": self.npm_feed.last_error},
                      "pypi": {"on": self.cfg.pypi, "ok": self.pypi_feed.ok, "error": self.pypi_feed.last_error},
                      "osv": {"ok": self.osv.ok, "error": self.osv.last_error}},
            "recall": recall, "popular_names": len(self.popular), "rules_version": rules.RULES_VERSION,
            "links": {k: v for k, v in self.cfg.links.items() if isinstance(v, str)},
            "recent": recent,
        }
        write_json(self.p("state.json"), state)
        write_json(self.p("catches.json"), shown[: self.cfg.max_catches])
        write_json(self.p("watch.json"), watch)
        write_json(self.p("events.json"), {"updated": int(now), "events": events})
        # the seq survives a restart
        state["npm_seq"] = self.npm_feed.since

    def rescore_stale(self) -> None:
        """tripped catches made under an older rules version are re-read with the current rules; what no
        longer trips comes off the wall, in public, as a 'drop' event. confirmed catches are never touched."""
        with self.lock:
            stale = [c for c in self.catches if c.get("verdict") == "tripped" and c.get("rules_version") != rules.RULES_VERSION]
        if not stale:
            return
        self.event("rescore", text=f"rules changed ({rules.RULES_VERSION}): re-reading {len(stale)} tripped catch(es)")
        log.info("rescoring %d stale catches under rules %s", len(stale), rules.RULES_VERSION)

        def work():                                   # its own thread, so the feeds cannot starve it
            for c in stale:
                self._rescore_one(c["ecosystem"], c["name"], c["version"])
            self.event("rescore", text=f"done: {len(stale)} catch(es) re-read under rules {rules.RULES_VERSION}")
        threading.Thread(target=work, daemon=True, name="rescore").start()

    def _rescore_one(self, ecosystem: str, name: str, version: str) -> None:
        import requests
        try:
            self._scan(ecosystem, name, version, source="rescore", force=True)
        except (fetch.SkipPackage, requests.HTTPError) as e:
            code = getattr(getattr(e, "response", None), "status_code", 0)
            if code == 404 or isinstance(e, fetch.SkipPackage):
                # gone from the registry (or unreadable) before the new rules could re-read it: a name
                # whose lines we cannot verify does not stay on the wall
                with self.lock:
                    self.catches = [c for c in self.catches if not (c["ecosystem"] == ecosystem and c["name"] == name and c["version"] == version and c.get("verdict") != "confirmed")]
                self.event("drop", ecosystem=ecosystem, name=name, version=version, text=f"gone from the registry before it could be re-read under rules {rules.RULES_VERSION}; taken off the wall")
            else:
                log.warning("rescore %s:%s@%s failed: %s", ecosystem, name, version, e)
        except Exception as e:  # noqa: BLE001
            log.warning("rescore %s:%s@%s failed: %s", ecosystem, name, version, e)

    def run(self) -> None:
        from .server import Store, serve
        store = Store(self.cfg.data_dir, agent=self)
        serve(store, self.cfg.host, self.cfg.port, self.cfg.cors)
        self.refresh_popular()
        self.rescore_stale()
        last_recheck = 0.0
        last_popular = time.time()
        while True:
            t0 = time.time()
            try:
                self.poll_feeds()
            except Exception as e:  # noqa: BLE001
                log.warning("poll: %s", e)
            if time.time() - last_recheck > 1800:
                last_recheck = time.time()
                try:
                    self.recheck()
                except Exception as e:  # noqa: BLE001
                    log.warning("recheck: %s", e)
            if time.time() - last_popular > 3600:
                last_popular = time.time()
                try:
                    self.refresh_popular()
                except Exception as e:  # noqa: BLE001
                    log.warning("popular: %s", e)
            try:
                self.write_all()
                st = read_json(self.p("state.json"), {})
                st["npm_seq"] = self.npm_feed.since
                write_json(self.p("state.json"), st)
            except Exception as e:  # noqa: BLE001
                log.warning("write: %s", e)
            time.sleep(max(1.0, self.cfg.poll_s - (time.time() - t0)))


def run(cfg: Config) -> None:
    Agent(cfg).run()
