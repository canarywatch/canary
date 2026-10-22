"""HTTP: the files the site reads, and two POSTs anyone can call.

GET  /state.json  /catches.json  /watch.json  /events.json  /rules.json  /popular.json
GET  /health
POST /check   json: { "text": "<package.json | package-lock.json | yarn.lock | pnpm-lock.yaml |
                                requirements.txt | pyproject.toml | Pipfile | a list of names>",
                      "ecosystem": "auto" | "npm" | "pypi" }
              -> every name matched against the wall and against OSV. the text is parsed in memory
                 and dropped; nothing a person pastes is written anywhere.
POST /scan    json: { "ecosystem": "npm" | "pypi", "name": "...", "version": "..." (optional) }
              -> fetches that one package from the public registry, runs the rules, asks OSV,
                 returns the verdict with the evidence. a tripped or confirmed result goes on the wall
                 like any other (source: "request").

Rate limits per IP: /check 10 a minute, /scan 4 a minute; two on-request scans run at once, the rest wait
up to 25 s and then get a 429. CORS is open for GET and for POST from the site.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from . import manifests

log = logging.getLogger("canary.server")

PUBLIC_FILES = {"state.json", "catches.json", "watch.json", "events.json", "rules.json", "popular.json"}
MAX_BODY = 2_200_000            # a package-lock.json of a big app is ~2 MB
EMPTY = {"state.json": {"updated": 0}, "events.json": {"updated": 0, "events": []}, "rules.json": {"rules": []}}


class Store:
    """Shared between the agent loop and the request threads."""

    def __init__(self, data_dir: str, agent=None):
        self.data_dir = data_dir
        self.agent = agent
        self.lock = threading.Lock()
        self.rate: dict[str, list[float]] = {}
        self.scan_slots = threading.Semaphore(2)

    def path(self, name: str) -> str:
        return os.path.join(self.data_dir, name)

    def read(self, name: str, default):
        try:
            with open(self.path(name)) as f:
                return json.load(f)
        except Exception:  # noqa: BLE001
            return default

    def allow(self, ip: str, bucket: str, per_min: int) -> bool:
        now = time.time()
        key = f"{bucket}:{ip}"
        with self.lock:
            hits = [t for t in self.rate.get(key, []) if now - t < 60]
            if len(hits) >= per_min:
                self.rate[key] = hits
                return False
            hits.append(now)
            self.rate[key] = hits
            if len(self.rate) > 20_000:
                self.rate = {k: v for k, v in self.rate.items() if v and now - v[-1] < 60}
            return True

    # ------------------------------------------------------------ /check
    def check(self, text: str, ecosystem: str) -> dict:
        eco, pairs, fmt = manifests.parse(text, ecosystem)
        catches = self.read("catches.json", [])
        on_wall: dict[str, list[dict]] = {}
        for c in catches:
            if c.get("ecosystem") == eco:
                on_wall.setdefault(c["name"], []).append(c)
        results = []
        osv_ok = True
        advis: dict[str, list[str]] = {}
        if self.agent is not None:
            advis = self.agent.osv.batch_names(eco, [n for n, _ in pairs])
            osv_ok = self.agent.osv.ok
        per_version_budget = 60
        for name, version in pairs:
            r: dict = {"name": name, "version": version, "status": "clean"}
            hits = on_wall.get(name, [])
            exact = next((c for c in hits if version and c["version"] == version), None)
            if exact and exact.get("verdict") in ("confirmed", "tripped"):
                r["status"] = exact["verdict"]
                r["rules"] = exact.get("rules", [])
                r["ids"] = [a["id"] for a in exact.get("advisories", [])]
                r["url"] = exact.get("url")
            elif hits and any(c.get("verdict") in ("confirmed", "tripped") for c in hits):
                r["status"] = "other-version"
                r["versions"] = sorted({c["version"] for c in hits if c.get("verdict") in ("confirmed", "tripped")})[:10]
            if name in advis and r["status"] != "confirmed":
                ids = advis[name]
                if version and self.agent is not None and per_version_budget > 0:
                    per_version_budget -= 1
                    exact_ids = self.agent.osv.malware_ids(eco, name, version)
                    if exact_ids:
                        r["status"] = "confirmed"; r["ids"] = exact_ids
                    elif r["status"] == "clean":
                        r["status"] = "other-version"; r["ids"] = ids
                else:
                    if r["status"] in ("clean", "other-version"):
                        r["status"] = "advisory" if not version else r["status"]
                        r["ids"] = ids
                        if r["status"] == "advisory":
                            r["note"] = "a malware advisory exists for this name; pin a version to check it exactly"
            if r.get("ids"):
                r["advisories"] = [{"id": i, "url": f"https://osv.dev/vulnerability/{i}"} for i in r["ids"][:6]]
            results.append(r)
        if self.agent is not None:
            with self.agent.lock:
                self.agent.checks_total += 1
        counts = {}
        for r in results:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        bad = [r for r in results if r["status"] != "clean"]
        return {"ecosystem": eco, "format": fmt, "parsed": len(pairs), "counts": counts, "flagged": bad, "osv_ok": osv_ok, "ts": int(time.time())}

    # ------------------------------------------------------------ /scan
    def scan(self, ecosystem: str, name: str, version: str | None) -> dict:
        if self.agent is None:
            raise RuntimeError("no agent")
        if ecosystem not in ("npm", "pypi"):
            raise ValueError("ecosystem must be npm or pypi")
        if ecosystem == "pypi":
            name = manifests.norm_pypi(name)
        if not manifests.valid_name(ecosystem, name):
            raise ValueError("that is not a valid package name")
        if version is not None and (len(version) > 64 or not re.match(r"^[0-9A-Za-z.+-]+$", version)):
            raise ValueError("that is not a valid version")
        if not self.scan_slots.acquire(timeout=25):
            raise TimeoutError("busy, try again in a moment")
        try:
            return self.agent.scan_now(ecosystem, name, version)
        finally:
            self.scan_slots.release()


def make_handler(store: Store, cors: str = "*"):
    class H(BaseHTTPRequestHandler):
        server_version = "canary/0.1"

        def log_message(self, fmt, *args):  # quieter
            log.debug(fmt, *args)

        def _cors(self):
            self.send_header("Access-Control-Allow-Origin", cors)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

        def _json(self, code: int, doc) -> None:
            body = json.dumps(doc, ensure_ascii=False).encode()
            self.send_response(code)
            self._cors()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _ip(self) -> str:
            return self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()[:64]

        def _body(self, limit: int) -> dict | None:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > limit:
                self._json(413, {"error": f"body must be 1 byte to {limit} bytes"})
                return None
            try:
                doc = json.loads(self.rfile.read(n))
            except Exception:  # noqa: BLE001
                self._json(400, {"error": "bad json"})
                return None
            if not isinstance(doc, dict):
                self._json(400, {"error": "json must be an object"})
                return None
            return doc

        def do_OPTIONS(self):
            self.send_response(204)
            self._cors()
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            name = urlparse(self.path).path.strip("/")
            if name in PUBLIC_FILES:
                fp = store.path(name)
                if not os.path.exists(fp):
                    return self._json(200, EMPTY.get(name, []))
                with open(fp, "rb") as f:
                    body = f.read()
                self.send_response(200)
                self._cors()
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
            if name in ("", "health"):
                return self._json(200, {"ok": True, "ts": int(time.time())})
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            p = urlparse(self.path).path
            ip = self._ip()
            if p == "/check":
                if not store.allow(ip, "check", 10):
                    return self._json(429, {"error": "too many requests, ten a minute"})
                doc = self._body(MAX_BODY)
                if doc is None:
                    return None
                text = doc.get("text")
                if not isinstance(text, str):
                    return self._json(400, {"error": "text must be a string"})
                eco = doc.get("ecosystem") or "auto"
                if eco not in ("auto", "npm", "pypi"):
                    return self._json(400, {"error": "ecosystem must be auto, npm or pypi"})
                try:
                    return self._json(200, store.check(text, eco))
                except ValueError as e:
                    return self._json(400, {"error": f"could not read that: {e}"})
                except Exception as e:  # noqa: BLE001
                    log.warning("check failed: %s", e)
                    return self._json(500, {"error": "check failed"})
            if p == "/scan":
                if not store.allow(ip, "scan", 4):
                    return self._json(429, {"error": "too many requests, four a minute"})
                doc = self._body(4096)
                if doc is None:
                    return None
                eco = str(doc.get("ecosystem") or "npm")
                name = str(doc.get("name") or "").strip()
                version = doc.get("version")
                version = str(version).strip() if version else None
                try:
                    return self._json(200, store.scan(eco, name, version))
                except ValueError as e:
                    return self._json(400, {"error": str(e)})
                except TimeoutError as e:
                    return self._json(429, {"error": str(e)})
                except LookupError as e:
                    return self._json(404, {"error": str(e)})
                except Exception as e:  # noqa: BLE001
                    log.warning("scan failed: %s", e)
                    return self._json(500, {"error": "scan failed"})
            return self._json(404, {"error": "not found"})

    return H


def serve(store: Store, host: str, port: int, cors: str = "*") -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), make_handler(store, cors))
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True, name="canary-http")
    t.start()
    log.info("http on %s:%s", host, port)
    return srv
