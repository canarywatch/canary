"""Confirmation from the public record: OSV.dev, which carries the OpenSSF malicious-packages
advisories (ids starting with MAL-) and GitHub's malware advisories.

A package is "confirmed" on the wall only when one of these says so. Our own rules can only
ever say "tripped", with the evidence next to it.
"""

from __future__ import annotations

import logging
import threading
import time

import requests

log = logging.getLogger("canary.osv")

QUERY = "https://api.osv.dev/v1/query"
BATCH = "https://api.osv.dev/v1/querybatch"
ECO = {"npm": "npm", "pypi": "PyPI"}
UA = {"User-Agent": "canary-agent/0.1 static analysis, never installs"}


def _is_malware(v: dict) -> bool:
    vid = v.get("id", "")
    if vid.startswith("MAL-"):
        return True
    text = (v.get("summary") or "") + " " + (v.get("details") or "")
    aliases = " ".join(v.get("aliases") or [])
    return "MAL-" in aliases or "malicious" in text.lower() or "malware" in text.lower()


class Osv:
    def __init__(self, ttl_s: int = 6 * 3600):
        self.cache: dict[str, tuple[float, list[str]]] = {}
        self.ttl = ttl_s
        self.lock = threading.Lock()
        self.ok = True
        self.last_error = ""

    def malware_ids(self, ecosystem: str, name: str, version: str | None = None) -> list[str]:
        """advisory ids that call this package malicious; [] when none or when OSV is unreachable (then self.ok is False)"""
        key = f"{ecosystem}:{name}@{version or '*'}"
        now = time.time()
        with self.lock:
            hit = self.cache.get(key)
            if hit and now - hit[0] < self.ttl:
                return hit[1]
        body: dict = {"package": {"name": name, "ecosystem": ECO.get(ecosystem, ecosystem)}}
        if version:
            body["version"] = version
        try:
            r = requests.post(QUERY, json=body, headers=UA, timeout=20)
            r.raise_for_status()
            vulns = r.json().get("vulns") or []
            ids = sorted({v["id"] for v in vulns if _is_malware(v)})
            self.ok = True
        except Exception as e:  # noqa: BLE001
            self.ok = False
            self.last_error = str(e)[:200]
            log.warning("osv %s: %s", key, e)
            return []
        with self.lock:
            self.cache[key] = (now, ids)
            if len(self.cache) > 50_000:
                old = sorted(self.cache.items(), key=lambda kv: kv[1][0])[: len(self.cache) // 2]
                for k, _ in old:
                    self.cache.pop(k, None)
        return ids

    def batch_names(self, ecosystem: str, names: list[str]) -> dict[str, list[str]]:
        """for /check: which of these names has any malware advisory, any version. up to 1000 per call."""
        out: dict[str, list[str]] = {}
        eco = ECO.get(ecosystem, ecosystem)
        for i in range(0, len(names), 500):
            chunk = names[i:i + 500]
            try:
                r = requests.post(BATCH, json={"queries": [{"package": {"name": n, "ecosystem": eco}} for n in chunk]}, headers=UA, timeout=30)
                r.raise_for_status()
                results = r.json().get("results") or []
            except Exception as e:  # noqa: BLE001
                log.warning("osv batch: %s", e)
                self.ok = False
                continue
            for n, res in zip(chunk, results):
                # querybatch returns ids only; MAL- ids are the malicious ones, GHSA need a second look (skipped here)
                ids = [v["id"] for v in (res.get("vulns") or []) if str(v.get("id", "")).startswith("MAL-")]
                if ids:
                    out[n] = ids
        return out
