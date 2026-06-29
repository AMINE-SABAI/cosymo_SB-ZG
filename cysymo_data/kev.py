"""Connecteur KEV (CISA Known Exploited Vulnerabilities).

Signal binaire fort : si une CVE y est, elle est exploitée *maintenant*.
On télécharge le catalogue entier une fois, on le met en cache, recherches O(1).
"""

import json
import os
import time
import requests
from datetime import datetime, timezone

from .model import KevResult

KEV_OFFICIAL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"


def _to_bool(v):
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("known", "true", "yes", "1")


class KevCatalog:
    def __init__(self, session=None, url=KEV_OFFICIAL,
                 cache_path="data/kev_cache.json", ttl_hours=24, timeout=30):
        self.session = session or requests.Session()
        self.url = url
        self.cache_path = cache_path
        self.ttl_seconds = ttl_hours * 3600
        self.timeout = timeout
        self._index = None
        self.catalog_version = None
        self.retrieved_at = None

    def _cache_fresh(self):
        if not os.path.exists(self.cache_path):
            return False
        return (time.time() - os.path.getmtime(self.cache_path)) < self.ttl_seconds

    def _download(self):
        resp = self.session.get(self.url, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        with open(self.cache_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return data

    def _read_cache(self):
        with open(self.cache_path, encoding="utf-8") as f:
            return json.load(f)

    def load(self, force=False):
        data = self._read_cache() if (not force and self._cache_fresh()) else self._download()
        self.catalog_version = data.get("catalogVersion") or data.get("dateReleased")
        self.retrieved_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._index = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
        return self

    def _ensure(self):
        if self._index is None:
            self.load()

    def lookup(self, cve_id) -> KevResult:
        self._ensure()
        entry = self._index.get(cve_id)
        if entry is None:
            return KevResult(cve_id=cve_id, in_kev=False, retrieved_at=self.retrieved_at)
        return KevResult(
            cve_id=cve_id,
            in_kev=True,
            date_added=entry.get("dateAdded"),
            ransomware=_to_bool(entry.get("knownRansomwareCampaignUse")),
            retrieved_at=self.retrieved_at,
        )

    def __contains__(self, cve_id):
        self._ensure()
        return cve_id in self._index

    def __len__(self):
        self._ensure()
        return len(self._index)