"""Finder NVD avec retry réseau.

Deux modes : find_by_keyword (texte, dépannage) et resolve_cpe + find_by_cpe (produit).
Les requêtes réessaient automatiquement en cas de hoquet réseau.
"""

import time
import requests
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone

from .model import NvdCve

NVD_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPES = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


def _get_with_retry(session, url, params, timeout, tries=3, pause=2.0):
    """Réessaie en cas de hoquet réseau (timeout, connexion coupée)."""
    last = None
    for attempt in range(tries):
        try:
            resp = session.get(url, params=params, timeout=timeout)
            resp.raise_for_status()
            return resp
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.ChunkedEncodingError) as e:
            last = e
            if attempt < tries - 1:
                time.sleep(pause * (attempt + 1))
    raise last


@dataclass
class CpeCandidate:
    part: str
    vendor: str
    product: str
    virtual_match: str
    title: str
    count: int


def _extract_cvss(metrics):
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        items = metrics.get(key)
        if items:
            data = items[0].get("cvssData", {})
            severity = items[0].get("baseSeverity") or data.get("baseSeverity")
            return data.get("baseScore"), severity, data.get("vectorString"), ver
    return None, None, None, None


def _parse_cve(item, fetched_at):
    cve = item["cve"]
    score, sev, vector, ver = _extract_cvss(cve.get("metrics", {}))
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
    return NvdCve(cve_id=cve["id"], cvss_score=score, cvss_severity=sev,
                  cvss_vector=vector, cvss_version=ver, description=desc,
                  published=cve.get("published"), retrieved_at=fetched_at)


class NvdClient:
    def __init__(self, api_key=None, timeout=30, session=None):
        self.api_key = api_key
        self.timeout = timeout
        self.session = session or requests.Session()
        if api_key:
            self.session.headers.update({"apiKey": api_key})
        self.delay = 0.7 if api_key else 6.5

    def _search_cves(self, params, max_results):
        results, start = [], 0
        per_page = min(max_results, 2000)
        fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        while len(results) < max_results:
            q = dict(params, resultsPerPage=per_page, startIndex=start)
            resp = _get_with_retry(self.session, NVD_CVES, q, self.timeout)
            payload = resp.json()
            for item in payload.get("vulnerabilities", []):
                results.append(_parse_cve(item, fetched_at))
                if len(results) >= max_results:
                    break
            total = payload.get("totalResults", 0)
            start += per_page
            if start >= total:
                break
            time.sleep(self.delay)
        return results

    def find_by_keyword(self, keyword, max_results=50, exact=False):
        params = {"keywordSearch": keyword}
        if exact:
            params["keywordExactMatch"] = ""
        return self._search_cves(params, max_results)

    def find_by_cpe(self, virtual_match, max_results=50):
        return self._search_cves({"virtualMatchString": virtual_match}, max_results)

    def resolve_cpe(self, keyword, limit=200):
        resp = _get_with_retry(self.session, NVD_CPES,
                               {"keywordSearch": keyword, "resultsPerPage": limit},
                               self.timeout)
        payload = resp.json()
        counter, titles = Counter(), {}
        for prod in payload.get("products", []):
            cpe = prod.get("cpe", {})
            if cpe.get("deprecated"):
                continue
            parts = cpe.get("cpeName", "").split(":")
            if len(parts) < 5:
                continue
            base = (parts[2], parts[3], parts[4])
            counter[base] += 1
            if base not in titles:
                ts = cpe.get("titles", [])
                titles[base] = next((t["title"] for t in ts if t.get("lang") == "en"),
                                    ts[0]["title"] if ts else f"{base[1]} {base[2]}")
        out = []
        for (part, vendor, product), count in counter.most_common():
            vm = f"cpe:2.3:{part}:{vendor}:{product}:*:*:*:*:*:*:*:*"
            out.append(CpeCandidate(part, vendor, product, vm, titles[(part, vendor, product)], count))
        return out