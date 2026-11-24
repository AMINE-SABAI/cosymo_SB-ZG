"""Finder NVD.

Deux modes :
  - find_by_keyword            : recherche texte (bruité — dépannage)
  - resolve_cpe + find_by_cpe  : recherche par produit (propre — recommandé)

resolve_cpe('Fortinet FortiOS') -> candidats produit (part:vendor:product)
find_by_cpe(virtualMatchString) -> les CVE qui affectent ce produit (+ CVSS)
"""

import time
import requests
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone

from .model import NvdCve

NVD_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPES = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


# Correspondances connues : mot-clé (ou fragment) -> (vendor, product) canonique dans NVD.
# Résout les cas où le nom courant diffère du CPE (surtout les produits détectés par Nmap).
# Table volontairement petite et transparente ; s'étend facilement au besoin.
KNOWN_CPES = {
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "apache http": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "http server": ("apache", "http_server"),
    "openssh": ("openbsd", "openssh"),
    "nginx": ("f5", "nginx"),
    "postgresql": ("postgresql", "postgresql"),
    "postgres": ("postgresql", "postgresql"),
    "fortios": ("fortinet", "fortios"),
    "fortinet fortios": ("fortinet", "fortios"),
    "windows server": ("microsoft", "windows_server"),
    "exchange": ("microsoft", "exchange_server"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "openssl": ("openssl", "openssl"),
    "tomcat": ("apache", "tomcat"),
}


def _norm(s):
    """Minuscule, espaces normalisés, ponctuation légère retirée."""
    s = (s or "").lower().strip()
    for ch in ("(", ")", ",", "/"):
        s = s.replace(ch, " ")
    return " ".join(s.split())


def _known_cpe(norm_keyword):
    """Cherche une correspondance connue dans le mot-clé normalisé. Plus longue clé d'abord."""
    for key in sorted(KNOWN_CPES, key=len, reverse=True):
        if key in norm_keyword:
            return KNOWN_CPES[key]
    return None


@dataclass
class CpeCandidate:
    part: str           # 'a' appli · 'o' OS/firmware · 'h' matériel
    vendor: str
    product: str
    virtual_match: str  # à passer à find_by_cpe
    title: str
    count: int          # popularité (nb de cpeNames vus)


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
                  cvss_vector=vector, cvss_version=ver, description=desc, retrieved_at=fetched_at)


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
            resp = self.session.get(NVD_CVES, params=q, timeout=self.timeout)
            resp.raise_for_status()
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
        """Texte -> candidats produit, via le dictionnaire CPE.

        Classement ameliore : au lieu de la seule popularite, on score chaque
        candidat par sa CORRESPONDANCE au mot-cle (le bon produit passe devant le
        bruit tiers), avec une petite table de correspondances connues pour les
        produits ou le nom differe du CPE (ex. 'mysql' -> oracle:mysql).
        Le classement ne fait que REORDONNER : aucun candidat n'est supprime.
        """
        resp = self.session.get(NVD_CPES,
                                params={"keywordSearch": keyword, "resultsPerPage": limit},
                                timeout=self.timeout)
        resp.raise_for_status()
        payload = resp.json()
        counter, titles = Counter(), {}
        for prod in payload.get("products", []):
            cpe = prod.get("cpe", {})
            if cpe.get("deprecated"):
                continue
            parts = cpe.get("cpeName", "").split(":")
            if len(parts) < 5:
                continue
            base = (parts[2], parts[3], parts[4])  # part, vendor, product
            counter[base] += 1
            if base not in titles:
                ts = cpe.get("titles", [])
                titles[base] = next((t["title"] for t in ts if t.get("lang") == "en"),
                                    ts[0]["title"] if ts else f"{base[1]} {base[2]}")

        kw = _norm(keyword)
        kw_tokens = set(kw.split())
        hint = _known_cpe(kw)  # (vendor, product) attendu, ou None

        def score(base, count):
            part, vendor, product = base
            s = 0
            # 1) correspondance connue (le plus fort signal)
            if hint and (vendor, product) == hint:
                s += 10000
            # 2) le nom de produit CPE colle au mot-cle
            pn = _norm(product)
            if pn == kw or pn.replace("_", " ") == kw:
                s += 3000                       # egalite exacte
            elif kw_tokens & set(pn.replace("_", " ").split()):
                s += 800                        # un token commun
            # 3) le vendor est un des tokens du mot-cle (ex. 'fortinet')
            if _norm(vendor) in kw_tokens:
                s += 400
            # 4) popularite en depart de jeu / departage
            s += min(count, 300)
            return s

        ranked = sorted(counter.items(), key=lambda kv: score(kv[0], kv[1]), reverse=True)
        out = []
        for (part, vendor, product), count in ranked:
            vm = f"cpe:2.3:{part}:{vendor}:{product}:*:*:*:*:*:*:*:*"
            out.append(CpeCandidate(part, vendor, product, vm, titles[(part, vendor, product)], count))
        return out
