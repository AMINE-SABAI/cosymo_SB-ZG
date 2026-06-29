"""Pipeline d'évaluation d'un actif.

  produit --NVD(CPE)--> CVE récentes + CVSS --EPSS+KEV--> métriques sourcées

Sortie : liste de CVEEnrichment, chacune portant tout (CVSS, EPSS, KEV, provenance).
"""

from .enrich import enrich
from .model import Provenance


def assess_asset(keyword, nvd_client, epss_client, kev_catalog,
                 max_recent=15, pool=2000):
    # 1. produit -> CPE
    candidates = nvd_client.resolve_cpe(keyword)
    if not candidates:
        return []
    top = candidates[0]

    # 2. toutes les CVE du produit, puis on garde les plus récentes
    all_cves = nvd_client.find_by_cpe(top.virtual_match, max_results=pool)
    all_cves.sort(key=lambda c: c.published or "", reverse=True)
    found = all_cves[:max_recent]
    cve_ids = [c.cve_id for c in found]

    # 3. CVE -> EPSS + KEV
    enriched = enrich(cve_ids, epss_client, kev_catalog)

    # 4. fusion du CVSS
    out = []
    for c in found:
        e = enriched[c.cve_id]
        e.cvss_score = c.cvss_score
        e.cvss_severity = c.cvss_severity
        e.cvss_version = c.cvss_version
        e.description = c.description
        e.provenance["cvss"] = Provenance("NVD", c.cvss_version, c.retrieved_at)
        out.append(e)
    return out