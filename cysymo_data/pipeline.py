from .enrich import enrich
from .model import Provenance


def _inject_version(virtual_match, version):
    """Insère la version exacte dans le CPE : cpe:2.3:a:v:p:*:... -> ...:p:VERSION:..."""
    parts = virtual_match.split(":")
    if len(parts) >= 6:
        parts[5] = version  # champ version (juste après le produit)
    return ":".join(parts)


def assess_asset(keyword, nvd_client, epss_client, kev_catalog,
                 max_recent=15, pool=2000, version=None):
    """Cherche les CVE d'un produit. Si version fournie, cible CETTE version ;
    repli automatique sur le produit entier si la version ne matche rien (format NVD)."""
    candidates = nvd_client.resolve_cpe(keyword)
    if not candidates:
        return []
    top = candidates[0]

    all_cves = []
    used_version = False
    if version:
        vm = _inject_version(top.virtual_match, version)
        all_cves = nvd_client.find_by_cpe(vm, max_results=pool)
        used_version = bool(all_cves)  # la version a matché si on a des résultats

    # repli : version inconnue de NVD (format different) -> produit entier
    if not all_cves:
        all_cves = nvd_client.find_by_cpe(top.virtual_match, max_results=pool)

    all_cves.sort(key=lambda c: c.published or "", reverse=True)
    found = all_cves[:max_recent]
    enriched = enrich([c.cve_id for c in found], epss_client, kev_catalog)
    out = []
    for c in found:
        e = enriched[c.cve_id]
        e.cvss_score = c.cvss_score
        e.cvss_severity = c.cvss_severity
        e.cvss_version = c.cvss_version
        e.description = c.description
        e.provenance["cvss"] = Provenance("NVD", c.cvss_version, c.retrieved_at)
        # trace : a-t-on ciblé la version exacte ?
        e.notes = (e.notes or "") + (f" [version ciblée : {version}]" if used_version else "")
        out.append(e)
    return out
