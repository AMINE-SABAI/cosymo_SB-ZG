"""Orchestrateur d'enrichissement.

Entrée : une liste d'identifiants de CVE.
Sortie : {cve_id: CVEEnrichment} — chaque CVE avec ses métriques ET leur source.

Discipline : on ne fabrique jamais un chiffre. Si une source ne couvre pas une
CVE, le champ reste None et on l'écrit dans `notes`.
"""

from .model import CVEEnrichment, Provenance


def enrich(cve_ids, epss_client, kev_catalog):
    ids = list(dict.fromkeys(cve_ids))
    epss_map = epss_client.fetch(ids)          # 1 appel batché
    results = {}

    for cve_id in ids:
        enr = CVEEnrichment(cve_id=cve_id)

        # --- EPSS ---
        e = epss_map.get(cve_id)
        if e is not None:
            enr.epss = e.epss
            enr.epss_percentile = e.percentile
            enr.provenance["epss"] = Provenance("FIRST EPSS", e.as_of, e.retrieved_at)
        else:
            enr.notes.append("EPSS : CVE non couverte")

        # --- KEV ---
        k = kev_catalog.lookup(cve_id)
        enr.in_kev = k.in_kev
        enr.kev_date_added = k.date_added
        enr.kev_ransomware = k.ransomware
        enr.provenance["kev"] = Provenance(
            "CISA KEV", kev_catalog.catalog_version, k.retrieved_at
        )

        results[cve_id] = enr

    return results