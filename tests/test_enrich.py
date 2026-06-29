"""Test offline de la Brique 0 : on injecte de fausses réponses,
on vérifie la logique sans dépendre du réseau."""

from unittest.mock import MagicMock
from cysymo_data import EpssClient, KevCatalog, enrich


def _fake_epss(rows):
    sess = MagicMock()
    resp = MagicMock()
    resp.json.return_value = {"status": "OK", "data": rows}
    resp.raise_for_status.return_value = None
    sess.get.return_value = resp
    return EpssClient(session=sess)


def _fake_kev(entries):
    cat = KevCatalog(session=MagicMock())
    cat._index = {e["cveID"]: e for e in entries}
    cat.catalog_version = "TEST-1.0"
    cat.retrieved_at = "2026-06-26T00:00:00+00:00"
    return cat


def test_enrichment():
    epss = _fake_epss([
        {"cve": "CVE-2024-21762", "epss": "0.808", "percentile": "0.99", "date": "2026-06-24"},
    ])
    kev = _fake_kev([
        {"cveID": "CVE-2024-21762", "dateAdded": "2024-02-09",
         "knownRansomwareCampaignUse": "Known"},
    ])
    out = enrich(["CVE-2024-21762", "CVE-9999-0000"], epss, kev)

    hot = out["CVE-2024-21762"]
    assert hot.epss == 0.808
    assert hot.in_kev is True
    assert hot.kev_ransomware is True
    assert hot.provenance["epss"].source == "FIRST EPSS"

    unknown = out["CVE-9999-0000"]
    assert unknown.epss is None
    assert unknown.epss_covered is False
    assert any("non couverte" in n for n in unknown.notes)
    print("OK  test_enrichment")


if __name__ == "__main__":
    test_enrichment()
    print("Tous les tests passent.")