"""Orchestration d'une mission : plusieurs actifs -> analyse consolidée.

Une mission = un client + une liste d'actifs. Pour chaque actif on déroule
la chaîne (produit -> CVE récentes -> métriques -> risque), puis on produit
une liste de findings priorisée TOUS actifs confondus : le "quoi corriger
d'abord" que le consultant attend.
"""

from dataclasses import dataclass, field

from cysymo_data import assess_asset
from cysymo_engine import asset_risk


@dataclass
class Asset:
    name: str                  # ex. "Passerelle VPN"
    product: str               # mot-clé produit (ex. "Fortinet FortiOS")
    exposure: str = "MEDIUM"   # LOW / MEDIUM / HIGH (humain)
    criticality: str = "MEDIUM"
    context: str = ""          # note métier (humain)
    version: str = ""          # version exacte (ex. "2.4.52"), venue d'un scan


@dataclass
class Finding:
    asset: str
    cve_id: str
    risk: float
    cvss_score: float
    epss: float
    in_kev: bool
    description: str = ""
    cvss_severity: str = ""
    product: str = ""
    version: str = ""


@dataclass
class MissionResult:
    client: str
    asset_risks: list = field(default_factory=list)  # [(Asset, AssetRisk)]
    findings: list = field(default_factory=list)      # Findings triés par risque


def run_mission(client, assets, nvd, epss, kev, max_recent=15):
    asset_risks, findings = [], []
    for a in assets:
        rows = assess_asset(a.product, nvd, epss, kev, max_recent=max_recent,
                            version=(a.version or None))
        ar = asset_risk(a.name, rows, exposure=a.exposure, criticality=a.criticality)
        asset_risks.append((a, ar))
        by_id = {e.cve_id: e for e in rows}
        for r in ar.cve_risks:
            if r.determined:
                e = by_id[r.cve_id]
                findings.append(Finding(a.name, r.cve_id, r.risk,
                                        e.cvss_score, e.epss, e.in_kev,
                                        description=e.description or "",
                                        cvss_severity=e.cvss_severity or "",
                                        product=a.product, version=(a.version or "")))
    findings.sort(key=lambda f: f.risk, reverse=True)
    return MissionResult(client, asset_risks, findings)
