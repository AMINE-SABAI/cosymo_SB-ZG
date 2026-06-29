"""Moteur de risque CySyMo (refonte).

Risque = Vraisemblance × Impact   (aligné NIST 800-30 / ISO 27005 / FAIR)
    vraisemblance = exposition × p     (p = EPSS, plancher relevé si KEV)
    impact        = (CVSS / 10) × criticité_métier

Risque par CVE dans [0,1]. Risque actif = 1 - Π(1 - risque_i).
Déterministe, zéro LLM. Donnée manquante -> "indéterminé", jamais inventé.
"""

from dataclasses import dataclass, field
from typing import Optional, Union

LEVELS = {"LOW": 0.3, "MEDIUM": 0.6, "HIGH": 1.0}
KEV_FLOOR = 0.95


def _coef(value: Union[str, float], default: float = 0.6) -> float:
    if value is None:
        return default
    if isinstance(value, str):
        return LEVELS[value.upper()]
    v = float(value)
    if not 0.0 <= v <= 1.0:
        raise ValueError("coefficient hors [0,1]")
    return v


@dataclass
class CVERisk:
    cve_id: str
    risk: Optional[float]
    likelihood: Optional[float]
    impact: Optional[float]
    exposure: float
    criticality: float
    kev_applied: bool
    determined: bool
    explanation: list = field(default_factory=list)


@dataclass
class AssetRisk:
    asset: str
    risk: Optional[float]
    cve_risks: list = field(default_factory=list)
    determined_count: int = 0
    undetermined_count: int = 0


def cve_risk(enr, exposure="MEDIUM", criticality="MEDIUM", kev_floor=KEV_FLOOR) -> CVERisk:
    e = _coef(exposure)
    c = _coef(criticality)
    expl = []

    p = enr.epss
    if enr.in_kev:
        floored = max(p if p is not None else 0.0, kev_floor)
        expl.append(f"vraisemblance : EPSS {p if p is not None else '—'} relevé au plancher KEV {kev_floor}")
        p = floored
    elif p is None:
        return CVERisk(enr.cve_id, None, None, None, e, c, False, False,
                       ["vraisemblance indéterminée (EPSS non couvert, hors KEV) — à coter par le consultant"])
    else:
        expl.append(f"vraisemblance : EPSS {p:.3f}")

    likelihood = e * p
    expl.append(f"  × exposition {e} = {likelihood:.4f}")

    if enr.cvss_score is None:
        return CVERisk(enr.cve_id, None, likelihood, None, e, c, enr.in_kev, False,
                       expl + ["impact indéterminé (CVSS absent) — à coter par le consultant"])
    impact = (enr.cvss_score / 10.0) * c
    expl.append(f"impact : CVSS {enr.cvss_score}/10 × criticité {c} = {impact:.4f}")

    risk = likelihood * impact
    expl.append(f"risque = {likelihood:.4f} × {impact:.4f} = {risk:.4f}")
    return CVERisk(enr.cve_id, risk, likelihood, impact, e, c, enr.in_kev, True, expl)


def asset_risk(asset_name, enrichments, exposure="MEDIUM", criticality="MEDIUM",
               kev_floor=KEV_FLOOR) -> AssetRisk:
    def pick(val, cve_id):
        return val.get(cve_id, "MEDIUM") if isinstance(val, dict) else val

    risks = [cve_risk(enr, exposure=pick(exposure, enr.cve_id),
                      criticality=pick(criticality, enr.cve_id), kev_floor=kev_floor)
             for enr in enrichments]

    determined = [r for r in risks if r.determined]
    comp = 1.0
    for r in determined:
        comp *= (1.0 - r.risk)
    agg = (1.0 - comp) if determined else None

    return AssetRisk(asset_name, agg, risks, len(determined), len(risks) - len(determined))