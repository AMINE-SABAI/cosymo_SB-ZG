"""Modèle de données de la Brique 0.

Principe directeur : aucune métrique ne flotte sans sa source.
Chaque chiffre porte d'où il vient (source), à quelle date il se réfère
(as_of) et quand on l'a récupéré (retrieved_at).
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EpssResult:
    """Réponse brute d'EPSS pour une CVE."""
    cve_id: str
    epss: float          # proba d'exploitation à 30 jours [0-1]
    percentile: float    # rang relatif parmi toutes les CVE [0-1]
    as_of: Optional[str] # date du score EPSS (yyyy-mm-dd)
    retrieved_at: str    # quand on l'a récupéré (ISO)


@dataclass
class KevResult:
    """Réponse brute du KEV pour une CVE."""
    cve_id: str
    in_kev: bool
    date_added: Optional[str] = None
    ransomware: Optional[bool] = None
    retrieved_at: Optional[str] = None


@dataclass
class Provenance:
    """Traçabilité d'un groupe de métriques."""
    source: str
    as_of: Optional[str]
    retrieved_at: Optional[str]


@dataclass
class CVEEnrichment:
    """Une CVE + toutes ses métriques sourcées. Sortie de la couche de données."""
    cve_id: str
    # --- sévérité (NVD / CVSS) ---
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cvss_version: Optional[str] = None
    description: Optional[str] = None
    # --- probabilité (EPSS) ---
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    # --- exploitation active (KEV) ---
    in_kev: Optional[bool] = None
    kev_date_added: Optional[str] = None
    kev_ransomware: Optional[bool] = None
    # --- traçabilité ---
    provenance: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    @property
    def epss_covered(self) -> bool:
        return self.epss is not None

@dataclass
class NvdCve:
    """Une CVE trouvée via NVD, avec son CVSS (sévérité technique)."""
    cve_id: str
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None      # LOW / MEDIUM / HIGH / CRITICAL
    cvss_vector: Optional[str] = None
    cvss_version: Optional[str] = None        # "3.1" / "3.0" / "2.0"
    published: Optional[str] = None
    description: Optional[str] = None
    retrieved_at: Optional[str] = None