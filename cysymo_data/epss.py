"""Connecteur EPSS (FIRST).

Donne, pour chaque CVE, la probabilité empirique d'exploitation à 30 jours.
C'est la source du `p` du moteur — il n'est plus estimé, il est récupéré.

Note : EPSS ne connaît que les CVE *publiées*. Une CVE absente de la réponse
n'est pas "proba zéro" : elle est "non couverte". On ne fabrique jamais un 0.
"""

import requests
from datetime import datetime, timezone

from .model import EpssResult

EPSS_BASE = "https://api.first.org/data/v1/epss"


def _chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


class EpssClient:
    def __init__(self, session=None, base_url=EPSS_BASE, timeout=20, batch_size=100):
        self.session = session or requests.Session()
        self.base_url = base_url
        self.timeout = timeout
        self.batch_size = batch_size

    def fetch(self, cve_ids):
        """{cve_id: EpssResult} pour les CVE connues d'EPSS. Les absentes sont omises."""
        ids = list(dict.fromkeys(cve_ids))  # dédoublonne en gardant l'ordre
        out = {}
        for chunk in _chunks(ids, self.batch_size):
            resp = self.session.get(
                self.base_url,
                params={"cve": ",".join(chunk)},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            payload = resp.json()
            fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            for row in payload.get("data", []):
                out[row["cve"]] = EpssResult(
                    cve_id=row["cve"],
                    epss=float(row["epss"]),
                    percentile=float(row["percentile"]),
                    as_of=row.get("date"),
                    retrieved_at=fetched_at,
                )
        return out
