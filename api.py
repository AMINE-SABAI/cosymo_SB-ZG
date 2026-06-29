"""API HTTP de CySyMo.

Expose le noyau d'analyse (mission -> risque priorisé) en endpoint web.
Lancer :  uvicorn api:app --reload
Doc interactive :  http://127.0.0.1:8000/docs
"""

import os
from dotenv import load_dotenv
from fastapi import FastAPI
from pydantic import BaseModel

from cysymo_data import NvdClient, EpssClient, KevCatalog
from mission import Asset, run_mission

load_dotenv()

app = FastAPI(title="CySyMo API", version="0.1")

# clients partagés, chargés une seule fois au démarrage
nvd = NvdClient(api_key=os.getenv("NVD_API_KEY"), timeout=90)
epss = EpssClient()
kev = KevCatalog().load()


class AssetIn(BaseModel):
    name: str
    product: str
    exposure: str = "MEDIUM"
    criticality: str = "MEDIUM"
    context: str = ""


class MissionIn(BaseModel):
    client: str
    assets: list[AssetIn]
    max_recent: int = 15


@app.get("/")
def health():
    return {"status": "ok", "kev_count": len(kev), "kev_version": kev.catalog_version}


@app.post("/assess")
def assess(payload: MissionIn):
    assets = [Asset(a.name, a.product, a.exposure, a.criticality, a.context)
              for a in payload.assets]
    res = run_mission(payload.client, assets, nvd, epss, kev, max_recent=payload.max_recent)
    return {
        "client": res.client,
        "assets": [
            {"name": ar.asset, "risk": ar.risk,
             "determined": ar.determined_count, "undetermined": ar.undetermined_count,
             "product": a.product, "exposure": a.exposure, "criticality": a.criticality}
            for a, ar in res.asset_risks
        ],
        "findings": [
            {"asset": f.asset, "cve_id": f.cve_id, "risk": round(f.risk, 4),
             "cvss": f.cvss_score, "epss": f.epss, "in_kev": f.in_kev}
            for f in res.findings
        ],
    }