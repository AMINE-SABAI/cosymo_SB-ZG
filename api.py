"""API CySyMo — expose tout le flux de l'agent + sert l'interface.

Backend sans état : le navigateur porte la mémoire (l'AgentState) et appelle
chaque phase. Lancer :  uvicorn api:app --reload   ->  http://127.0.0.1:8000
"""

import os
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel

from cysymo_data import NvdClient, EpssClient, KevCatalog
from mission import Asset, run_mission
from extractor import extract_assets
from filereader import read_document
from scanreader import parse_nmap_xml
from understand import understand_context
from orgrisks import analyze_org_risks
from threatmodel import build_threat_model, verify_threats
from pdfreport import build_pdf
from scenarios import build_scenarios, verify_scenarios
from report import generate_report

load_dotenv()

app = FastAPI(title="CySyMo", version="1.0")

NVD_KEY = os.getenv("NVD_API_KEY")
ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY")
nvd = NvdClient(api_key=NVD_KEY, timeout=60)
epss = EpssClient()
kev = KevCatalog().load()


class ExtractIn(BaseModel):
    text: str

class ContextIn(BaseModel):
    text: str

class AssetIn(BaseModel):
    name: str
    product: str
    exposure: str = "MEDIUM"
    criticality: str = "MEDIUM"
    context: str = ""
    version: str = ""

class AssessIn(BaseModel):
    client: str = "Client"
    assets: list[AssetIn]
    max_recent: int = 10

class AnalysisIn(BaseModel):
    client: str
    assets: list[dict]
    findings: list[dict]
    context: str = ""

class PdfReportIn(BaseModel):
    client: str = ""
    date: str = ""
    consultant: str = ""
    reference: str = ""
    summary: str = ""
    findings: list[dict] = []
    orgrisks: list[dict] = []
    threats: list[dict] = []
    scenarios: list[dict] = []

class ReportIn(BaseModel):
    client: str
    assets: list[dict]
    findings: list[dict]
    scenarios: list[dict] = []
    date: str = ""
    consultant: str = ""
    reference: str = ""


@app.get("/")
def index():
    return FileResponse("static/index.html")

@app.get("/health")
def health():
    return {"status": "ok", "kev_count": len(kev), "kev_version": kev.catalog_version}

@app.post("/extract")
def extract(p: ExtractIn):
    try:
        return {"assets": extract_assets(p.text, api_key=ANTHROPIC_KEY)}
    except Exception as e:
        return {"assets": [], "error": str(e)}

@app.post("/assess")
def assess(p: AssessIn):
    assets = [Asset(a.name, a.product, a.exposure, a.criticality, a.context, a.version) for a in p.assets]
    res = run_mission(p.client, assets, nvd, epss, kev, max_recent=p.max_recent)
    return {
        "client": res.client,
        "assets": [{"name": ar.asset, "risk": ar.risk, "product": a.product,
                    "exposure": a.exposure, "criticality": a.criticality, "context": a.context,
                    "determined": ar.determined_count, "undetermined": ar.undetermined_count}
                   for a, ar in res.asset_risks],
        "findings": [{"asset": f.asset, "cve_id": f.cve_id, "risk": round(f.risk, 4),
                      "cvss": f.cvss_score, "epss": f.epss, "in_kev": f.in_kev,
                      "description": f.description, "cvss_severity": f.cvss_severity,
                      "product": f.product, "version": f.version}
                     for f in res.findings],
    }

@app.post("/scenarios")
def scenarios(p: AnalysisIn):
    try:
        analysis = {"client": p.client, "assets": p.assets, "findings": p.findings}
        scs = build_scenarios(analysis, api_key=ANTHROPIC_KEY)
        scs, issues = verify_scenarios(scs, analysis)
        return {"scenarios": scs, "issues": issues}
    except Exception as e:
        return {"scenarios": [], "issues": [], "error": str(e)}

@app.post("/report")
def report(p: ReportIn):
    try:
        analysis = {"client": p.client, "assets": p.assets,
                    "findings": p.findings, "scenarios": p.scenarios}
        for k in ("date", "consultant", "reference"):
            v = getattr(p, k)
            if v:
                analysis[k] = v
        return {"report": generate_report(analysis, api_key=ANTHROPIC_KEY)}
    except Exception as e:
        return {"report": "", "error": str(e)}


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    """Reçoit un document (PDF/DOCX/TXT) et renvoie son texte."""
    try:
        data = await file.read()
        return {"text": read_document(file.filename, data)}
    except Exception as e:
        return {"text": "", "error": str(e)}


@app.post("/understand")
def understand(p: ContextIn):
    """Contexte collecté -> synthèse + actifs proposés + questions."""
    try:
        return understand_context(p.text, api_key=ANTHROPIC_KEY)
    except Exception as e:
        return {"summary": "", "assets": [], "questions": [], "error": str(e)}


@app.post("/orgrisks")
def orgrisks(p: ContextIn):
    """Contexte collecté -> risques non-techniques (organisation, accès, processus)."""
    try:
        return {"risks": analyze_org_risks(p.text, api_key=ANTHROPIC_KEY)}
    except Exception as e:
        return {"risks": [], "error": str(e)}


@app.post("/threatmodel")
def threatmodel(p: AnalysisIn):
    """Actifs + contexte -> cartographie STRIDE (frontieres + menaces par actif)."""
    try:
        analysis = {"client": p.client, "assets": p.assets, "findings": p.findings}
        if p.context:
            analysis["context"] = p.context
        data = build_threat_model(analysis, api_key=ANTHROPIC_KEY)
        data, issues = verify_threats(data, analysis)
        data["issues"] = issues
        return data
    except Exception as e:
        return {"boundaries": [], "threats": [], "issues": [], "error": str(e)}


@app.post("/report/pdf")
def report_pdf(p: PdfReportIn):
    """Assemble le rapport consolide (technique + org + STRIDE + scenarios) en PDF."""
    import tempfile, os
    fd, path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    build_pdf(p.model_dump(), path)
    with open(path, "rb") as f:
        pdf_bytes = f.read()
    os.remove(path)
    fname = "rapport_cysymo_" + (p.client or "client").replace(" ", "_") + ".pdf"
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": "attachment; filename=" + fname})


@app.post("/upload/scan")
async def upload_scan(file: UploadFile = File(...)):
    """Reçoit un scan Nmap XML et renvoie des actifs pré-remplis (produit + version exacte)."""
    try:
        data = await file.read()
        assets = parse_nmap_xml(data)
        return {"assets": assets, "count": len(assets)}
    except Exception as e:
        return {"assets": [], "count": 0, "error": str(e)}
