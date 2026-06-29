"""Agent CySyMo — l'orchestrateur.

La MÉMOIRE de l'agent est l'objet AgentState : il accumule tout au fil de la
mission. Le flux a des POINTS D'ARRÊT HUMAINS explicites :

  ingest()         -> l'IA propose des actifs        [l'humain valide]
  set_assets()     -> le moteur calcule les findings [l'humain valide]
  set_validated()  -> l'IA propose des scénarios     [l'humain valide]
  finalize()       -> l'IA rédige le rapport
"""

import os
from dataclasses import dataclass, field

from extractor import extract_assets
from mission import Asset, run_mission
from scenarios import build_scenarios, verify_scenarios
from report import generate_report


@dataclass
class AgentState:
    client: str = ""
    source: str = "text"
    raw_input: str = ""
    proposed_assets: list = field(default_factory=list)
    assets: list = field(default_factory=list)
    analysis: dict = field(default_factory=dict)
    scenarios: list = field(default_factory=list)
    scenario_issues: list = field(default_factory=list)
    report: str = ""
    step: str = "init"


class CysymoAgent:
    def __init__(self, nvd, epss, kev, api_key=None):
        self.nvd, self.epss, self.kev = nvd, epss, kev
        self.api_key = api_key
        self.state = AgentState()

    def ingest(self, raw_input, client="Client", source="text"):
        if source == "file":
            with open(raw_input, encoding="utf-8") as f:
                text = f.read()
        else:
            text = raw_input
        self.state.client = client
        self.state.source = source
        self.state.raw_input = text
        self.state.proposed_assets = extract_assets(text, api_key=self.api_key)
        self.state.step = "assets_proposed"
        return self.state.proposed_assets

    def set_assets(self, assets_dicts):
        self.state.assets = [Asset(a["name"], a["product"],
                                   a.get("exposure", "MEDIUM"),
                                   a.get("criticality", "MEDIUM"),
                                   a.get("context", "")) for a in assets_dicts]
        res = run_mission(self.state.client, self.state.assets,
                          self.nvd, self.epss, self.kev, max_recent=10)
        self.state.analysis = {
            "client": res.client,
            "assets": [{"name": ar.asset, "risk": ar.risk, "product": a.product,
                        "exposure": a.exposure, "criticality": a.criticality,
                        "context": a.context} for a, ar in res.asset_risks],
            "findings": [{"asset": f.asset, "cve_id": f.cve_id, "cvss": f.cvss_score,
                          "epss": f.epss, "in_kev": f.in_kev} for f in res.findings[:10]],
        }
        self.state.step = "findings_proposed"
        return self.state.analysis

    def set_validated_findings(self, kept_cve_ids):
        self.state.analysis["findings"] = [
            f for f in self.state.analysis["findings"] if f["cve_id"] in kept_cve_ids
        ]
        scs = build_scenarios(self.state.analysis, api_key=self.api_key)
        scs, issues = verify_scenarios(scs, self.state.analysis)
        self.state.scenarios = scs
        self.state.scenario_issues = issues
        self.state.step = "scenarios_proposed"
        return scs, issues

    def finalize(self, extra=None):
        payload = dict(self.state.analysis)
        payload["scenarios"] = self.state.scenarios
        if extra:
            payload.update(extra)
        self.state.report = generate_report(payload, api_key=self.api_key)
        self.state.step = "done"
        return self.state.report