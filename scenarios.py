"""Chaînage en scénarios d'attaque — couche IA ("l'IA relie").

L'IA relie les CVE validées en chemins d'attaque (logique EBIOS). Elle n'utilise
QUE les CVE présentes dans l'analyse, n'en invente aucune, ne produit aucun chiffre.
"""

import json
import os
from anthropic import Anthropic

MODEL = "claude-sonnet-4-6"

SYSTEM = """You are a cybersecurity consultant building operational attack
scenarios (EBIOS-style) from a validated risk analysis.

You receive assets (with exposure, criticality, context) and findings (CVEs with
CVSS, EPSS, KEV status). Chain them into 1 to 3 realistic attack scenarios: how a
threat actor would gain entry and progress toward high-value assets.

Each scenario is an object:
- title: short French title
- entry_point: name of the asset used for initial access
- steps: ordered list of {asset, cve, action} where:
    - asset: an asset name FROM THE DATA
    - cve: a CVE id FROM THE DATA, or null for a movement/pivot step
    - action: short French description of the step
- rationale: short French justification grounded in exposure / criticality / KEV / EPSS

STRICT rules:
- Use ONLY assets and CVEs present in the provided data. NEVER invent a CVE or asset.
- Entry points should be Internet-exposed assets (exposure HIGH); targets should be
  high-criticality assets.
- Prefer chains starting from actively-exploited (KEV) or high-EPSS vulnerabilities.
- Do NOT output risk numbers; the engine owns those.
- Respond ONLY with valid JSON: a list of scenario objects. No text around it."""


def _clean(raw):
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lstrip().startswith("json"):
            raw = raw.lstrip()[4:]
    return raw.strip()


def build_scenarios(analysis, api_key=None, model=MODEL):
    """analysis : dict {client, assets, findings} -> liste de scénarios (dicts)."""
    client = Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))
    payload = json.dumps(analysis, ensure_ascii=False, indent=2)
    msg = client.messages.create(
        model=model, max_tokens=2000, system=SYSTEM,
        messages=[{"role": "user", "content": "Analyse validée :\n\n" + payload}],
    )
    return json.loads(_clean("".join(b.text for b in msg.content if b.type == "text")))

def verify_scenarios(scenarios, analysis):
    """Garde-fou : vérifie que chaque CVE citée existe dans l'analyse.

    Marque chaque étape (verified True/False, ou None pour un pivot sans CVE)
    et renvoie la liste des CVE hallucinées. L'IA propose, le CODE contrôle.
    """
    valid = {f["cve_id"] for f in analysis.get("findings", [])}
    issues = []
    for s in scenarios:
        for st in s.get("steps", []):
            cve = st.get("cve")
            if not cve:
                st["verified"] = None                 # étape de pivot, pas de CVE
            elif cve in valid:
                st["verified"] = True
            else:
                st["verified"] = False                # CVE absente -> hallucination
                st["flag"] = "CVE absente de l'analyse"
                issues.append({"scenario": s.get("title", "?"), "cve": cve})
    return scenarios, issues