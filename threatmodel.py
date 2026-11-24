"""Threat modeling STRIDE — couche IA ("cartographie systématique des menaces").

Pour chaque actif, l'IA passe en revue les 6 categories STRIDE et propose les
menaces pertinentes DANS LE CONTEXTE de ce systeme. C'est une cartographie
exhaustive (large), qui precede et nourrit les scenarios (narratifs, cibles).

STRIDE :
  S - Spoofing (usurpation d'identite)
  T - Tampering (alteration de donnees)
  R - Repudiation (deni d'action)
  I - Information disclosure (divulgation)
  D - Denial of service (deni de service)
  E - Elevation of privilege (elevation de privileges)

Discipline : l'IA PROPOSE, l'humain VALIDE. Elle raisonne a partir du contexte
et des actifs fournis, sans inventer de composant absent.
"""

import json
import os
import re
from anthropic import Anthropic

MODEL = "claude-sonnet-4-6"

STRIDE = {
    "S": "Spoofing (usurpation d'identite)",
    "T": "Tampering (alteration de donnees)",
    "R": "Repudiation (deni d'action)",
    "I": "Information disclosure (divulgation d'information)",
    "D": "Denial of service (deni de service)",
    "E": "Elevation of privilege (elevation de privileges)",
}

SYSTEM = """You are a cybersecurity consultant performing STRIDE threat modeling
(OWASP methodology) on a client's system.

You receive the system context and a list of validated assets. For EACH asset,
review the six STRIDE threat categories and identify which ones are relevant for
that asset in THIS system, with a concrete threat description.

STRIDE categories: S=Spoofing, T=Tampering, R=Repudiation, I=Information disclosure,
D=Denial of service, E=Elevation of privilege.

Produce a JSON object:
- "boundaries": a list of trust boundaries in the system IN FRENCH
  (e.g. "Frontiere Internet / DMZ", "DMZ / reseau interne"). Infer from exposure.
- "threats": a list of threat objects, each:
    - "asset": an asset name FROM THE DATA
    - "category": one of "S" | "T" | "R" | "I" | "D" | "E"
    - "threat": concrete description IN FRENCH of the threat on this asset
    - "severity": "LOW" | "MEDIUM" | "HIGH" (a proposal)
- "gaps": a list of SHORT questions IN FRENCH describing information that is
  missing to make the threat model and architecture diagram COMPLETE (e.g. network
  segmentation details, data flows between assets, presence of a firewall/WAF, which
  zone an asset really sits in). Empty list if the model is complete enough.

Rules:
- Only reference assets present in the data. Never invent an asset.
- NEVER cite CVE identifiers (e.g. "CVE-2001-0361") in threat descriptions. Describe
  the TYPE of threat in plain language (e.g. "usurpation d'identite par force brute sur
  les identifiants", "interception du canal chiffre par un attaquant en position d'homme
  du milieu"). CVE references belong only to the sourced technical analysis, never here.
  A threat description that names a CVE is WRONG.
- Cover the relevant STRIDE categories per asset (not every category applies to every asset).
- Ground each threat in the asset's exposure/criticality/context.
- Respond ONLY with valid JSON. No text around it."""


def _clean(raw):
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lstrip().startswith("json"):
            raw = raw.lstrip()[4:]
    return raw.strip()


def _salvage_json(raw):
    """Tente de lire un JSON, meme tronque par une reponse coupee.
    Recupere autant d'objets 'threats' complets que possible."""
    import re
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    # recuperation : on extrait les objets menace complets deja fermes
    threats = []
    for m in re.finditer(r'\{[^{}]*"category"[^{}]*\}', raw):
        try:
            threats.append(json.loads(m.group(0)))
        except json.JSONDecodeError:
            continue
    boundaries = []
    bm = re.search(r'"boundaries"\s*:\s*\[(.*?)\]', raw, re.DOTALL)
    if bm:
        for q in re.findall(r'"([^"]+)"', bm.group(1)):
            boundaries.append(q)
    return {"boundaries": boundaries, "threats": threats, "gaps": [],
            "_truncated": True}


_CVE = r'CVE-\d{4}-\d{3,7}'
# une parenthese qui contient au moins une CVE -> on retire toute la parenthese
_CVE_PAREN = re.compile(r'\s*\([^)]*' + _CVE + r'[^)]*\)', re.IGNORECASE)
# une mention inline (avec connecteur eventuel : via / ex. / cf. / , / ou / et)
_CVE_INLINE = re.compile(
    r'\s*(?:,\s*|;\s*|\b(?:via|cf\.?|ex\.?|voir|liee?\s+a|notamment)\s+)?'
    + _CVE + r'(?:\s*(?:,|;|ou|et)\s*' + _CVE + r')*', re.IGNORECASE)


def _strip_cves(text):
    """Retire toute reference CVE glissee dans un texte de menace (garde-fou anti-invention).
    Le threat model decrit des TYPES de menaces ; les CVE ne viennent que de l'analyse sourcee."""
    if not text:
        return text
    cleaned = _CVE_PAREN.sub("", text)          # parentheses entieres d'abord
    cleaned = _CVE_INLINE.sub("", cleaned)       # puis mentions inline
    cleaned = re.sub(r'\(\s*\)', '', cleaned)    # parentheses vides orphelines
    cleaned = re.sub(r'\s+([.,;:)])', r'\1', cleaned)
    cleaned = re.sub(r'\(\s+', '(', cleaned)
    cleaned = re.sub(r'\s{2,}', ' ', cleaned).strip()
    return cleaned


def build_threat_model(analysis, api_key=None, model=MODEL):
    """analysis : {client, assets, findings, context?} -> {boundaries, threats}."""
    client = Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))
    payload = json.dumps(analysis, ensure_ascii=False, indent=2)
    msg = client.messages.create(
        model=model, max_tokens=8192, system=SYSTEM,
        messages=[{"role": "user", "content": "Systeme a modeliser :\n\n" + payload}],
    )
    data = _salvage_json(_clean("".join(b.text for b in msg.content if b.type == "text")))
    data.setdefault("boundaries", [])
    data.setdefault("threats", [])
    data.setdefault("gaps", [])
    # garde-fou : aucune CVE ne doit subsister dans les descriptions de menaces
    for t in data["threats"]:
        if "threat" in t:
            t["threat"] = _strip_cves(t["threat"])
    return data


def verify_threats(model_data, analysis):
    """Garde-fou : chaque menace doit porter sur un actif reel et une categorie STRIDE valide."""
    valid_assets = {a["name"] for a in analysis.get("assets", [])}
    issues = []
    for t in model_data.get("threats", []):
        if t.get("asset") not in valid_assets:
            t["verified"] = False
            issues.append({"asset": t.get("asset"), "reason": "actif absent"})
        elif t.get("category") not in STRIDE:
            t["verified"] = False
            issues.append({"asset": t.get("asset"), "reason": "categorie STRIDE invalide"})
        else:
            t["verified"] = True
    return model_data, issues
