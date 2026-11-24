"""Analyse des risques non-techniques — couche IA ("risques connus-inconnus").

À partir du contexte collecté (description + documents), l'IA repère les risques
d'ORGANISATION, de PROCESSUS, de GOUVERNANCE, d'ACCÈS, de CONFIGURATION — ceux
qu'aucune base publique (CVE) ne référence, parce qu'ils sont propres au client.

Discipline : contrairement aux CVE, il n'y a pas de source publique pour vérifier.
Donc l'IA PROPOSE (avec la source dans le contexte), l'humain VALIDE. L'IA ne
signale que ce qui découle du contexte fourni ; elle n'invente rien.
"""

import json
import os
from anthropic import Anthropic

MODEL = "claude-sonnet-4-6"

SYSTEM = """You assist a cybersecurity consultant. From the collected context about
a client's system (free text + documents), identify NON-TECHNICAL risks: weaknesses
of governance, process, organization, access control, configuration, or compliance.
These are NOT CVEs — they are client-specific weaknesses found by reading the context.

Examples: excessive access rights ("the finance director has admin access to the HR
database"), no network segmentation, no patch-management process, unencrypted sensitive
data, no MFA, no incident response plan, shared credentials, etc.

For each risk, produce an object:
- "category": one of "Gouvernance" | "Acces" | "Processus" | "Configuration" | "Conformite"
- "description": clear description IN FRENCH of the risk
- "severity": "LOW" | "MEDIUM" | "HIGH" — a PROPOSAL, to be validated by the human
- "source": short FRENCH note on where in the context this comes from
  (e.g. "d'apres le document notes.docx" or "mentionne dans la description")

STRICT rules:
- Only report risks that follow from the PROVIDED context. Never invent facts.
- If the context is too thin to find non-technical risks, return an empty list.
- severity is a proposal, not a computed score.
- Respond ONLY with valid JSON: a list of risk objects. No text around it."""


def _clean(raw):
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lstrip().startswith("json"):
            raw = raw.lstrip()[4:]
    return raw.strip()


def analyze_org_risks(context, api_key=None, model=MODEL):
    """context : tout le texte collecté -> liste de risques non-techniques (dicts)."""
    client = Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))
    msg = client.messages.create(
        model=model, max_tokens=2000, system=SYSTEM,
        messages=[{"role": "user", "content": "Contexte collecté :\n\n" + context}],
    )
    return json.loads(_clean("".join(b.text for b in msg.content if b.type == "text")))
