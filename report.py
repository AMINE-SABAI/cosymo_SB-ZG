"""Générateur de rapport — couche IA ("l'IA rédige").

L'IA narre à partir des données validées ; elle n'invente aucun chiffre.
Légitime car en aval de la validation humaine.
"""

import json
import os
from anthropic import Anthropic

MODEL = "claude-sonnet-4-6"

SYSTEM = """You are a senior cybersecurity consultant writing a risk assessment
report for a client, IN FRENCH.

You receive structured, already-validated analysis data (assets, vulnerabilities,
risk scores, sources). Write a professional report in French Markdown with:

1. "## Synthèse exécutive" — plain-language overview for management: overall
   posture and the 2-3 most urgent risks, in business terms.
2. "## Méthodologie" — brief: metrics come from public empirical sources
   (NVD for CVSS, FIRST EPSS for exploitation probability, CISA KEV for active
   exploitation). Principle: the AI proposes, the consultant validates, a
   deterministic engine computes.
3. "## Analyse par actif" — for each asset: its risk level, exposure, criticality,
   and the most important vulnerabilities with their figures.
4. "## Recommandations priorisées" — ordered action list, most urgent first,
   focused on actively-exploited (KEV) and high-probability vulnerabilities.

STRICT rules:
- Use ONLY the figures provided in the data. NEVER invent a number, a CVE, or a fact.
- When citing a probability, severity, or exploitation status, attribute it to its
  source (EPSS, CVSS, CISA KEV).
- Concrete and concise. Professional tone. French.
- Output Markdown only, no preamble."""


def generate_report(analysis, api_key=None, model=MODEL):
    """analysis : dict {client, assets, findings} (forme de la réponse /assess)."""
    client = Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))
    payload = json.dumps(analysis, ensure_ascii=False, indent=2)
    msg = client.messages.create(
        model=model,
        max_tokens=3000,
        system=SYSTEM,
        messages=[{"role": "user",
                   "content": "Données d'analyse validées :\n\n" + payload}],
    )
    return "".join(b.text for b in msg.content if b.type == "text")