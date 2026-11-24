"""Compréhension du contexte — couche IA ("l'IA comprend et questionne").

À partir de tout le contexte collecté (description + documents), l'IA produit :
  - une SYNTHÈSE de ce qu'elle a compris du système,
  - les ACTIFS identifiés (comme l'extracteur),
  - les QUESTIONS / infos manquantes pour fiabiliser l'analyse.

C'est le "l'IA propose", enrichi : elle montre sa compréhension et dialogue,
au lieu de sauter directement aux actifs. Elle n'invente aucun chiffre de risque.
"""

import json
import os
from anthropic import Anthropic

MODEL = "claude-sonnet-4-6"

SYSTEM = """You assist a cybersecurity consultant during the context-gathering phase.
You receive everything the consultant collected about a client's system: a free-text
description and/or the text of documents (each source is labelled).

Produce a JSON object with exactly three fields:

- "summary": a short synthesis IN FRENCH of the system as you understand it
  (infrastructure, exposure, business context). 3 to 6 sentences. This lets the
  consultant check you understood correctly.

- "assets": a list of structured assets. Each: {name (FR), product (EN, normalized
  vendor+product as in vulnerability databases), exposure ("LOW"|"MEDIUM"|"HIGH"),
  criticality ("LOW"|"MEDIUM"|"HIGH"), context (FR)}. exposure and criticality are
  PROPOSALS to be validated.

- "questions": a list of short questions IN FRENCH about missing information that
  would improve the analysis (e.g. product versions, network segmentation, presence
  of a WAF, data sensitivity). Empty list if nothing important is missing.

STRICT rules:
- Never invent an asset, a product, a version, a CVE or any risk figure.
- Base everything ONLY on the provided context.
- Respond ONLY with valid JSON. No text around it."""


def _clean(raw):
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lstrip().startswith("json"):
            raw = raw.lstrip()[4:]
    return raw.strip()


def understand_context(context, api_key=None, model=MODEL):
    """context : tout le texte collecté -> {summary, assets, questions}."""
    client = Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))
    msg = client.messages.create(
        model=model, max_tokens=2000, system=SYSTEM,
        messages=[{"role": "user", "content": "Contexte collecté :\n\n" + context}],
    )
    data = json.loads(_clean("".join(b.text for b in msg.content if b.type == "text")))
    data.setdefault("summary", "")
    data.setdefault("assets", [])
    data.setdefault("questions", [])
    return data
