"""Extracteur d'actifs — couche IA ("l'IA propose").

L'IA structure le langage ; elle ne calcule aucun risque, n'invente ni version
ni CVE ni chiffre. Les métriques viennent toujours des sources empiriques.
"""

import json
import os
from anthropic import Anthropic

MODEL = "claude-sonnet-4-6"   # pour réduire le coût : "claude-haiku-4-5"

SYSTEM = """Tu assistes un consultant en cybersécurité.
Tu transformes une description libre d'un système informatique en une liste
d'actifs structurés.

Pour chaque actif identifiable (logiciel, équipement réseau, serveur, base),
produis un objet avec :
- name : libellé court et clair (ex: "Passerelle VPN")
- product : nom du produit normalisé tel qu'il apparaît dans les bases de
  vulnérabilités, vendeur + produit (ex: "Fortinet FortiOS", "Apache HTTP Server", "Oracle MySQL")
- exposure : "LOW" | "MEDIUM" | "HIGH" — déduit du contexte (exposé Internet = HIGH,
  interne isolé = LOW). Si incertain : "MEDIUM".
- criticality : "LOW" | "MEDIUM" | "HIGH" — déduit de l'importance métier
  (données sensibles / paie / RH = HIGH). Si incertain : "MEDIUM".
- context : courte note métier tirée du texte (ou "").

Règles STRICTES :
- N'invente jamais un actif absent du texte.
- N'invente ni version, ni CVE, ni chiffre de risque.
- exposure et criticality sont des PROPOSITIONS à valider par l'humain.
- Réponds UNIQUEMENT par du JSON valide : une liste d'objets. Aucun texte autour."""


def _clean(raw):
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lstrip().startswith("json"):
            raw = raw.lstrip()[4:]
    return raw.strip()


def extract_assets(text, api_key=None, model=MODEL):
    """Texte libre -> liste d'actifs proposés (dicts)."""
    client = Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))
    msg = client.messages.create(
        model=model,
        max_tokens=1500,
        system=SYSTEM,
        messages=[{"role": "user", "content": text}],
    )
    raw = "".join(block.text for block in msg.content if block.type == "text")
    return json.loads(_clean(raw))