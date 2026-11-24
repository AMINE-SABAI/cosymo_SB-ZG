"""Lecteur de scan Nmap XML — donnee STRUCTUREE, parsee directement (zero IA, zero token).

Contrairement a filereader.py (qui sort du texte flou -> IA), ce lecteur extrait
directement des actifs propres : produit, VERSION EXACTE, port, adresse. Les faits
viennent du scan, pas d'une supposition. L'IA n'intervient pas -> aucune hallucination.

L'exposition est DEDUITE (un port ouvert = joignable), mais reste une PROPOSITION :
le consultant valide, et ajoute la criticite metier (que le scan ne connait pas).
"""

import xml.etree.ElementTree as ET

# Ports courants -> plutot exposes sur Internet (heuristique, a valider par l'humain)
PUBLIC_PORTS = {80, 443, 21, 22, 25, 53, 3389, 8080, 8443}


def _product_name(svc):
    """Reconstruit un nom de produit exploitable pour la recherche NVD."""
    if svc is None:
        return ""
    product = (svc.get("product") or "").strip()
    name = (svc.get("name") or "").strip()
    return product or name  # 'Apache httpd' si dispo, sinon 'http'


def _exposure(portid):
    try:
        return "HIGH" if int(portid) in PUBLIC_PORTS else "MEDIUM"
    except (TypeError, ValueError):
        return "MEDIUM"


def parse_nmap_xml(data):
    """data : bytes ou str du XML Nmap -> liste d'actifs pre-remplis.

    Chaque actif : {name, product, version, exposure, criticality, context, _source}
    - product : pour la recherche NVD
    - version : le gain de precision ('2.4.52')
    - criticality : MEDIUM par defaut (le scan ne connait pas le metier)
    """
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    root = ET.fromstring(data)
    assets = []
    for host in root.findall("host"):
        # etat de l'hote
        status = host.find("status")
        if status is not None and status.get("state") == "down":
            continue
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "hote"
        # nom d'hote si dispo
        hostname = None
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")
        label = hostname or addr

        ports = host.find("ports")
        if ports is None:
            continue
        for p in ports.findall("port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = p.get("portid")
            svc = p.find("service")
            product = _product_name(svc)
            version = (svc.get("version") if svc is not None else "") or ""
            svc_name = (svc.get("name") if svc is not None else "") or "service"

            # nom lisible de l'actif
            name = f"{svc_name} sur {label}:{portid}"
            ctx_bits = [f"Detecte par scan sur {label}, port {portid}"]
            if product:
                ctx_bits.append(f"produit : {product}")
            if version:
                ctx_bits.append(f"version : {version}")
            assets.append({
                "name": name,
                "product": product,
                "version": version,
                "exposure": _exposure(portid),
                "criticality": "MEDIUM",
                "context": " — ".join(ctx_bits),
                "_source": "scan",
            })
    return assets
