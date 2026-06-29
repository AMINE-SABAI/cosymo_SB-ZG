# Rapport d'évaluation des risques cybersécurité
**Client :** Atlas Distribution
**Classification :** Confidentiel
**Date :** 2025

---

## Synthèse exécutive

Atlas Distribution présente une posture de sécurité **globalement préoccupante**, concentrée sur un actif unique mais critique : la passerelle VPN Fortinet, directement exposée sur Internet. La base de données de paie, bien que de criticité métier élevée, bénéficie d'une exposition réseau maîtrisée qui limite significativement son niveau de risque actuel.

**Les deux risques prioritaires pour la direction sont :**

1. **Compromission imminente de la passerelle VPN Fortinet** — Une vulnérabilité activement exploitée dans la nature (référencée au catalogue CISA KEV) affecte la passerelle d'accès distant de l'entreprise. Avec un score de gravité de 9,8/10 (CVSS) et une probabilité d'exploitation de 85,8 % (EPSS), ce vecteur représente la menace la plus sérieuse et la plus probable à court terme. Une compromission réussie permettrait à un attaquant externe d'accéder au réseau interne d'Atlas Distribution sans authentification légitime, ouvrant la voie à des intrusions profondes, des ransomwares ou des exfiltrations de données.

2. **Risque de rebond vers les données de paie** — Bien que la base de données MySQL hébergeant les données de paie affiche un risque direct faible, une compromission préalable de la passerelle VPN pourrait servir de point de pivot pour atteindre des systèmes internes normalement cloisonnés. La confidentialité des données salariales des employés constitue un enjeu légal (RGPD) et social majeur.

**En l'absence d'action corrective immédiate sur la passerelle VPN, Atlas Distribution s'expose à une probabilité élevée de violation de son périmètre réseau dans un délai court.**

---

## Méthodologie

L'évaluation repose sur des sources empiriques publiques de référence :

- **NVD (National Vulnerability Database)** — scores de sévérité CVSS, reflétant l'impact technique potentiel d'une vulnérabilité (de 0 à 10).
- **FIRST EPSS (Exploit Prediction Scoring System)** — probabilité empirique qu'une vulnérabilité soit exploitée dans les 30 jours, calculée à partir de données d'exploitation observées.
- **CISA KEV (Known Exploited Vulnerabilities Catalog)** — liste officielle des vulnérabilités pour lesquelles une exploitation active dans la nature est confirmée par les autorités américaines de cybersécurité.

**Principe de gouvernance du rapport :** l'intelligence artificielle propose une structuration et une priorisation des constats ; le consultant valide les interprétations ; un moteur déterministe calcule les scores de risque composites à partir des métriques brutes. Aucune donnée n'est extrapolée ou inventée — seules les figures fournies par l'analyse validée sont citées.

---

## Analyse par actif

### 🔴 Passerelle VPN Fortinet (Fortinet FortiOS)

| Attribut | Valeur |
|---|---|
| **Niveau de risque global** | **0,5682 / 1,00 — ÉLEVÉ** |
| **Exposition réseau** | HIGH (Internet) |
| **Criticité métier** | MEDIUM |
| **Contexte** | Passerelle exposée directement sur Internet |

Cet actif concentre l'essentiel du risque de l'organisation. Son exposition directe sur Internet en fait une cible de choix pour les acteurs malveillants, et la présence d'une vulnérabilité activement exploitée le place en situation d'urgence.

#### Vulnérabilités identifiées

| CVE | CVSS | EPSS | KEV | Score de risque | Priorité |
|---|---|---|---|---|---|
| **CVE-2026-24858** | **9,8** | **85,84 %** | **✅ Oui** | **0,5586** | 🔴 CRITIQUE |
| CVE-2025-53844 | 8,8 | 0,56 % | ❌ Non | 0,0030 | 🟠 MODÉRÉ |
| CVE-2025-25249 | 8,1 | 0,75 % | ❌ Non | 0,0036 | 🟠 MODÉRÉ |
| CVE-2026-22153 | 8,1 | 0,70 % | ❌ Non | 0,0034 | 🟠 MODÉRÉ |
| CVE-2025-64157 | 6,7 | 1,37 % | ❌ Non | 0,0055 | 🟡 FAIBLE |
| CVE-2025-53847 | 6,5 | 0,28 % | ❌ Non | 0,0011 | 🟡 FAIBLE |
| CVE-2025-61624 | 6,0 | 0,50 % | ❌ Non | 0,0018 | 🟡 FAIBLE |
| CVE-2025-68686 | 5,9 | 0,48 % | ❌ Non | 0,0017 | 🟡 FAIBLE |
| CVE-2025-55018 | 5,8 | 0,35 % | ❌ Non | 0,0012 | 🟡 FAIBLE |

**Focus CVE-2026-24858 :** Cette vulnérabilité cumule tous les marqueurs de criticité maximale. Son score CVSS de **9,8/10** (source : NVD) indique un impact technique quasi-total (confidentialité, intégrité, disponibilité). Son score EPSS de **85,84 %** (source : FIRST) signifie que la probabilité d'exploitation active dans les 30 jours est extrêmement élevée. Sa présence dans le **catalogue CISA KEV** confirme que des acteurs malveillants l'exploitent déjà dans des attaques réelles. Le score de risque composite de **0,5586** représente à lui seul 98 % du risque global de cet actif.

---

### 🟢 Base de données Paie (Oracle MySQL)

| Attribut | Valeur |
|---|---|
| **Niveau de risque global** | **0,0046 / 1,00 — FAIBLE** |
| **Exposition réseau** | LOW (réseau interne) |
| **Criticité métier** | HIGH |
| **Contexte** | Base interne hébergeant les données de paie |

Malgré une criticité métier élevée (données personnelles et salariales), le risque technique direct de cet actif est contenu grâce à son exposition réseau limitée. Il convient toutefois de maintenir une vigilance sur les chemins d'accès indirects (notamment via la passerelle VPN).

#### Vulnérabilités identifiées

| CVE | CVSS | EPSS | KEV | Score de risque | Priorité |
|---|---|---|---|---|---|
| CVE-2025-50102 | 4,9 | 0,47 % | ❌ Non | 0,0007 | 🟡 FAIBLE |

**Focus CVE-2025-50102 :** Vulnérabilité de sévérité modérée (CVSS **4,9/10**, source : NVD), avec une probabilité d'exploitation de **0,47 %** (source : FIRST EPSS). Absente du catalogue CISA KEV. Son impact reste limité dans le contexte actuel d'exposition interne, mais doit être corrigée dans le cadre du cycle de patching standard.

---

## Recommandations priorisées

### 🔴 Action 1 — URGENCE IMMÉDIATE : Remédiation CVE-2026-24858 sur la passerelle VPN Fortinet

**Délai cible : 24 à 72 heures**

- **Justification :** Vulnérabilité activement exploitée dans la nature (CISA KEV), CVSS 9,8/10, EPSS 85,84 %. Risque de compromission totale de la passerelle et du réseau interne.
- **Actions :**
  - Appliquer immédiatement le correctif officiel Fortinet (patch FortiOS) dès sa disponibilité, ou appliquer les mesures de contournement publiées par l'éditeur si le correctif n'est pas encore disponible.
  - En l'absence de correctif disponible, envisager le retrait temporaire de l'exposition Internet de la passerelle et le basculement sur un accès alternatif sécurisé.
  - Auditer les journaux d'accès VPN pour détecter toute tentative ou trace d'exploitation antérieure à la remédiation.
  - Isoler la passerelle du reste du réseau interne en attendant la correction (segmentation d'urgence).

---

### 🟠 Action 2 — COURT TERME : Traitement des vulnérabilités de sévérité élevée sur FortiOS (hors KEV)

**Délai cible : 7 à 14 jours**

- **Justification :** Trois vulnérabilités affichent un CVSS ≥ 8,1 (CVE-2025-53844 à 8,8, CVE-2025-25249 et CVE-2026-22153 à 8,1). Bien que non référencées au KEV, leur sévérité et l'exposition de l'actif justifient une correction rapide.
- **Actions :**
  - Intégrer ces CVE dans le plan de patching de la passerelle lors de la mise à jour déclenchée par l'Action 1.
  - Vérifier la disponibilité des correctifs Fortinet pour chacune de ces références.

---

### 🟡 Action 3 — MOYEN TERME : Renforcement de l'architecture VPN et durcissement

**Délai cible : 30 jours**

- **Justification :** La concentration du risque sur un équipement unique exposé sur Internet constitue un risque architectural structurel, indépendamment des vulnérabilités CVE.
- **Actions :**
  - Mettre en place une authentification multifacteur (MFA) obligatoire sur la passerelle VPN.
  - Restreindre les adresses IP sources autorisées à initier des connexions VPN, si techniquement faisable.
  - Déployer une surveillance active (SIEM/SOC) des connexions VPN avec alertes sur comportements anormaux.
  - Réaliser un audit de segmentation réseau pour s'assurer que la base de données de paie est inaccessible directement depuis la zone VPN sans contrôle d'accès supplémentaire.

---

### 🟡 Action 4 — PLANIFIÉ : Patching de la base de données Paie (CVE-2025-50102)

**Délai cible : prochain cycle de maintenance (≤ 60 jours)**

- **Justification :** Vulnérabilité de sévérité modérée (CVSS 4,9), faible probabilité d'exploitation (EPSS 0,47 %), non présente au KEV. Traitement intégrable dans