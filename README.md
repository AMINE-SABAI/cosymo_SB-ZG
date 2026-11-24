# CySyMo — AI agent for cyber risk assessment (consulting version)

CySyMo helps a cybersecurity consultant run a **full risk assessment** of a client's system: from the documents and scans the consultant collects, to a **prioritised PDF report**, built on **real, sourced vulnerability data**.

The agent does not guess risk. It finds the actual vulnerabilities of each product in public databases, scores them with a deterministic engine, and uses an LLM only where judgment on text is needed: understanding the context, spotting organisational risks, mapping threats, chaining attack scenarios and writing the summary.

> **Principle: the AI proposes, the human validates, the code computes and checks.**
> The LLM never invents a CVE, a version or a risk number.

---

## The consultant's journey (7 steps)

```
1. CONTEXT        free-text description  +  documents (PDF, Word, TXT)  +  Nmap XML scan
                  scan parsed with zero AI: exact product versions, open ports

2. UNDERSTANDING  Claude summarises the system and asks the questions still missing
                                                                     ── human answers
3. ASSETS         Claude proposes assets (product, version, exposure, criticality)
                                                                     ── human validates
4. ANALYSIS       known vulnerabilities:  product → CPE (NVD) → CVEs + CVSS (NVD)
                                          → exploitation probability (FIRST EPSS)
                                          → actively exploited? (CISA KEV)
                                          → deterministic risk score, no AI
                  organisational risks:   Claude finds governance, access, process and
                                          configuration weaknesses that no CVE database lists
                                                                     ── human validates
5. THREATS        STRIDE threat model per asset; code checks every threat targets a real
                  asset and a valid STRIDE category                  ── human validates
6. SCENARIOS      Claude chains validated findings into attack paths; code flags any
                  CVE that is not in the analysis                     ── human validates
7. REPORT         consolidated PDF of everything validated, assembled with zero AI;
                  only the executive summary is written by Claude
```

The backend is **stateless**: the browser holds the mission state and calls one endpoint per step.

---

## Three layers of risk

| Layer | What it covers | Source |
|---|---|---|
| Known-known | documented vulnerabilities (CVE) | NVD, FIRST EPSS, CISA KEV |
| Unknown-known | client-specific weaknesses (access, governance, processes) | AI reading of the client's context, validated by the consultant |
| Threat landscape | STRIDE threats and attack scenarios | AI proposal, checked by code, validated by the consultant |

---

## Risk model (known vulnerabilities)

```
Risk       = Likelihood × Impact            (aligned with NIST 800-30, ISO 27005, FAIR)
Likelihood = exposure × p                   p = EPSS, raised to 0.95 if the CVE is in CISA KEV
Impact     = (CVSS / 10) × business criticality
Asset risk = 1 − Π(1 − risk_i)
```

Exposure and criticality: LOW = 0.3, MEDIUM = 0.6, HIGH = 1.0. Each score comes with a line-by-line explanation.

---

## Trust by design

- **Every number has a source**: provenance (source, reference date, retrieval time) is stored for each metric.
- **Missing data is never invented**: a CVE without EPSS or CVSS is marked "undetermined — to be rated by the consultant".
- **Exact versions when available**: a version from an Nmap scan targets that version's CVEs, with automatic fallback to the whole product.
- **Code checks the LLM**: invented CVEs in scenarios and threats on non-existent assets are flagged.
- **Robust data access**: NVD rate limits respected, retries on network errors, KEV catalog cached 24 h, known-product hints for CPE resolution.

---

## Project structure

| Path | Role |
|---|---|
| `api.py` | FastAPI backend: one endpoint per step, serves the interface |
| `static/index.html` | Web interface (consultant journey) |
| `filereader.py`, `scanreader.py` | Read PDF / Word / TXT documents; parse Nmap XML scans |
| `understand.py` | AI: context summary and missing questions |
| `extractor.py` | AI: assets proposal |
| `cysymo_data/` | NVD, FIRST EPSS and CISA KEV clients, sourced enrichment |
| `cysymo_engine.py`, `mission.py` | Deterministic risk engine, prioritised findings |
| `orgrisks.py` | AI: organisational and governance risks |
| `threatmodel.py` | AI: STRIDE threat model + verification |
| `scenarios.py` | AI: attack scenarios + verification |
| `report.py`, `pdfreport.py` | AI summary; deterministic PDF assembly |
| `agent.py` | Python orchestrator of the core flow with human checkpoints |
| `tests/` | Offline tests (mocked data sources) |

---

## Run it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

`.env`:
```
ANTHROPIC_API_KEY=...
NVD_API_KEY=...        # optional, much faster NVD queries
```

```bash
uvicorn api:app --reload
# open http://127.0.0.1:8000
```

Tests: `PYTHONPATH=. python tests/test_enrich.py`
Deployed on Google Cloud Run (Docker).

## Stack

Python · Claude API (Anthropic) · FastAPI · NVD, FIRST EPSS, CISA KEV · Nmap XML · ReportLab · Docker · Google Cloud Run · HTML/JS

---
Built by Amine Sabai and Akram (2026).
