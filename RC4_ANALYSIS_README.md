# RC4 / TLS Hygiene Index — Analysis Guide

This document explains how to run the RC4 analysis scripts that form the
dissertation contribution on TLS hygiene in Irish mail server infrastructure.

---

## Prerequisites

You need the following already on disk (no new scans are run):

| Path | What it is |
|---|---|
| `results/<CC>-<timestamp>/records.fresh` | Raw scan results from FreshGrab |
| `results/<CC>-<timestamp>/cluster*.json` | Key-reuse cluster files from ReportReuse |
| `mmdb/GeoLite2-ASN.mmdb` | MaxMind ASN database for provider attribution |
| `venv/` | Python virtual environment with dependencies |

Install dependencies if the venv does not exist yet:

```bash
python3 -m venv venv
source venv/bin/activate
pip install numpy scipy scikit-learn matplotlib geoip2
```

---

## Running everything at once (recommended)

```bash
source venv/bin/activate
bash run_rc4_analysis.sh
```

The script **auto-detects the most recent `results/*/` folder** so you do not
need to hardcode the country code or timestamp. If you want to target a
specific scan, pass it as an argument:

```bash
bash run_rc4_analysis.sh results/IE-20260317-171424
```

This runs all three steps in order and takes roughly 5–10 minutes.
Outputs are written to `rc4/` and `rc4_hygiene_charts/`.

---

## Scripts

### `rc4_analysis.py` — Step 1: RC4 extraction

Reads `records.fresh` and identifies every host still negotiating an RC4
cipher suite. Produces `rc4/rc4_analysis.json`, which all later scripts
depend on.

```bash
python3 rc4_analysis.py \
    -i results/IE-20260317-171424/records.fresh \
    -o rc4/rc4_analysis.json
```

**Output:** `rc4/rc4_analysis.json`

---

### `rc4_hygiene_pipeline.py` — Step 2: TLS Hygiene Index computation

Runs four analysis stages in sequence, passing results in memory between them.
Auto-detects the results directory if `--results` is not given.

| Stage | What it does | Output directory |
|---|---|---|
| 1 — Hygiene Index | Per-host 0–6 score across 6 TLS indicators; Mann-Whitney U validation | `rc4/hygiene/` |
| 2 — Software hygiene | SMTP banner classification; hygiene by software and deployment model | `rc4/software_hygiene/` |
| 3 — Advanced methods | Logistic regression weighting; k-means ASN typology | `rc4/hygiene_advanced/` |
| 4 — Anomaly report | Prioritised RC4 cluster outreach list (JSON + Markdown) | `rc4/anomaly_report/` |

The six TLS Hygiene Index indicators are:

- `rc4` — RC4 cipher suite negotiated
- `legacy_tls` — SSLv3 / TLSv1.0 / TLSv1.1 in use
- `expired_cert` — certificate expired at scan time
- `self_signed` — certificate is self-signed
- `no_fwd_secrecy` — cipher suite is not (EC)DHE
- `untrusted_chain` — certificate chain not browser-trusted

```bash
# Auto-detect results dir
python3 rc4_hygiene_pipeline.py

# Or specify explicitly
python3 rc4_hygiene_pipeline.py --results results/IE-20260317-171424
```

For a quick test on a subset of hosts (completes in seconds):

```bash
python3 rc4_hygiene_pipeline.py --limit 5000
```

**Outputs:**
```
rc4/hygiene/hygiene_summary.json
rc4/hygiene/host_scores.json
rc4/hygiene/cluster_hygiene.json
rc4/software_hygiene/software_hygiene_summary.json
rc4/hygiene_advanced/hygiene_advanced.json
rc4/anomaly_report/rc4_anomaly_report.json
rc4/anomaly_report/rc4_anomaly_report.md
```

---

### `rc4_figures.py` — Step 3: Figure generation

Reads all JSON outputs from Step 2 and produces 12 publication-ready figures.
Must be run after `rc4_hygiene_pipeline.py`. Auto-detects the results directory.

```bash
# Auto-detect
python3 rc4_figures.py

# Or specify explicitly
python3 rc4_figures.py --results results/IE-20260317-171424
```

| Figure | Description |
|---|---|
| `fig1_score_distribution.png` | Population TLS Hygiene Index score distribution |
| `fig2_rc4_vs_population.png` | RC4 vs non-RC4 score comparison (index validation) |
| `fig3_indicator_prevalence.png` | Prevalence of each indicator across all hosts |
| `fig4_asn_ranking.png` | Best and worst ASN/providers by mean hygiene score |
| `fig5_cluster_hygiene.png` | Key-reuse cluster hygiene vs cluster size |
| `fig6_software_hygiene.png` | Mean hygiene score by mail server software |
| `fig7_deployment_hygiene.png` | Hygiene by deployment model (cloud vs self-hosted) |
| `fig8_exim_eol_hygiene.png` | Exim EOL vs supported version hygiene |
| `fig9_logistic_weighting.png` | Data-driven indicator weighting (logistic regression) |
| `fig10_asn_typology_heatmap.png` | ASN typology via k-means clustering |
| `fig11_rc4_by_provider.png` | RC4 hosts by provider (clustered vs isolated) |
| `fig12_cluster43_deepdive.png` | Cross-ASN RC4 outlier cluster cipher deep-dive |

**Output directory:** `rc4_hygiene_charts/`

---

## Output structure

```
rc4/
  rc4_analysis.json               <- RC4 host list (step 1)
  hygiene/
    hygiene_summary.json          <- score distribution, flag rates, Mann-Whitney U
    host_scores.json              <- per-host score + flags
    cluster_hygiene.json          <- per key-reuse cluster hygiene summary
  software_hygiene/
    software_hygiene_summary.json <- hygiene by software and deployment model
  hygiene_advanced/
    hygiene_advanced.json         <- logistic regression weights + ASN typology
  anomaly_report/
    rc4_anomaly_report.json       <- prioritised RC4 cluster list
    rc4_anomaly_report.md         <- human-readable outreach report

rc4_hygiene_charts/
  fig1_score_distribution.png
  fig2_rc4_vs_population.png
  ... (12 figures total)
```

---

## Key finding

RC4 hosts score significantly higher on all other TLS neglect indicators
(expired certs, legacy TLS, self-signed certs, no forward secrecy) than
the non-RC4 population — confirmed by Mann-Whitney U test (p ≈ 1.9×10⁻⁷⁸).
This validates RC4 as a reliable marker for broader infrastructure neglect,
not just an isolated cipher misconfiguration.
