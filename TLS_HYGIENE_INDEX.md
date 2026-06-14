# TLS Hygiene Index — Dissertation Contribution

This document describes the dissertation-level analytical contribution built
on top of the existing IE-20260317-171424 scan results. It is implemented
entirely as a **post-hoc analysis of existing data** — no additional scanning
was performed.

It extends the earlier RC4 anomaly case studies (`rc4_charts/17-19`,
`rc4_crossasn_anomalies.py`) from four hand-picked examples into a
**dataset-wide, statistically validated, multi-method framework** for
characterising TLS deployment neglect across the scanned population.

---

## 1. Motivation / Research Question

The earlier RC4 work found 4 anomalous key-reuse clusters where RC4 servers
co-occurred with other signs of neglect (expired certs, self-signed certs,
etc.). The natural dissertation-level question is:

> **Is RC4 usage an isolated legacy-cipher artefact, or is it a marker for a
> broader pattern of TLS configuration neglect — and if so, can that pattern
> be measured, validated, attributed (to providers/software), and
> generalised across the whole dataset?**

This is answered through four linked pieces of work, each building on the
last.

---

## 2. The TLS Hygiene Index (core methodology)

**Script:** `rc4_hygiene_index.py` → `rc4/hygiene/`
**Figures:** `rc4_hygiene_figures.py` → `rc4_hygiene_charts/fig1-5`

### What it does

Streams `results/IE-20260317-171424/records.fresh` (19,720 hosts, full
zgrab2-style TLS handshake data per port) and computes, for every host with
a usable TLS handshake on any of {p25, p110, p143, p443, p587, p993}, six
binary indicators (1 if present on **any** port for that host):

| Indicator | Definition |
|---|---|
| `rc4` | RC4 cipher suite (5 / 49169) negotiated |
| `legacy_tls` | SSLv3 / TLS 1.0 / TLS 1.1 negotiated |
| `expired_cert` | Leaf certificate expired at scan time |
| `self_signed` | Leaf certificate is self-signed |
| `no_fwd_secrecy` | Negotiated cipher is not (EC)DHE |
| `untrusted_chain` | Certificate chain not browser-trusted |

**TLS Hygiene Index = sum of indicators present (0–6)**, per host.

### Novelty

- Generalises a single ad-hoc "neglect score" (previously computed only for
  the 179 known RC4 hosts) into a **population-wide, reproducible metric**
  applied to all 8,979 TLS-bearing hosts.
- Provides the **statistical validation step** that the earlier case studies
  lacked: a Mann-Whitney U test comparing the "other neglect" score (the
  index excluding the RC4 flag itself) of RC4 hosts vs. the rest of the
  population.

### Key results

- 8,979 / 19,720 hosts (45.5%) have a usable TLS handshake.
- Indicator prevalence: untrusted chain 45.6%, self-signed 34.6%, expired
  cert 19.4%, no forward secrecy 5.4%, RC4 2.0%, legacy TLS 0.9%.
- **RC4 hosts (n=179) have a mean "other neglect" score of 3.20 (out of 5)
  vs. 1.02 for non-RC4 hosts (n=8,800)** — Mann-Whitney U, **p ≈ 1.9×10⁻⁷⁸**.
  → RC4 is overwhelmingly a *marker* for broader neglect, not an isolated
  legacy-cipher issue.
- `rc4/hygiene/cluster_hygiene.json`: large key-reuse clusters (≥5 members)
  have a higher mean hygiene score (1.03) than small clusters (0.82),
  extending the manual A1-A4 anomaly findings into a dataset-wide pattern.

---

## 3. Software / Deployment-Model Attribution ("the why")

**Script:** `rc4_software_hygiene.py` → `rc4/software_hygiene/`
**Figures:** `rc4_software_hygiene_figures.py` → `rc4_hygiene_charts/fig6-8`

### What it does

Classifies each host's mail server software from its SMTP banner (regex
matching against ~19 known MTA/security-gateway signatures: Postfix, Exim,
Microsoft Exchange / Exchange Online, Amazon SES, MailEnable, Plesk,
Sendmail, Haraka, MDaemon, IceWarp, Sophos, Cisco ESA, Barracuda, Kerio,
Axigen, Communigate, OpenSMTPD, Qmail), groups software into four
**deployment models** (Managed Cloud / Self-Hosted / Hosting Panel /
Security Gateway), and joins this with each host's TLS Hygiene Index score.

Additionally performs a targeted case study on **Exim version strings**:
hosts running Exim < 4.92 are flagged as running a version affected by
**CVE-2019-10149** ("Return of the WIZard" remote code execution).

### Novelty

- Adds a **causal/attributional dimension**: not just *what* is neglected
  and *where* (which ASN), but *why* — i.e., which software/operational
  choices are associated with neglect.
- Connects a **specific, named CVE** to the hygiene index, turning an
  abstract "score" into a concrete security-relevant claim.

### Key results

- **Deployment model is strongly predictive of hygiene**: Managed Cloud
  (Amazon SES, Exchange Online, n=781) has a mean hygiene score of **0.00**
  — perfectly clean — vs. Hosting Panel software (Plesk, MailEnable, n=360)
  at **1.81**, Self-Hosted (Postfix, Exim, Sendmail, etc., n=5,724) at
  **1.20**.
- Software-level breakdown: Sendmail (2.30) and Plesk (2.00) are worst;
  Postfix (1.46) and Exim (0.84) are mid-range; Amazon SES and Exchange
  Online are 0.00.
- **Exim EOL analysis**: hosts running Exim < 4.92 (n=49, vulnerable to
  CVE-2019-10149) have a mean hygiene score of **1.94** vs. **0.81** for
  supported versions (n=1,804) — outdated software correlates with broader
  neglect, not just the targeted CVE.

---

## 4. Data-Driven Indicator Weighting (methodological rigor)

**Script:** `rc4_hygiene_advanced.py` (part 1) → `rc4/hygiene_advanced/`
**Figures:** `rc4_hygiene_advanced_figures.py` → `rc4_hygiene_charts/fig9`

### What it does

The base Hygiene Index (Section 2) treats all 6 indicators as equally
weighted (+1 each) — a simple but methodologically naive choice. This
extension fits a **logistic regression** predicting RC4 presence from the
other 5 indicators, and uses the resulting (rescaled) coefficients as
empirically-derived weights for a "weighted hygiene score".

### Novelty

- Replaces an arbitrary scoring scheme with one **derived from the data
  itself**, addressing the main methodological weakness of a simple
  indicator-count.
- The regression coefficients are independently interesting: they quantify
  *how strongly* each indicator co-occurs with RC4, not just *whether* it
  does.

### Key results

| Indicator | Odds ratio (for RC4 presence) |
|---|---|
| No forward secrecy | **847.3** |
| Expired certificate | 12.6 |
| Self-signed certificate | 6.5 |
| Legacy TLS (≤1.1) | 1.06 (≈ no effect) |
| Untrusted cert chain | **0.13** (RC4 hosts are *less* likely to have this) |

- The weighted score widens the separation between RC4 and non-RC4 hosts
  from a **3.1× ratio** (naive equal-weight: 3.20 vs 1.02) to a **~19×
  ratio** (data-driven: 1.15 vs 0.06).
- The "untrusted chain" finding (OR=0.13) is counterintuitive and worth
  discussing: it suggests RC4 deployments tend to come from older but
  *previously well-configured* infrastructure (e.g., once had a valid CA
  chain) rather than entirely ad-hoc/self-signed setups — a distinct
  neglect pattern from the self-signed/untrusted cluster found in Section 5.

---

## 5. Unsupervised ASN Typology

**Script:** `rc4_hygiene_advanced.py` (part 2) → `rc4/hygiene_advanced/`
**Figures:** `rc4_hygiene_advanced_figures.py` → `rc4_hygiene_charts/fig10`

### What it does

Rather than manually ranking ASNs by mean hygiene score (Section 2's
"worst/best 10" approach), this computes a 6-dimensional indicator-rate
vector for every ASN with ≥10 scanned hosts and runs **k-means clustering**
(k=4) to derive an empirical typology of provider "neglect profiles".

### Novelty

- Moves from a **manually-sorted list** to an **empirically-derived
  typology** — a recognised unsupervised-learning technique applied to
  network measurement data.
- The resulting clusters are independently interpretable and largely
  *recover and generalise* the earlier hand-picked anomaly cases (A1-A4),
  which were concentrated in what k-means independently identifies as
  "Cluster 0".

### Key results (k=4, 30 ASNs with ≥10 hosts)

| Cluster | Profile | Example members |
|---|---|---|
| 0 (5 ASNs) | "Legacy Irish ISP" — only cluster with meaningful RC4 (4%) and legacy TLS (5%); moderate everything else | Blacknight, Eir Broadband, Digiweb, Cork Internet Exchange, Liberty Global |
| 1 (16 ASNs) | "Major cloud/CDN, relatively clean" — lowest rates overall | Amazon, Microsoft, WebWorld, Orion Network, Team Blue Carrier |
| 2 (8 ASNs) | "Self-signed/untrusted-heavy platforms" — 86% self-signed, 92% untrusted, 0% RC4 | Tilda Publishing (Kaz/Ltd), M247 Europe, Incapsula, WorkTitans |
| 3 (1 ASN) | Singleton outlier — 100% no-forward-secrecy + 100% untrusted chain | Adobe Inc. |

---

## 6. RC4 Anomaly / Outreach Prioritization

**Script:** `rc4_anomaly_report.py` → `rc4/anomaly_report/`
**Figures:** `rc4_anomaly_report_figures.py`, `rc4_cluster43_deepdive.py` →
`rc4_hygiene_charts/fig11-12`

### What it does

Combines the RC4 host list (`rc4/rc4_analysis.json`), the TLS Hygiene Index
(`rc4/hygiene/host_scores.json`), and the key-reuse cluster files
(`cluster*.json`) into a single prioritised report identifying *which*
clusters/providers a remediation contact should target, and *why* each
one is anomalous. Clusters containing RC4 hosts are classified as:

1. **Cross-ASN key reuse** — an RC4 host shares a TLS key with hosts in a
   *different* organisation's ASN (highest priority: suggests a stale or
   misconfigured clone on an otherwise shared/templated deployment).
2. **Mass RC4 deployment** — >50% of a key-reuse cluster runs RC4 (single
   provider, many affected hosts — one contact fixes many servers).
3. **ECDHE/RC4 paradox or port-selective RC4** — forward secrecy on some
   ports/services but RC4 on others.
4. Other/standard.

Isolated RC4 hosts (no key reuse with any other scanned host) are grouped
by ASN/provider for the same purpose.

### Novelty

- Turns the dataset-wide hygiene metric back into a **concrete, actionable
  artefact** — a ranked outreach list — closing the loop from "we can
  measure neglect at scale" to "here is exactly who to contact and why".
- Provides a **case-study deep dive** (Cluster 43) that visually
  demonstrates *how* an anomaly manifests at the cipher-negotiation level
  within a shared-key cluster, not just that it exists.

### Key results

- 179 RC4 hosts total: 80 inside 21 key-reuse clusters, 99 isolated.
- **Provider concentration**: Amazon.com, Inc. accounts for **128 of 179
  RC4 hosts (71%)** — by far the highest-impact single contact (fig11).
  Blacknight Internet Solutions accounts for 20.
- **Cluster 43** is the only Priority-1 (cross-ASN) anomaly: a 23-host
  shared-key cluster spanning Blacknight Internet Solutions and Iomart
  Cloud Services (bluemonkeyweb.co.uk). One member
  (`46.22.131.131`/`131-131.colo.sta.blacknight.ie`) is the *only* host in
  the cluster negotiating RC4 on ports 25/110/143/993 — every sibling uses
  ECDHE (forward secrecy) on the same ports despite sharing the same
  certificate/key — and it has the worst hygiene score in the cluster
  (6/6) (fig12).

The full ranked report, including per-cluster member tables, is in
`rc4/anomaly_report/rc4_anomaly_report.md`. **It is marked for internal
use ahead of supervisor consultation — no provider should be contacted
without sign-off.**

---

## 7. Summary of Novel Contributions

1. **Generalisation**: a 4-case-study, hand-picked anomaly analysis →
   dataset-wide metric applied to 8,979 hosts.
2. **Statistical validation**: Mann-Whitney U test (p ≈ 1.9×10⁻⁷⁸)
   confirming RC4 as a statistically significant marker for broader TLS
   neglect.
3. **Causal attribution**: linking neglect to mail-server software and
   deployment model (Managed Cloud vs Self-Hosted vs Hosting Panel),
   including a concrete CVE-linked case study (Exim/CVE-2019-10149).
4. **Methodological rigor**: replacing an arbitrary equal-weight scoring
   scheme with logistic-regression-derived weights, improving RC4/non-RC4
   separation 3.1× → 19×.
5. **Unsupervised typology**: k-means-derived provider typology that
   recovers and generalises the earlier manual anomaly findings.
6. **Actionable outreach prioritisation**: a ranked, evidence-backed list
   of clusters/providers for remediation, anchored by a detailed
   cipher-level case study of the single cross-ASN anomaly (Cluster 43).

All of this is reproducible from the existing scan output
(`results/IE-20260317-171424/`) via:

```bash
source venv/bin/activate
python3 rc4_hygiene_index.py
python3 rc4_hygiene_figures.py
python3 rc4_software_hygiene.py
python3 rc4_software_hygiene_figures.py
python3 rc4_hygiene_advanced.py
python3 rc4_hygiene_advanced_figures.py
python3 rc4_anomaly_report.py
python3 rc4_anomaly_report_figures.py
python3 rc4_cluster43_deepdive.py
```

---

## 8. File Map

| Path | Description |
|---|---|
| `rc4_hygiene_index.py` | Core hygiene index computation (Section 2) |
| `rc4_hygiene_figures.py` | fig1-5: distribution, RC4 validation, prevalence, ASN ranking, cluster overlay |
| `rc4_software_hygiene.py` | Software/deployment-model attribution (Section 3) |
| `rc4_software_hygiene_figures.py` | fig6-8: software hygiene, deployment model, Exim EOL |
| `rc4_hygiene_advanced.py` | Logistic regression weighting + k-means ASN typology (Sections 4-5) |
| `rc4_hygiene_advanced_figures.py` | fig9-10: weighting comparison, ASN typology heatmap |
| `rc4_anomaly_report.py` | RC4 outreach prioritisation report (Section 6) |
| `rc4_anomaly_report_figures.py` | fig11: RC4 hosts by provider |
| `rc4_cluster43_deepdive.py` | fig12: Cluster 43 cipher-level anomaly deep dive |
| `rc4/hygiene/` | JSON outputs: `hygiene_summary.json`, `host_scores.json`, `cluster_hygiene.json` |
| `rc4/software_hygiene/` | JSON output: `software_hygiene_summary.json` |
| `rc4/hygiene_advanced/` | JSON output: `hygiene_advanced.json` |
| `rc4/anomaly_report/` | JSON + Markdown outputs: `rc4_anomaly_report.json`, `rc4_anomaly_report.md` |
| `rc4_hygiene_charts/` | All 12 figures (fig1-fig12) |
| `rc4_charts/17-19` | Original A1-A4 anomaly case studies (kept as illustrative examples) |
| `rc4_crossasn_anomalies.py` | Original anomaly detection script (kept) |
