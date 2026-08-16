# CEO Account Takeover Investigation - Microsoft Sentinel

A complete SOC portfolio project simulating an executive account-takeover investigation: a written incident case study, a working Python detection tool, and a guide to reproduce the investigation live in a real (free-tier) Microsoft Sentinel environment.

**Live case file:** deployed automatically via Vercel on push to `main` - see your project's assigned domain on the [Vercel dashboard](https://vercel.com/dashboard). It's a portfolio landing page rendering the real output of the detection engine below.

> **Note:** All usernames, IPs, and log data in this repo are fictional/synthetic. This is a defensive security project - detection, investigation, and response only. No offensive/attack code is included.

## What's in this repo

| Path | What it is |
|---|---|
| [`docs/case-study.md`](docs/case-study.md) | Full written incident investigation: alert triage, KQL queries, timeline, MITRE ATT&CK mapping, containment/remediation, executive summary, and 20 interview Q&As |
| [`tool/`](tool) | **Executive Account Guardian** - a working Python tool that ingests sign-in/audit log exports and automatically detects impossible travel, credential-stuffing bursts, and malicious mailbox rules |
| [`docs/live-demo-build-guide.md`](docs/live-demo-build-guide.md) | Step-by-step guide to reproduce this investigation in a real, free-tier Microsoft Sentinel + Microsoft 365 Developer sandbox environment |

## Quick start (the tool)

```bash
cd tool
pip install pandas
python3 generate_sample_data.py
python3 detector.py --signins sample_signins.csv --audit sample_audit.csv \
  --watchlist ceo@fictionalcorp.com --out findings.json --html report.html
```

Open `tool/report.html` for the generated findings report. See [`tool/TOOL-README.md`](tool/TOOL-README.md) for full details, detection logic, and how to point it at real Sentinel/Log Analytics exports.

## Why this project

Executive accounts are the highest-value identity target in most organizations — a compromise is a direct path to Business Email Compromise, financial fraud, and data theft. This project demonstrates the full SOC lifecycle end to end — **Detect → Triage → Investigate → Hunt → Correlate → Contain → Remediate → Report** — backed by a real, runnable detection tool rather than narrative alone.

## Author

Built by [Lishan](https://github.com/Lishan-dev) as a Microsoft Sentinel SOC portfolio project.
