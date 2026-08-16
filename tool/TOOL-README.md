# Executive Account Guardian

A detection engine that flags likely account-takeover activity against high-value (executive/VIP) Microsoft 365 identities, built from real SOC investigation patterns: **impossible travel, credential-stuffing bursts, off-hours/new-location sign-ins, and malicious mailbox forwarding rules.**

Run it against exported Entra ID sign-in logs and Exchange audit logs — the same data available from Microsoft Sentinel / Log Analytics or the Microsoft Graph API — and it produces a scored, evidence-backed HTML report a SOC analyst or CISO can act on directly.

This was built as the working companion to a full written incident-investigation case study (*CEO Account Takeover Investigation — Microsoft Sentinel*), so the detection logic maps 1:1 onto real KQL rules and real SOC triage questions rather than being a generic anomaly-detection demo.

## The real-world problem this solves

Executive accounts are the highest-value identity target in most organizations — compromise leads directly to Business Email Compromise, financial fraud, and data theft. Most orgs either:
- Have no dedicated monitoring tier for VIP accounts at all, or
- Rely entirely on native cloud alerting, which is high-noise and doesn't correlate sign-in anomalies with mailbox-level persistence (like forwarding rules) in one pass.

This tool closes that gap with a lightweight, auditable, and fully explainable rule set — every finding cites the exact evidence and threshold that triggered it, so nothing is a black box.

## What it detects

| Detection | Logic |
|---|---|
| New/unfamiliar location | Successful sign-in from a country not seen in the user's prior 30-day baseline |
| Impossible travel | Two successful sign-ins whose implied travel speed exceeds a configurable threshold (default 900 km/h) |
| Credential-guessing pattern | 3+ failed sign-ins within 15 minutes immediately preceding a success |
| Off-hours sign-in | Successful authentication outside a configurable working-hours window |
| Malicious mailbox rule | Inbox rule creation containing `ForwardTo` / `RedirectTo` — classic BEC-staging behavior |

Each finding includes severity, the specific evidence fields that triggered it, and a per-user aggregate risk score (0–100).

## Quick start

```bash
pip install pandas

# generate a synthetic demo dataset matching the CEO takeover scenario
python3 generate_sample_data.py

# run the detector
python3 detector.py \
  --signins sample_signins.csv \
  --audit sample_audit.csv \
  --watchlist ceo@fictionalcorp.com \
  --out findings.json \
  --html report.html
```

Open `report.html` in a browser for the formatted findings report.

## Using it against real data

The CSV schema matches a direct export of `SigninLogs` and `OfficeActivity` from Log Analytics/Sentinel, so pointing it at real data requires no code changes — just export with matching column names, or adapt the two `read_csv` calls in `detector.py` to pull directly via the Microsoft Graph API / `az monitor log-analytics query`.

Recommended real-world deployment path:
1. Schedule a nightly export of `SigninLogs`/`OfficeActivity` for your VIP watchlist (Graph API, Azure Automation, or a scheduled KQL export).
2. Run this tool against the export.
3. Pipe `findings.json` into your ticketing system (or a Sentinel/Teams webhook) for any `Critical`/`High` finding.
4. Use the HTML report as the analyst's starting evidence packet — it's designed to answer "what happened, where, and why does it matter" without requiring a fresh KQL session for every alert.

## Extending it

- Swap `COUNTRY_CENTROIDS` for a real IP-geolocation feed (MaxMind GeoLite2, or Sentinel's built-in `geo_info()` KQL function) for accurate impossible-travel distance.
- Add OAuth consent-grant detection (`AuditLogs` `Consent to application` events) for cloud-native persistence.
- Add MFA-method-change detection (`Register security info` events) for auth-factor persistence.
- Wire `main()` into an Azure Function or Logic App for a fully automated pipeline feeding Sentinel incidents.

## Project structure

```
exec-account-guardian/
├── detector.py              # detection engine + CLI
├── report.py                # HTML report generator
├── generate_sample_data.py  # synthetic demo dataset generator
├── README.md
```

## Why this project demonstrates hire-ready SOC/detection-engineering skill

- Real, working Python — not a mockup or a written narrative alone.
- Detection logic directly traceable to the KQL rules a Sentinel analyst would actually write (see the companion case study document).
- Explainable-by-design: every finding shows its evidence, avoiding "black box" alerting that SOC teams don't trust.
- Structured for real deployment (CSV-in, JSON/HTML-out) rather than a one-off notebook.
