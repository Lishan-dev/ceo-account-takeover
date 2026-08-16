# Live Demo Build Guide: CEO Account Takeover Investigation in a Real Microsoft Sentinel Environment (Free Tier)

This guide walks you through building the CEO Account Takeover scenario **for real**, in your own free/sandbox tenant, so you have a live environment to screen-share in interviews and real screenshots for your portfolio — not just written narrative.

**Total cost: $0**, using two free Microsoft programs together.

---

## 0. The Two Accounts You Need

| Account | Why | Cost |
|---|---|---|
| **Microsoft 365 Developer Program** tenant | Gives you a full E5 sandbox: Entra ID P2, Exchange Online, sample users, PowerShell access | Free, auto-renews every 90 days if you keep using it |
| **Azure Free Trial / Pay-As-You-Go** subscription | Hosts your Log Analytics workspace + Sentinel | Free $200 credit; Sentinel costs pennies at this data volume |

Sign up in this order:

1. Go to `https://developer.microsoft.com/microsoft-365/dev-program` → join → "Instant sandbox" → this creates a tenant like `yourname.onmicrosoft.com` with ~25 demo users, Exchange, SharePoint, and **Entra ID P2 already licensed**.
2. Go to `https://azure.microsoft.com/free` and sign up for the Azure free trial using either a personal Microsoft account or the new tenant's global admin.

---

## 1. Create the Log Analytics Workspace + Enable Sentinel

1. Azure Portal → **Log Analytics workspaces** → **Create**.
   - Resource group: `rg-soc-portfolio`
   - Name: `law-soc-ceo-investigation`
   - Region: closest to you
2. Once deployed, go to **Microsoft Sentinel** in the portal → **Create** → select the workspace you just made → **Add**.
3. Sentinel billing note: with the small data volumes in this exercise (a handful of test sign-ins and mailbox events), you'll stay well within free-trial credit. Set a budget alert on the resource group as a safety net.

---

## 2. Connect Real Entra ID Logs

1. In your **M365 Developer tenant**, go to **Entra ID (Azure AD) → Diagnostic settings**.
2. Add a diagnostic setting → send to your Log Analytics workspace (`law-soc-ceo-investigation`) → check:
   - `SignInLogs`
   - `AuditLogs`
   - `NonInteractiveUserSignInLogs`
   - `RiskyUsers` / `UserRiskEvents` (if Identity Protection is available on your P2 license)
3. In **Sentinel → Content hub**, install the **Microsoft Entra ID** solution, then in **Data connectors**, connect Entra ID sign-in and audit logs (this activates the built-in analytics rule templates you'll use later).

Give it 10–15 minutes — real sign-in events start flowing the moment anyone authenticates in that tenant.

---

## 3. Pick / Create Your "CEO" Test User

1. In the M365 dev tenant admin center, either use one of the pre-seeded demo users or create a new one: `Alex.Wilber@yourtenant.onmicrosoft.com` → add to a new group called **Executives**.
2. Create a **Sentinel Watchlist** called `VIPUsers` containing this UPN — this is what your "high-value account" detection logic will reference, exactly like a real SOC's exec-monitoring tier.

---

## 4. Generate a REAL Anomalous Sign-In (Ethically, On Your Own Tenant)

You don't need to fake this — you can generate a genuinely anomalous, geographically-distant sign-in against your own test account:

1. Use a VPN (or your phone's mobile data with a VPN app set to a different country) to sign into `https://myaccount.microsoft.com` as your test CEO user from an "unusual" location.
2. Before that, intentionally mistype the password 3–4 times to generate the failed-attempt burst, then succeed on the correct one.
3. This produces **real** `SigninLogs` entries: real `Location`, real new `IPAddress`, a real `ResultType` sequence of failures-then-success — no synthetic data needed.

> This is standard, legitimate security-lab practice: testing detection logic against your own tenant/account that you own and control.

---

## 5. Generate the Mailbox Rule (Exchange Online, Real PowerShell)

Connect to Exchange Online PowerShell against your dev tenant and create a real forwarding rule on the test mailbox to simulate the BEC-staging behavior:

```powershell
Connect-ExchangeOnline -UserPrincipalName admin@yourtenant.onmicrosoft.com

New-InboxRule -Mailbox "Alex.Wilber@yourtenant.onmicrosoft.com" `
  -Name "Test-ExternalForward" `
  -ForwardTo "external.testaddress@outlook.com" `
  -StopProcessingRules $false
```

This generates a real `New-InboxRule` event in `OfficeActivity` you can query and alert on. Remove it afterward with `Remove-InboxRule` to keep the environment clean, or leave it briefly to demo the "detect → remove" containment step live.

*(Note: Office 365 unified audit logging must be turned on in Purview/Compliance center — enable it once, it can take up to 24h to activate the first time.)*

---

## 6. Build the Analytics Rule

Sentinel → **Analytics → Create → Scheduled query rule**.

**Name:** `Unfamiliar Sign-In — Executive Watchlist`
**Query:**
```kql
SigninLogs
| where UserPrincipalName in (_GetWatchlist('VIPUsers') | project UserPrincipalName)
| where ResultType == 0
| join kind=leftanti (
    SigninLogs
    | where TimeGenerated < ago(1d)
    | summarize by UserPrincipalName, Location
) on UserPrincipalName, Location
```
**Entity mapping:** map `UserPrincipalName` → Account, `IPAddress` → IP.
**Severity:** High. **Run every:** 5 minutes, lookback 5 minutes.

Build a second rule for the inbox rule detection:
```kql
OfficeActivity
| where Operation in ("New-InboxRule","Set-InboxRule")
| where Parameters has "ForwardTo" or Parameters has "RedirectTo"
```

Both rules firing against your own real, self-generated events produces genuine Sentinel **incidents** you can open, triage, and screen-record end to end.

---

## 7. Build a Workbook

Sentinel → **Workbooks → New** → add:
- A tile: sign-ins by country over time (`SigninLogs | summarize count() by Location, bin(TimeGenerated,1h)`)
- A tile: failed vs. successful auth over time
- A tile: inbox rule creation events

Save it as `Executive Account Monitoring`. This becomes a real portfolio screenshot, not a mockup.

---

## 8. Run the Investigation Live

Once your incident appears in **Sentinel → Incidents**:
1. Open it, walk the **investigation graph** (real entity relationships between your test user, IP, and device).
2. Use **Logs** to run the KQL queries from the written case study I already built you (Section 8 of `CEO-Account-Takeover-Investigation-Sentinel.md`) — they'll now return real rows from your own tenant instead of illustrative examples.
3. Take a bookmark of key evidence (Sentinel supports this natively) to build your evidence table from real query output.
4. Close the incident with a real classification and comment, exactly as you would in production.

---

## 9. What to Capture for Your Portfolio

- Screenshot: the fired incident in Sentinel's incident queue
- Screenshot: your KQL query + real result set for at least 3 of the queries
- Screenshot: the investigation graph
- Screenshot: the workbook
- Short screen recording (3–5 min): walking through detection → KQL → containment (removing the inbox rule) → incident closure
- Export the closed incident's comments/evidence as your "final report" backing

Pair this live-environment walkthrough with the written case study document as your leave-behind — recruiters/hiring managers get the narrative, technical interviewers get to watch you actually run it.

---

## 10. Cleanup / Cost Control

- Set a budget alert of $5 on the resource group.
- Delete the Log Analytics workspace when you're done recording if you don't want ongoing (minimal) ingestion cost.
- The M365 Developer sandbox stays free as long as you log in periodically (Microsoft reclaims inactive sandboxes after ~90 days of no sign-in activity).

---

## Why This Is the "Real" Version

Everything above uses **actual Microsoft services, actual Entra ID authentication, and actual Exchange Online mail rules** — the anomalous sign-in, the failed-attempt burst, and the forwarding rule are all real events in a real tenant that you own, not fabricated log rows. The written case study you already have becomes the *report* for an investigation you can now also *demonstrate live*, which is exactly what separates a hireable SOC portfolio piece from a tutorial writeup.
