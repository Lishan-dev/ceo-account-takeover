# CEO Account Takeover Investigation — Microsoft Sentinel
### A SOC Portfolio Case Study (Simulated Environment)

> **Disclaimer:** This is a fully simulated investigation built for portfolio/interview purposes. All usernames, IP addresses, domains, timestamps, and log excerpts are fictional. No real breach occurred. All content is defensive in nature (detection, investigation, response, remediation) - no offensive/attack code is included.

---

## 1. Executive Overview

**Scenario:** At approximately **03:07 AM**, Microsoft Sentinel generated a high-severity incident indicating that the account `ceo@fictionalcorp.com` had authenticated to Microsoft 365 from an unusual geographic location and an unrecognized device. This activity fell well outside the CEO's normal sign-in baseline (weekday, single-country, known-device pattern).

The SOC's job was to answer a core set of questions:

- Was this sign-in legitimate (e.g., travel) or attacker-controlled?
- If compromised, how was access obtained?
- What did the actor do after authenticating — read mail, create rules, touch files, target other users?
- Was there evidence of persistence (MFA changes, OAuth consent, new auth methods)?
- Was this heading toward Business Email Compromise (BEC) / financial fraud?
- What containment and remediation actions are required, and what should change to prevent recurrence?

This document walks through the full lifecycle: **Detect → Triage → Investigate → Hunt → Correlate → Contain → Remediate → Report**, using Microsoft Sentinel as the central investigation platform.

---

## 2. Introduction: Detect / Investigate / Respond / Report

**Detect** — A Sentinel analytics rule (`Sign-in from Unfamiliar Location — High-Value Account`) fired against a sign-in event tagged as anomalous by Entra ID Identity Protection.

**Investigate** — The analyst pivots into Sentinel's incident view, entity pages, and hunting workbooks, running KQL against `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`, `OfficeActivity`, and `IdentityInfo` to reconstruct what happened before and after the alert.

**Respond** — Based on evidence, the analyst determines whether this is a true positive, and if so, executes containment (session revocation, credential reset, rule removal) proportional to the confirmed risk.

**Report** — The incident is documented with a timeline, evidence table, MITRE ATT&CK mapping, root cause assessment, and an executive summary suitable for the CISO and leadership.

---

## 3. What This Project Demonstrates

**SOC Alert Triage** — Validating a true positive, scoping the investigation, assigning initial severity, identifying why the affected identity matters.

**Threat Hunting** — Going beyond the single alert to proactively search for related indicators, follow-on activity, and attacker persistence.

**Log Analysis & Correlation** — Working across Entra ID sign-in/audit logs, Microsoft 365 activity (Exchange, SharePoint, OneDrive), risk detections, and (where available) endpoint telemetry.

**Attacker Behavior Analysis** — Reconstructing a plausible attack chain from authentication through mailbox access, persistence attempts, and possible BEC.

**Incident Response** — Executing and documenting containment, credential/session controls, and recovery steps.

**SOC Reporting** — Producing an evidence-backed timeline, root-cause assessment, threat rating, and a plain-language executive summary.

---

## 4. Why This Project Matters

**Real business risk.** A compromised CEO identity is one of the highest-value targets in any enterprise. Access to that mailbox and connected cloud apps can expose:

- Strategic and M&A documents, board communications
- Financial approval workflows (wire transfers, vendor payments)
- Customer and partner correspondence
- Credentials or trust that can be used to pivot to Finance, IT admins, or other executives

A compromised executive account is also a launchpad for **Business Email Compromise**, internal spear-phishing, and further credential theft — attacks that are cheap for the attacker and extremely costly for the business.

**SOC lifecycle demonstrated end-to-end:** Detect → Triage → Investigate → Hunt → Correlate → Contain → Remediate → Report.

**Enterprise tooling:** Microsoft Sentinel is used as the single pane of glass — incidents, analytics rules, hunting queries, workbooks, entity pages, threat intelligence, and automation (playbooks).

**MITRE ATT&CK discipline:** Techniques are only mapped where the simulated evidence actually supports them — not added for the sake of looking advanced.

---

## 5. Initial Alert

```
Incident:        Suspicious Sign-In — High-Value Account (CEO)
Sentinel Rule:   Sign-in from Unfamiliar Location — Privileged/Executive Users
Severity:        High
Detection Time:  03:07 (local, HQ time zone)
User:            ceo@fictionalcorp.com  (Group: Executives, Role: Global CEO)
Source IP:       185.220.101.47 (simulated)
Location:        Country flagged as atypical for this user's history
Application:     Office 365 Exchange Online / Microsoft 365 portal
Auth Method:     Password + Push MFA (simulated)
Device:          Unrecognized device, no compliance record in Intune
Risk Signal:     Entra ID Identity Protection — "Unfamiliar sign-in properties"
```

**Why this alert matters:** The combination of (a) an off-hours timestamp, (b) an atypical location, (c) an unmanaged/unrecognized device, and (d) a high-value identity is exactly the profile Sentinel's executive-tier detection logic is tuned to surface. None of these facts alone proves compromise — together they justify immediate triage.

**Guiding question for the SOC:**
> "Is this a legitimate unusual sign-in (e.g., undisclosed travel, VPN, new phone), or is this evidence of account takeover?"

We do **not** assume compromise at this stage.

---

## 6. Alert Triage (First 5–10 Minutes)

| # | Question | Finding |
|---|----------|---------|
| 1 | What triggered the alert? | Entra ID flagged unfamiliar sign-in properties on a high-value account |
| 2 | Which user is affected? | CEO — Global Admin exempt, but Executives group, mailbox holds sensitive data |
| 3 | Why is this user high-value? | Access to financial approvals, board comms, strategic data |
| 4 | Where did the login originate? | IP geolocates to a country with no business justification on file |
| 5 | What device was used? | Not present in Intune's managed-device inventory |
| 6 | Is the IP known? | Not on internal allow-list; flagged "suspicious" by TI feed (medium confidence) |
| 7 | Is the location unusual? | Yes — no prior sign-ins from this country in 90-day baseline |
| 8 | Is the sign-in time unusual? | Yes — 03:00 local falls outside CEO's typical 06:30–19:00 pattern |
| 9 | Was MFA involved? | Yes — push notification approved (raises the stakes: MFA fatigue or legitimate approval?) |
| 10 | Other suspicious sign-ins? | Yes — repeated failed attempts 20 minutes prior, same user |
| 11 | Known travel schedule? | Calendar/HR system shows no scheduled travel for this date |
| 12 | Evidence of compromised device? | No endpoint telemetry from this device (unmanaged) |
| 13 | Classification | **Requires further investigation** — not yet confirmed true/false positive |

**Initial severity:** **High.** Justification: privileged/executive identity + off-hours + new country + new device + prior failed attempts, even though MFA was ultimately satisfied. Failed attempts followed by success is a classic password-spray or credential-stuffing signature and cannot be dismissed at triage.

---

## 7. Microsoft Sentinel Investigation Workspace

| Component | Role in this investigation |
|---|---|
| **Incidents** | Central case record; groups the alert, entities, and evidence bookmarks |
| **Analytics rules** | The rule that fired (unfamiliar sign-in) plus related rules (impossible travel, new mailbox rule, risky sign-in) |
| **Entity pages** | Pivot on the user (`ceo@fictionalcorp.com`) and the IP to see all related activity across tables |
| **Investigation graph** | Visualizes relationships between the user, IP, device, and any downstream alerts |
| **Logs (KQL)** | Primary tool for querying `SigninLogs`, `AuditLogs`, `OfficeActivity`, `IdentityInfo` |
| **Hunting queries** | Proactive searches beyond the alert (see Section 10) |
| **Workbooks** | Sign-in analysis workbook, Office 365 activity workbook for visual trend review |
| **Watchlists** | VIP/executive user list, known-good corporate IP ranges, travel exception list |
| **Threat Intelligence** | Enrich the source IP/domain against TI indicators ingested into Sentinel |
| **Automation/Playbooks** | Logic App playbook to enrich, notify, and (with approval) contain (Section 18) |

---

## 8. KQL Investigation Queries

All queries below are **defensive/investigative only** — read/query operations against log tables, no offensive code.

### A. User Sign-In History
```kql
SigninLogs
| where UserPrincipalName == "ceo@fictionalcorp.com"
| where TimeGenerated > ago(7d)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName,
          DeviceDetail.displayName, DeviceDetail.trustType, ResultType, ResultDescription,
          AuthenticationRequirement, RiskLevelDuringSignIn, RiskState
| order by TimeGenerated desc
```
**Purpose:** Baseline vs. anomaly comparison. **Look for:** new countries, new devices, `ResultType` failures clustered before a success, elevated `RiskLevelDuringSignIn`. **Interpretation:** Establishes whether the 03:07 event is an outlier against the user's own history.

### B. Geographic Anomaly
```kql
SigninLogs
| where UserPrincipalName == "ceo@fictionalcorp.com"
| where TimeGenerated > ago(30d)
| summarize SignInCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by Location, IPAddress
| order by SignInCount asc
```
**Purpose:** Surface locations/IPs seen rarely or only once. **Look for:** a single-occurrence country coinciding with the alert timestamp. **Interpretation:** Rare locations are not proof of compromise but raise pretest probability significantly for an executive account.

### C. Impossible Travel
```kql
let signins = SigninLogs
| where UserPrincipalName == "ceo@fictionalcorp.com"
| where ResultType == 0
| project TimeGenerated, Location, IPAddress
| order by TimeGenerated asc;
signins
| serialize
| extend PrevTime = prev(TimeGenerated), PrevLocation = prev(Location)
| extend GapHours = datetime_diff('hour', TimeGenerated, PrevTime)
| where Location != PrevLocation and GapHours < 4
| project TimeGenerated, PrevTime, GapHours, Location, PrevLocation
```
**Purpose:** Detect two successful sign-ins from geographically distant locations in a time window too short for real travel. **Interpretation:** A strong compromise indicator when paired with other findings — but VPN/proxy usage can produce false positives, so it is corroborating, not conclusive, evidence.

### D. Failed Authentication Preceding Success (Spray/Stuffing Pattern)
```kql
SigninLogs
| where UserPrincipalName == "ceo@fictionalcorp.com"
| where TimeGenerated between (ago(1h) .. now())
| summarize Attempts = count(), Failures = countif(ResultType != 0),
            Successes = countif(ResultType == 0), IPs = make_set(IPAddress)
    by bin(TimeGenerated, 15m)
| where Failures > 3 and Successes > 0
```
**Purpose:** Identify the "many failures, then a success" pattern typical of password spraying/credential stuffing. **Interpretation:** Combined with a new IP/location, this strongly suggests the successful sign-in was not the legitimate user's first attempt with a forgotten password, but rather guessed/leaked credentials.

### E. MFA / Authentication Method Changes
```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where TargetResources has "ceo@fictionalcorp.com"
| where OperationName has_any ("Update user", "Register security info",
        "User registered security info", "Delete user", "Update StrongAuthenticationMethod")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
```
**Purpose:** Detect attacker attempts to add a new MFA method (a common persistence technique). **Look for:** an `OperationName` for security-info registration initiated shortly after the suspicious sign-in, especially if `InitiatedBy` doesn't match the CEO's normal admin/self-service pattern.

### F. Mailbox Activity
```kql
OfficeActivity
| where UserId == "ceo@fictionalcorp.com"
| where TimeGenerated > ago(2h)
| where Operation in ("MailItemsAccessed", "New-InboxRule", "Set-InboxRule",
        "Send", "SoftDelete", "MoveToDeletedItems")
| project TimeGenerated, Operation, ClientIP, ResultStatus, Parameters
| order by TimeGenerated asc
```
**Purpose:** Determine what the session did inside the mailbox after authentication. **Look for:** `MailItemsAccessed` immediately after sign-in, or any `Send`/`New-InboxRule` events — both are high-signal for takeover-in-progress.

### G. Suspicious Inbox Rules / Forwarding
```kql
OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where TimeGenerated > ago(2h)
| extend RuleParams = tostring(Parameters)
| where RuleParams has_any ("ForwardTo", "RedirectTo", "MoveToFolder", "DeleteMessage")
| project TimeGenerated, UserId, Operation, ClientIP, RuleParams
```
**Purpose:** Attackers commonly create a rule to forward or hide replies (e.g., silently forwarding external mail, or moving finance-related mail to RSS/Archive to hide it from the victim). **Interpretation:** A rule with an external forwarding address or a rule that hides mail from certain senders (e.g., "finance", "wire", "invoice") is a critical finding, strongly indicative of BEC staging.

### H. OAuth / Application Consent Activity
```kql
AuditLogs
| where TimeGenerated > ago(2h)
| where OperationName in ("Consent to application", "Add app role assignment to service principal",
        "Add OAuth2PermissionGrant")
| where InitiatedBy has "ceo@fictionalcorp.com" or TargetResources has "ceo@fictionalcorp.com"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
```
**Purpose:** Detect illicit OAuth app consent (a common cloud-native persistence method that survives password resets). **Look for:** consent granted to an unfamiliar or newly-registered application with broad mail/file scopes.

### I. Related Users / Shared Indicators
```kql
SigninLogs
| where IPAddress == "185.220.101.47"
| where TimeGenerated > ago(7d)
| summarize Users = make_set(UserPrincipalName), Count = count() by IPAddress
```
**Purpose:** Determine whether the same suspicious IP touched other accounts (spray campaign vs. single targeted attack). **Interpretation:** If only the CEO account was targeted from this IP, it suggests deliberate targeting rather than an opportunistic spray hitting many users.

**Query pattern used throughout:** *Purpose → Query → What to look for → Analyst interpretation.*

---

## 9. Timeline Reconstruction

| Time | Event | Evidence (Log/Table) | Why it matters |
|---|---|---|---|
| 02:47 | 6 failed sign-in attempts | `SigninLogs`, ResultType ≠ 0 | Suggests credential guessing/spraying, not a simple typo |
| 02:58 | Successful authentication from atypical country | `SigninLogs`, ResultType = 0, new `Location` | First confirmed foothold |
| 03:01 | New session token issued | `SigninLogs` session/token metadata | Attacker now has an active session |
| 03:04 | Mailbox accessed (`MailItemsAccessed`) | `OfficeActivity` | Confirms post-auth activity, not a dead login |
| 03:07 | Sentinel generates high-risk incident | Analytics rule trigger | SOC becomes aware |
| 03:12 | SOC begins triage | Case notes / incident record | Response clock starts |
| 03:20 | Suspicious inbox rule discovered (external forward) | `OfficeActivity`, `New-InboxRule` | Strong BEC-staging indicator |
| 03:27 | Additional suspicious sign-in attempt (different app) | `SigninLogs` | Possible lateral probing within M365 |
| 03:35 | Containment initiated (session revoke, password reset) | `AuditLogs`, ticket record | Stops attacker's active access |

Every entry above is tied to a specific, queryable log source — a timeline built on assertions without corresponding evidence is not defensible in a real incident report.

---

## 10. Threat Hunting Beyond the Alert

**Guiding question:** *"If this account is compromised, what else could the attacker have done?"*

**Identity:** additional sign-ins from the same IP/ASN; other risky users flagged by Identity Protection in the same window; any new devices registered to the account.

**Email:** full mailbox access pattern (read vs. search vs. export); any messages sent from the account (potential BEC to Finance); any messages related to wire transfers, invoices, or vendor changes.

**Cloud:** SharePoint/OneDrive access logs for the CEO's document libraries; unusual bulk downloads; new sharing links created (`AddedToSecureLink`, `SharingSet`).

**Persistence:** new MFA methods registered; new OAuth app consents; any change to Conditional Access exclusions involving this user.

**Lateral movement/targeting:** sign-in attempts against Finance, IT admin, or other executive accounts from the same source IP or using similar patterns (spray fingerprint).

---

## 11. Threat Intelligence Enrichment

| Indicator | Reputation | Context | Confidence | Risk |
|---|---|---|---|---|
| `185.220.101.47` | Flagged medium-risk (associated with anonymization infrastructure) | No prior business use by this org | Medium | High when paired with behavioral evidence |
| Forwarding domain in inbox rule | Newly registered domain, no prior mail history with org | Domain unrelated to any known vendor | Medium-High | High |
| User agent string | Generic/automation-like, inconsistent with CEO's known browser/OS fingerprint | — | Low-Medium (UA alone is weak) | Supporting only |

**Analyst discipline:** TI reputation alone is never treated as proof. A "suspicious" IP score is one input; it only becomes actionable when it aligns with the failed-then-successful auth pattern, the off-hours timing, and the mailbox rule — i.e., internal telemetry corroborating external reputation.

---

## 12. Attacker Behavior Analysis

```
Initial Access  →  Valid Account Usage  →  Mailbox Access  →  Persistence Attempt
(credential          (successful auth,        (MailItemsAccessed)   (inbox rule w/
 spray/stuffing)      MFA satisfied)                                 external forward)
        ↓
Internal Reconnaissance (additional sign-in attempt, app probing)
        ↓
Suspected Business Email Compromise Staging (forwarding rule created, no confirmed
fraudulent send observed yet in this simulated evidence set)
```

- **Observed (directly evidenced):** failed-then-successful authentication, new location/device, mailbox access, creation of an external-forwarding inbox rule.
- **Strongly suspected (evidence-consistent but not 100% certain):** credential-based initial access (vs. session/token theft) given the presence of failed password attempts rather than a token replay signature.
- **Unsupported assumption (explicitly not claimed):** that a fraudulent wire transfer was requested or completed — no `Send` to Finance with financial content was observed in this simulated evidence set, so BEC is *staged/suspected*, not confirmed.

---

## 13. MITRE ATT&CK Mapping

| Technique | Evidence | Why it applies | Detection opportunity |
|---|---|---|---|
| **T1078 – Valid Accounts** | Successful auth with correct credentials + MFA | Attacker used legitimate credentials rather than exploiting a vulnerability | Sign-in risk detections, impossible travel |
| **T1110 – Brute Force (Password Guessing/Spraying)** | 6 failed attempts before success in `SigninLogs` | Pattern consistent with spraying/stuffing prior to success | Failed-then-success KQL rule (Section 8D) |
| **T1114 – Email Collection** | `MailItemsAccessed` immediately post-auth | Attacker read mailbox content | Anomalous mailbox access volume/time |
| **T1114.003 – Email Forwarding Rule** | New-InboxRule with external ForwardTo | Classic BEC persistence/exfiltration technique | Inbox rule creation alerting (Section 8G) |
| **T1098 – Account Manipulation** | *Not confirmed* — no MFA-method addition observed in this scenario's evidence | Mapped as a hunting target, not a confirmed technique | MFA/auth-method change alerting (Section 8E) |

Techniques such as Phishing (T1566) or External Remote Services are **not mapped** here because the simulated evidence does not directly establish the initial-access vector — see Root Cause (Section 15).

---

## 14. Threat-Level Assessment

**Identity risk:** High — executive account, unrecognized device, atypical location.
**Behavioral risk:** High — failed-then-success pattern, mailbox access, external-forwarding rule created.
**Intelligence risk:** Medium — IP and domain reputational signals, not definitively malicious in isolation.
**Business risk:** High — CEO mailbox, plausible BEC staging, potential exposure of sensitive communications.

**Final rating: High** (not automatically escalated to *Critical*). Rationale: escalation to Critical would require confirmed data exfiltration, a completed fraudulent transaction, or confirmed persistence surviving containment (e.g., a rogue MFA method or OAuth grant). None of those were confirmed in this evidence set — the forwarding rule was caught and evidence points to a contained, single-account incident. The rating is driven by the *behavioral and evidentiary picture*, not by the user's title alone.

---

## 15. Containment

| Action | Purpose | Risk/consideration |
|---|---|---|
| Revoke active sessions/refresh tokens | Immediately cuts attacker access even if password isn't yet changed | May log out legitimate concurrent sessions — coordinate with the user |
| Reset account credentials | Removes value of any stolen/guessed password | Must be done via out-of-band verification (phone call), not email, to avoid tipping off an attacker still in the mailbox |
| Require MFA re-registration / verify existing methods | Confirms no rogue authenticator was added | Avoid accidentally removing the legitimate user's method |
| Remove the malicious inbox rule | Stops ongoing forwarding/exfiltration | Preserve a copy of the rule as evidence before deleting |
| Review and revoke suspicious OAuth grants | Removes persistence that survives password reset | Validate impact on any legitimate third-party integrations first |
| Block malicious source IP at the edge/Conditional Access | Prevents immediate re-use of the same infrastructure | Low value alone if attacker rotates IPs — pair with behavioral controls |
| Hunt for and check other high-value accounts | Determine blast radius | Time-sensitive — do in parallel, not after |
| Preserve evidence (logs, rule config, session data) | Supports root cause and, if needed, legal/HR follow-up | Export before remediation actions overwrite state |
| Increase monitoring on the account | Detect any bounce-back attempts | Temporary, time-boxed control |

**Note:** Full account disablement was not required here because token revocation + password reset + rule removal fully interrupted the observed activity; disablement is reserved for cases with confirmed active, ongoing attacker control that other controls can't stop fast enough.

---

## 16. Remediation

- Confirm credential reset completed and verified out-of-band with the CEO
- Confirm MFA methods reviewed; remove anything not recognized by the user
- Confirm all sessions/tokens revoked across all connected apps
- Investigate the unmanaged device further where possible (or require it to be enrolled/blocked from future access)
- Full review of all inbox rules on the mailbox (not just the malicious one) for anything else missed
- Full review of OAuth app consents granted to the tenant, not just this user
- Recommend Conditional Access policy requiring managed/compliant devices for executive accounts
- Recommend risk-based Conditional Access (block/require step-up MFA on medium+ sign-in risk)
- Recommend dedicated monitoring/alerting tier for VIP/executive accounts
- Recommend a brief awareness refresh with the executive team on phishing/credential hygiene (framed constructively, not punitively)

---

## 17. Detection Engineering

| Detection idea | Data source | Logic | Severity | Response |
|---|---|---|---|---|
| High-value account sign-in from new country | `SigninLogs` + watchlist of VIP UPNs | New `Location` not in 90-day baseline for watchlisted user | High | Auto-enrich + notify SOC |
| Impossible travel | `SigninLogs` | Two successful sign-ins, distance/time infeasible | High | Auto-enrich, analyst review |
| New/unmanaged device sign-in (privileged user) | `SigninLogs` + Intune | `DeviceDetail.trustType` not compliant, VIP watchlist | Medium-High | Notify SOC, prompt device compliance |
| Failed → success burst | `SigninLogs` | ≥3 failures then success within 15 min | High | Auto-enrich + notify |
| New MFA method registered | `AuditLogs` | `Register security info` on VIP account outside change window | High | Notify + verify with user |
| External-forwarding inbox rule created | `OfficeActivity` | `New-InboxRule`/`Set-InboxRule` params contain `ForwardTo`/`RedirectTo` to external domain | Critical | Auto-disable rule pending review, notify SOC |
| Anomalous OAuth consent | `AuditLogs` | Consent to app with high-privilege mail/file scopes, low app reputation/age | High | Notify SOC, hold for admin review |
| Executive activity outside normal hours | `OfficeActivity` + `SigninLogs` | Activity outside user's learned working-hours baseline | Medium | Log for correlation, no auto-action |

---

## 18. Automation (Conceptual Playbook)

```
High-Risk CEO Sign-In Alert
        ↓
Validate Alert (dedupe, confirm real user/account)
        ↓
Enrich IP/Identity (TI lookup, geolocation, ASN)                [Automated]
        ↓
Check Recent Sign-ins (query SigninLogs for pattern)            [Automated]
        ↓
Check Mailbox Activity (query OfficeActivity for rules/access)  [Automated]
        ↓
Check Risk Indicators (Identity Protection risk state)          [Automated]
        ↓
Notify SOC (Teams/email with enriched case summary)             [Automated]
        ↓
Analyst Reviews Evidence                                        [Human]
        ↓
Contain if Confirmed (revoke session, reset creds, remove rule) [Human-approved]
        ↓
Create/Update Incident with full evidence package                [Automated logging]
```

Enrichment and evidence-gathering are automated to compress the response window; **account containment actions require analyst approval** given the business impact of disrupting a CEO's access.

---

## 19. Evidence Table

| Evidence | Source | Observation | Risk | Confidence |
|---|---|---|---|---|
| Sign-in | Entra ID (`SigninLogs`) | Unusual location, new device | High | High |
| Failed-then-success pattern | `SigninLogs` | 6 failures, then success within minutes | High | High |
| Source IP | Threat Intelligence | Medium-risk reputation | Medium | Medium |
| Inbox rule | `OfficeActivity` | External forwarding rule created | Critical | High |
| MFA status | `AuditLogs` | No unauthorized method added | Low | High |
| File/SharePoint access | `OfficeActivity` | No abnormal bulk download observed | Low | Medium |
| Other accounts | `SigninLogs` (same IP) | No other org accounts touched by this IP | Low | Medium |

---

## 20. Root Cause Analysis

**Most likely initial-access vector, given the evidence:** credential compromise via guessing/stuffing (supported by the failed-attempt burst immediately preceding success) rather than phishing or token theft (no phishing email or session-token replay signature was present in this evidence set).

However, per SOC discipline:

> **"Root cause cannot be fully confirmed from the available telemetry alone."** Confirming *how* the credential was obtained (e.g., prior phishing, breach-list reuse, infostealer log) would require additional evidence: mail-flow/phishing-report review, dark-web/breach-monitoring correlation, and endpoint forensics on the CEO's usual devices to rule out infostealer malware.

**Additional evidence that would strengthen the conclusion:** mailbox sent/received items around the suspected phishing window, EDR telemetry from the CEO's known devices, and any breach-database correlation for the CEO's credentials.

---

## 21. Final Incident Report

**Incident Name:** CEO Account Takeover Investigation
**Classification:** Account Compromise / Identity Threat (Suspected BEC Staging)
**Severity:** High
**Detection Source:** Microsoft Sentinel (Unfamiliar Sign-In analytics rule + Identity Protection risk signal)
**Affected Asset:** CEO Microsoft 365 identity (`ceo@fictionalcorp.com`)
**Initial Detection:** Suspicious sign-in at 03:07 from an atypical location/device

**Investigation Summary:** Sentinel flagged an off-hours, out-of-country sign-in to the CEO's account. Investigation confirmed a burst of failed authentication attempts immediately preceding the successful login, mailbox access consistent with attacker reconnaissance, and creation of an external mail-forwarding rule — a strong indicator of Business Email Compromise staging. No confirmed fraudulent transaction or data exfiltration was identified. The malicious rule was removed and the session/credentials contained within roughly 28 minutes of the alert firing.

**Key Findings:**
- Credential-guessing pattern preceded successful authentication
- Mailbox accessed post-authentication
- External-forwarding inbox rule created (removed during containment)
- No unauthorized MFA method or OAuth grant confirmed
- No other org accounts touched from the same source IP

**Attack Timeline:** See Section 9.

**MITRE ATT&CK Mapping:** T1078 (Valid Accounts), T1110 (Brute Force), T1114 (Email Collection), T1114.003 (Email Forwarding Rule). See Section 13.

**Containment:** Session/token revocation, credential reset, malicious rule removal, IP blocked at Conditional Access, related-account hunt performed with no additional compromise found.

**Remediation:** MFA method review, OAuth consent audit, Conditional Access hardening for executive accounts (compliant-device requirement, risk-based sign-in policy), VIP monitoring tier.

**Business Impact:** Limited/contained. Mailbox was accessed and an exfiltration mechanism (forwarding rule) was staged but removed before confirmed data loss or financial fraud occurred.

**Root Cause:** Not fully confirmed — most consistent with credential guessing/stuffing; phishing and infostealer origin not ruled out. See Section 20.

**Final Threat Level:** **High** — driven by confirmed mailbox access and BEC-staging behavior, not solely by the user's executive title.

---

## 22. Executive Summary (For CISO / Leadership)

At approximately 3:00 AM, the CEO's Microsoft 365 account was signed into from an unfamiliar location and device, after several failed login attempts. Our security monitoring system (Microsoft Sentinel) flagged this immediately as high-risk because it targeted a senior executive account.

**Was the account compromised?** The investigation found strong evidence that someone other than the CEO gained access — including a mail-forwarding rule set up to quietly copy incoming email to an outside address, a technique commonly used ahead of financial fraud attempts.

**What was exposed?** The attacker had access to the mailbox for roughly 30 minutes before containment. We found no evidence of a completed fraudulent transaction or bulk file download, but we cannot rule out that some emails were viewed during that window.

**What did the SOC do?** We cut off the attacker's active session, reset the account's credentials, removed the forwarding rule, and confirmed no other executive or finance accounts were affected from the same source.

**Is the threat contained?** Yes — as of this report, the account is secured, the malicious rule is removed, and monitoring has been increased on the account.

**What should leadership do next?** Approve the recommended Conditional Access changes for executive accounts (requiring managed devices and stronger sign-in risk checks), and consider a brief, non-punitive refresher on phishing awareness for the executive team.

---

## 23. Interview-Ready Explanation (2–3 Minutes, First Person)

> "For this project, I simulated a real-world CEO account takeover investigation using Microsoft Sentinel.
>
> It started with a Sentinel alert showing the CEO's account signing in around 3 AM from a country we'd never seen for that user, on a device that wasn't managed by our MDM. Because it was a high-value executive account, I treated it as high priority right away, but I didn't assume compromise — the first question I always ask is whether there's a legitimate explanation, like travel.
>
> I triaged the alert by pulling the user's sign-in history and checking things like whether MFA was satisfied, whether the location had ever been seen before, and whether there was a travel record. That's when I found several failed login attempts right before the successful one — a pattern that looks a lot more like credential guessing than someone just mistyping their password.
>
> From there I moved into KQL. I wrote queries against SigninLogs to confirm the anomaly and check for impossible travel, and against AuditLogs to see if the attacker tried to register a new MFA method — which they hadn't. Then I pivoted to OfficeActivity to see what happened inside the mailbox after authentication, and that's where I found the real red flag: a newly created inbox rule silently forwarding mail to an external address. That's a classic Business Email Compromise staging technique.
>
> I hunted beyond the single alert to check whether the same IP had touched any other accounts in the org — it hadn't, which told me this was a targeted attempt rather than a broad spray campaign.
>
> Based on all of that, I rated the incident High — not Critical, because I hadn't found confirmed data exfiltration or a completed fraudulent transaction, and the forwarding rule was caught before it did damage. I mapped the behavior to MITRE ATT&CK — Valid Accounts, Brute Force, and Email Collection with the forwarding-rule sub-technique.
>
> For containment, I revoked the active session, forced a credential reset verified out-of-band with the actual CEO, and removed the malicious rule. Then I recommended Conditional Access changes so executive accounts require a compliant device and stronger sign-in risk enforcement going forward.
>
> What I reported to leadership was simple: here's what happened, here's what we know was and wasn't exposed, here's what we did, and here's what needs approval to prevent it next time."

---

## 24. Interview Questions & Answers

**1. Why is a CEO account considered high risk?**
*Answer:* It has broad access to sensitive business, financial, and strategic data, and its trust can be leveraged for BEC or further compromise.
*Reasoning:* Impact is a function of both access level and the trust others place in communications from that identity.
*Evidence to investigate:* Mailbox permissions, delegated access, group memberships.

**2. What makes a 3 AM sign-in suspicious?**
*Answer:* It falls outside the user's established working-hours baseline, especially combined with a new location/device.
*Reasoning:* Time alone is weak evidence; it's the combination with other anomalies that matters.
*Evidence to investigate:* Historical sign-in time distribution for the user.

**3. How would you determine whether the login was legitimate?**
*Answer:* Check travel records/calendar, confirm directly with the user out-of-band, and review device/location consistency.
*Reasoning:* Verification with the actual human is the fastest way to rule out false positives.
*Evidence to investigate:* HR/travel system, direct phone confirmation.

**4. What logs would you investigate first?**
*Answer:* Entra ID `SigninLogs`, then `AuditLogs` and `OfficeActivity`.
*Reasoning:* Authentication logs establish the "did they get in" question before investigating "what did they do."
*Evidence to investigate:* As above.

**5. What KQL queries would you run?**
*Answer:* Sign-in history, geographic anomaly, impossible travel, failed-then-success burst, mailbox rule search.
*Reasoning:* Each answers a distinct investigative question in sequence.
*Evidence to investigate:* See Section 8.

**6. How do you investigate impossible travel?**
*Answer:* Compare consecutive successful sign-in locations and timestamps for a physically infeasible gap.
*Reasoning:* A strong but not definitive indicator — VPNs can produce false positives.
*Evidence to investigate:* `SigninLogs` location/time deltas.

**7. What does a successful login actually prove?**
*Answer:* Only that valid credentials and the MFA challenge were satisfied — not that the legitimate user performed it.
*Reasoning:* MFA fatigue/push-bombing can result in a "successful" but illegitimate authentication.
*Evidence to investigate:* MFA method used, push-approval timing pattern.

**8. How would you determine whether credentials were compromised?**
*Answer:* Look for a failed-attempt burst preceding success, breach-list correlation, and rule out phishing/infostealer activity.
*Reasoning:* Distinguishes credential guessing from token theft or phishing.
*Evidence to investigate:* `SigninLogs`, threat intel, endpoint telemetry.

**9. How would you investigate MFA manipulation?**
*Answer:* Query `AuditLogs` for security-info registration events on the account around the incident window.
*Reasoning:* New MFA methods are a common persistence mechanism.
*Evidence to investigate:* `AuditLogs` `Register security info` events.

**10. What would you look for in Microsoft 365 audit logs?**
*Answer:* Mailbox rule changes, permission delegation, admin role changes, OAuth consent grants.
*Reasoning:* These represent the most common post-compromise persistence/impact actions.
*Evidence to investigate:* `AuditLogs`, `OfficeActivity`.

**11. How would you investigate mailbox rules?**
*Answer:* Query `New-InboxRule`/`Set-InboxRule` operations and inspect parameters for forwarding/hiding behavior.
*Reasoning:* Malicious rules are a top BEC-staging technique.
*Evidence to investigate:* `OfficeActivity`.

**12. How would you detect BEC activity?**
*Answer:* Look for forwarding rules, unusual sent-mail content (wire/invoice language), and impersonation attempts to Finance.
*Reasoning:* BEC has a recognizable behavioral signature distinct from simple account access.
*Evidence to investigate:* `OfficeActivity` Send events, mail content review (with appropriate authorization).

**13. How would you investigate OAuth abuse?**
*Answer:* Query consent-grant audit events and review the requesting app's age, publisher, and requested scopes.
*Reasoning:* Malicious OAuth apps survive password resets, making them a favored persistence method.
*Evidence to investigate:* `AuditLogs` consent events, Entra ID enterprise app registry.

**14. How would you determine whether other users were affected?**
*Answer:* Pivot on the source IP/indicators to see what other accounts they touched.
*Reasoning:* Determines whether this is a targeted attack or part of a broader campaign.
*Evidence to investigate:* `SigninLogs` filtered by IP/ASN.

**15. When would you disable the account?**
*Answer:* When there's confirmed, ongoing attacker control that faster controls (session revoke, password reset) can't immediately stop.
*Reasoning:* Disabling a CEO's account has real business cost, so it's proportional to confirmed, active risk.
*Evidence to investigate:* Real-time session state.

**16. When would you revoke sessions?**
*Answer:* Immediately upon confirming suspicious activity, before or alongside the password reset.
*Reasoning:* A password reset alone doesn't invalidate already-issued tokens.
*Evidence to investigate:* Active session/refresh-token inventory.

**17. How do you determine incident severity?**
*Answer:* Combine identity value, behavioral evidence, threat intel context, and confirmed business impact — not title alone.
*Reasoning:* Severity should reflect evidence, not assumptions.
*Evidence to investigate:* Full evidence table (Section 19).

**18. How do you map activity to MITRE ATT&CK?**
*Answer:* Only map techniques the evidence directly supports, and note detection opportunities for each.
*Reasoning:* Forced mappings reduce the credibility and usefulness of the report.
*Evidence to investigate:* Section 13.

**19. What would you report to the CISO?**
*Answer:* A concise executive summary: what happened, what was/wasn't exposed, what was done, and what's needed next.
*Reasoning:* Leadership needs decision-relevant information, not raw log detail.
*Evidence to investigate:* Section 22.

**20. What would you improve after the incident?**
*Answer:* Conditional Access hardening for executive accounts, VIP monitoring tier, and automated rule-blocking detections.
*Reasoning:* Turning one incident into a durable detection/prevention improvement is the point of the post-incident process.
*Evidence to investigate:* Section 17 detection engineering ideas.

---

## Lessons Learned

- Failed-then-successful authentication bursts deserve automatic escalation for VIP accounts, even when MFA is ultimately satisfied.
- Inbox-rule creation should be near-real-time alerted (not just logged) for executive/finance accounts given how quickly it can precede fraud.
- "Critical" severity should be reserved for confirmed impact, not assigned by job title alone — this keeps ratings meaningful and avoids alert fatigue on legitimately High incidents.
- Root cause should be stated with appropriate humility when the telemetry doesn't fully support a conclusion — a partial answer with a documented evidence gap is more credible than a guess.

---

*End of case study.*
