"""
Executive Account Guardian
---------------------------
A detection engine for identifying likely account-takeover activity against
high-value (executive/VIP) identities, built from real SOC investigation
patterns: impossible travel, credential-stuffing bursts, off-hours sign-ins
from new locations/devices, and malicious mailbox forwarding rules.

Designed to run against exported Microsoft Entra ID sign-in logs and
Microsoft 365 (Exchange) audit logs (CSV), the same data you'd pull from
Microsoft Sentinel / Log Analytics or the Graph API in a real environment.

This is a defensive, read-only analysis tool. It does not perform any
account actions -- it produces findings for a human analyst to act on.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import pandas as pd

# ---------------------------------------------------------------------------
# Config / thresholds -- tune these per organization
# ---------------------------------------------------------------------------

IMPOSSIBLE_TRAVEL_SPEED_KMH = 900          # faster than a commercial flight
FAILED_BURST_WINDOW_MIN = 15
FAILED_BURST_THRESHOLD = 3
BASELINE_LOOKBACK_DAYS = 30
WORKING_HOURS_START = 6                    # 06:00 local
WORKING_HOURS_END = 21                     # 21:00 local
SUSPICIOUS_RULE_KEYWORDS = ["ForwardTo", "RedirectTo", "ForwardAsAttachmentTo"]

# Approximate country centroids for impossible-travel distance calc.
# In production, replace with a real IP-geolocation feed (MaxMind, Sentinel's
# built-in GeoLite enrichment, or Entra ID's own Location field lat/long).
COUNTRY_CENTROIDS = {
    "United States": (39.8283, -98.5795),
    "United Kingdom": (55.3781, -3.4360),
    "Germany": (51.1657, 10.4515),
    "Philippines": (12.8797, 121.7740),
    "Nigeria": (9.0820, 8.6753),
    "Russia": (61.5240, 105.3188),
    "Romania": (45.9432, 24.9668),
    "Brazil": (-14.2350, -51.9253),
    "Vietnam": (14.0583, 108.2772),
    "Singapore": (1.3521, 103.8198),
    "Netherlands": (52.1326, 5.2913),
    "France": (46.2276, 2.2137),
    "Canada": (56.1304, -106.3468),
    "Australia": (-25.2744, 133.7751),
    "India": (20.5937, 78.9629),
    "Indonesia": (-0.7893, 113.9213),
}


@dataclass
class Finding:
    severity: str           # Low / Medium / High / Critical
    category: str           # e.g. "Impossible Travel"
    user: str
    timestamp: str
    detail: str
    evidence: dict = field(default_factory=dict)


def haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1 = map(math.radians, a)
    lat2, lon2 = map(math.radians, b)
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(h))


class ExecAccountGuardian:
    def __init__(self, signin_csv: str, audit_csv: Optional[str] = None,
                 watchlist: Optional[list[str]] = None):
        self.signins = pd.read_csv(signin_csv, parse_dates=["TimeGenerated"])
        self.audit = pd.read_csv(audit_csv, parse_dates=["TimeGenerated"]) if audit_csv else None
        self.watchlist = set(watchlist) if watchlist else set(self.signins["UserPrincipalName"].unique())
        self.findings: list[Finding] = []

    # ------------------------------------------------------------------
    def run(self) -> list[Finding]:
        self.findings.clear()
        for user in self.watchlist:
            user_signins = self.signins[self.signins["UserPrincipalName"] == user].sort_values("TimeGenerated")
            if user_signins.empty:
                continue
            self._detect_new_location(user, user_signins)
            self._detect_impossible_travel(user, user_signins)
            self._detect_failed_burst(user, user_signins)
            self._detect_off_hours(user, user_signins)
        if self.audit is not None:
            self._detect_malicious_rules()
        self._score_and_sort()
        return self.findings

    # ------------------------------------------------------------------
    def _detect_new_location(self, user: str, df: pd.DataFrame):
        cutoff = df["TimeGenerated"].max() - timedelta(days=BASELINE_LOOKBACK_DAYS)
        baseline = set(df[df["TimeGenerated"] < cutoff]["Location"].unique())
        recent = df[df["TimeGenerated"] >= cutoff]
        for _, row in recent.iterrows():
            if row["Location"] not in baseline and row["ResultType"] == 0:
                self.findings.append(Finding(
                    severity="High", category="New/Unfamiliar Location", user=user,
                    timestamp=str(row["TimeGenerated"]),
                    detail=f"Successful sign-in from '{row['Location']}', not seen in the prior "
                           f"{BASELINE_LOOKBACK_DAYS}-day baseline for this user.",
                    evidence={"IPAddress": row.get("IPAddress"), "Location": row["Location"],
                              "Device": row.get("DeviceDetail_displayName")}
                ))

    # ------------------------------------------------------------------
    def _detect_impossible_travel(self, user: str, df: pd.DataFrame):
        successes = df[df["ResultType"] == 0].reset_index(drop=True)
        for i in range(1, len(successes)):
            prev, cur = successes.iloc[i - 1], successes.iloc[i]
            if prev["Location"] == cur["Location"]:
                continue
            p1 = COUNTRY_CENTROIDS.get(prev["Location"])
            p2 = COUNTRY_CENTROIDS.get(cur["Location"])
            if not p1 or not p2:
                continue
            hours = (cur["TimeGenerated"] - prev["TimeGenerated"]).total_seconds() / 3600
            if hours <= 0:
                continue
            distance = haversine_km(p1, p2)
            speed = distance / hours
            if speed > IMPOSSIBLE_TRAVEL_SPEED_KMH:
                self.findings.append(Finding(
                    severity="Critical", category="Impossible Travel", user=user,
                    timestamp=str(cur["TimeGenerated"]),
                    detail=f"Sign-in from '{cur['Location']}' occurred {hours:.1f}h after a sign-in "
                           f"from '{prev['Location']}' -- implied speed ~{speed:,.0f} km/h "
                           f"(exceeds {IMPOSSIBLE_TRAVEL_SPEED_KMH} km/h threshold).",
                    evidence={"prev_location": prev["Location"], "prev_time": str(prev["TimeGenerated"]),
                              "cur_location": cur["Location"], "cur_time": str(cur["TimeGenerated"]),
                              "implied_speed_kmh": round(speed, 1)}
                ))

    # ------------------------------------------------------------------
    def _detect_failed_burst(self, user: str, df: pd.DataFrame):
        df = df.sort_values("TimeGenerated").reset_index(drop=True)
        for i, row in df.iterrows():
            if row["ResultType"] != 0:
                continue
            window_start = row["TimeGenerated"] - timedelta(minutes=FAILED_BURST_WINDOW_MIN)
            prior = df[(df["TimeGenerated"] >= window_start) & (df["TimeGenerated"] < row["TimeGenerated"])]
            failures = prior[prior["ResultType"] != 0]
            if len(failures) >= FAILED_BURST_THRESHOLD:
                self.findings.append(Finding(
                    severity="High", category="Credential Guessing Pattern", user=user,
                    timestamp=str(row["TimeGenerated"]),
                    detail=f"{len(failures)} failed sign-in attempts within {FAILED_BURST_WINDOW_MIN} "
                           f"minutes immediately preceding a successful authentication.",
                    evidence={"failed_attempts": len(failures),
                              "window_minutes": FAILED_BURST_WINDOW_MIN,
                              "success_time": str(row["TimeGenerated"])}
                ))

    # ------------------------------------------------------------------
    def _detect_off_hours(self, user: str, df: pd.DataFrame):
        for _, row in df[df["ResultType"] == 0].iterrows():
            hour = row["TimeGenerated"].hour
            if hour < WORKING_HOURS_START or hour > WORKING_HOURS_END:
                self.findings.append(Finding(
                    severity="Medium", category="Off-Hours Sign-In", user=user,
                    timestamp=str(row["TimeGenerated"]),
                    detail=f"Successful sign-in at {row['TimeGenerated'].strftime('%H:%M')} local, "
                           f"outside the {WORKING_HOURS_START:02d}:00-{WORKING_HOURS_END:02d}:00 window.",
                    evidence={"hour": hour}
                ))

    # ------------------------------------------------------------------
    def _detect_malicious_rules(self):
        rules = self.audit[self.audit["Operation"].isin(["New-InboxRule", "Set-InboxRule"])]
        for _, row in rules.iterrows():
            params = str(row.get("Parameters", ""))
            if any(k in params for k in SUSPICIOUS_RULE_KEYWORDS):
                self.findings.append(Finding(
                    severity="Critical", category="Malicious Mailbox Rule", user=row["UserId"],
                    timestamp=str(row["TimeGenerated"]),
                    detail="Inbox rule created with forwarding/redirect behavior -- classic "
                           "Business Email Compromise staging technique.",
                    evidence={"Operation": row["Operation"], "Parameters": params,
                              "ClientIP": row.get("ClientIP")}
                ))

    # ------------------------------------------------------------------
    def _score_and_sort(self):
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        self.findings.sort(key=lambda f: (order.get(f.severity, 9), f.timestamp))

    # ------------------------------------------------------------------
    def risk_score(self) -> dict:
        weights = {"Critical": 40, "High": 20, "Medium": 8, "Low": 2}
        by_user: dict[str, int] = {}
        for f in self.findings:
            by_user[f.user] = by_user.get(f.user, 0) + weights.get(f.severity, 0)
        return {u: min(score, 100) for u, score in by_user.items()}

    def to_json(self) -> str:
        return json.dumps([f.__dict__ for f in self.findings], indent=2, default=str)


def main():
    parser = argparse.ArgumentParser(description="Executive Account Guardian - anomaly detector")
    parser.add_argument("--signins", required=True, help="Path to sign-in log CSV")
    parser.add_argument("--audit", help="Path to O365 audit log CSV (optional)")
    parser.add_argument("--watchlist", nargs="*", help="UPNs to treat as VIP/executive accounts")
    parser.add_argument("--out", default="findings.json", help="Output JSON path")
    parser.add_argument("--html", default="report.html", help="Output HTML report path")
    args = parser.parse_args()

    guardian = ExecAccountGuardian(args.signins, args.audit, args.watchlist)
    findings = guardian.run()

    Path(args.out).write_text(guardian.to_json())
    print(f"[+] {len(findings)} findings written to {args.out}")

    from report import generate_html_report
    generate_html_report(findings, guardian.risk_score(), args.html)
    print(f"[+] HTML report written to {args.html}")


if __name__ == "__main__":
    main()
