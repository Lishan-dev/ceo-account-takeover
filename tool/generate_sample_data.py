"""
Generates realistic-shaped, fully synthetic Entra ID sign-in log and O365
audit log CSVs matching the CEO Account Takeover case study, so the detector
can be demoed end-to-end before pointing it at real exported tenant data.

Column schema matches what you'd get exporting SigninLogs / OfficeActivity
from Log Analytics, so swapping in a real export requires no code changes.
"""

import csv
import random
from datetime import datetime, timedelta

random.seed(7)

USERS = [
    "ceo@fictionalcorp.com",
    "cfo@fictionalcorp.com",
    "analyst1@fictionalcorp.com",
    "analyst2@fictionalcorp.com",
]

BASE_DAY = datetime(2026, 8, 10, 9, 0)


def normal_history(user: str, days: int = 45) -> list[dict]:
    rows = []
    for d in range(days):
        day = BASE_DAY - timedelta(days=days - d)
        for _ in range(random.randint(1, 3)):
            t = day.replace(hour=random.randint(7, 18), minute=random.randint(0, 59))
            rows.append({
                "TimeGenerated": t.isoformat(),
                "UserPrincipalName": user,
                "IPAddress": f"10.20.{random.randint(0,255)}.{random.randint(0,255)}",
                "Location": "United States",
                "AppDisplayName": "Office 365 Exchange Online",
                "ResultType": 0,
                "ResultDescription": "Success",
                "DeviceDetail_displayName": "CORP-LAPTOP-01",
                "DeviceDetail_trustType": "Azure AD joined",
                "RiskLevelDuringSignIn": "none",
            })
    return rows


def ceo_incident_rows() -> list[dict]:
    """The simulated 3AM takeover scenario from the case study."""
    rows = []
    incident_day = BASE_DAY.replace(hour=0, minute=0)

    # 02:47 - failed attempts
    for i in range(6):
        t = incident_day.replace(hour=2, minute=47) + timedelta(minutes=i)
        rows.append({
            "TimeGenerated": t.isoformat(),
            "UserPrincipalName": "ceo@fictionalcorp.com",
            "IPAddress": "185.220.101.47",
            "Location": "Romania",
            "AppDisplayName": "Office 365 Exchange Online",
            "ResultType": 50126,
            "ResultDescription": "Invalid username or password",
            "DeviceDetail_displayName": "Unknown",
            "DeviceDetail_trustType": "Unregistered",
            "RiskLevelDuringSignIn": "medium",
        })

    # 02:58 - successful auth
    rows.append({
        "TimeGenerated": incident_day.replace(hour=2, minute=58).isoformat(),
        "UserPrincipalName": "ceo@fictionalcorp.com",
        "IPAddress": "185.220.101.47",
        "Location": "Romania",
        "AppDisplayName": "Office 365 Exchange Online",
        "ResultType": 0,
        "ResultDescription": "Success",
        "DeviceDetail_displayName": "Unknown",
        "DeviceDetail_trustType": "Unregistered",
        "RiskLevelDuringSignIn": "high",
    })

    # A legitimate-looking US sign-in a few hours later (same day) to show
    # impossible travel logic when paired with the prior event.
    rows.append({
        "TimeGenerated": incident_day.replace(hour=8, minute=10).isoformat(),
        "UserPrincipalName": "ceo@fictionalcorp.com",
        "IPAddress": "10.20.1.5",
        "Location": "United States",
        "AppDisplayName": "Office 365 Exchange Online",
        "ResultType": 0,
        "ResultDescription": "Success",
        "DeviceDetail_displayName": "CORP-LAPTOP-01",
        "DeviceDetail_trustType": "Azure AD joined",
        "RiskLevelDuringSignIn": "none",
    })

    return rows


def audit_rows() -> list[dict]:
    incident_day = BASE_DAY.replace(hour=0, minute=0)
    return [
        {
            "TimeGenerated": incident_day.replace(hour=3, minute=20).isoformat(),
            "Operation": "New-InboxRule",
            "UserId": "ceo@fictionalcorp.com",
            "ClientIP": "185.220.101.47",
            "Parameters": "Name=Test-ExternalForward; ForwardTo=external.testaddress@outlook.com; StopProcessingRules=False",
        },
        {
            "TimeGenerated": incident_day.replace(hour=9, minute=15).isoformat(),
            "Operation": "Set-InboxRule",
            "UserId": "analyst1@fictionalcorp.com",
            "ClientIP": "10.20.4.9",
            "Parameters": "Name=MoveNewsletters; MoveToFolder=Newsletters",
        },
    ]


def write_csv(path: str, rows: list[dict], fieldnames: list[str]):
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    signin_rows = []
    for u in USERS:
        signin_rows += normal_history(u)
    signin_rows += ceo_incident_rows()
    signin_rows.sort(key=lambda r: r["TimeGenerated"])

    signin_fields = ["TimeGenerated", "UserPrincipalName", "IPAddress", "Location",
                      "AppDisplayName", "ResultType", "ResultDescription",
                      "DeviceDetail_displayName", "DeviceDetail_trustType", "RiskLevelDuringSignIn"]
    write_csv("sample_signins.csv", signin_rows, signin_fields)

    audit_fields = ["TimeGenerated", "Operation", "UserId", "ClientIP", "Parameters"]
    write_csv("sample_audit.csv", audit_rows(), audit_fields)

    print(f"Wrote sample_signins.csv ({len(signin_rows)} rows) and sample_audit.csv ({len(audit_rows())} rows)")
