"""Generates a self-contained HTML incident report from Finding objects."""

from __future__ import annotations
from datetime import datetime

SEVERITY_COLOR = {
    "Critical": "#7a1616",
    "High": "#b3401f",
    "Medium": "#b3821f",
    "Low": "#3a6b3a",
}

TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Executive Account Guardian - Findings Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f1115; color:#e8e8e8; margin:0; padding:32px; }}
  h1 {{ font-size: 22px; margin-bottom:4px; }}
  .subtitle {{ color:#9aa0a6; margin-bottom:24px; font-size:13px; }}
  .risk-cards {{ display:flex; gap:16px; margin-bottom:28px; flex-wrap:wrap; }}
  .risk-card {{ background:#181b21; border:1px solid #2a2e36; border-radius:8px; padding:14px 18px; min-width:180px; }}
  .risk-card .user {{ font-weight:600; font-size:14px; }}
  .risk-card .score {{ font-size:26px; font-weight:700; margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; margin-top:8px; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #22262e; font-size:13px; vertical-align:top; }}
  th {{ color:#9aa0a6; font-weight:600; text-transform:uppercase; font-size:11px; letter-spacing:0.04em; }}
  .sev {{ display:inline-block; padding:2px 8px; border-radius:4px; color:white; font-size:11px; font-weight:600; }}
  .evidence {{ color:#9aa0a6; font-family: ui-monospace, Menlo, monospace; font-size:11px; white-space:pre-wrap; }}
  .empty {{ color:#9aa0a6; padding:24px; text-align:center; }}
</style>
</head>
<body>
  <h1>Executive Account Guardian &mdash; Findings Report</h1>
  <div class="subtitle">Generated {generated_at} &middot; {count} finding(s) across {user_count} account(s)</div>

  <div class="risk-cards">
    {risk_cards}
  </div>

  <table>
    <thead>
      <tr><th>Severity</th><th>Category</th><th>User</th><th>Timestamp</th><th>Detail</th><th>Evidence</th></tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</body>
</html>
"""

ROW_TEMPLATE = """<tr>
  <td><span class="sev" style="background:{color}">{severity}</span></td>
  <td>{category}</td>
  <td>{user}</td>
  <td>{timestamp}</td>
  <td>{detail}</td>
  <td class="evidence">{evidence}</td>
</tr>"""

CARD_TEMPLATE = """<div class="risk-card">
  <div class="user">{user}</div>
  <div class="score" style="color:{color}">{score}/100</div>
</div>"""


def _score_color(score: int) -> str:
    if score >= 60:
        return "#e05a3a"
    if score >= 30:
        return "#e0b93a"
    return "#5ac07a"


def generate_html_report(findings, risk_scores: dict, out_path: str):
    rows = "\n".join(
        ROW_TEMPLATE.format(
            color=SEVERITY_COLOR.get(f.severity, "#555"),
            severity=f.severity,
            category=f.category,
            user=f.user,
            timestamp=f.timestamp,
            detail=f.detail,
            evidence="\n".join(f"{k}: {v}" for k, v in f.evidence.items()),
        )
        for f in findings
    ) or '<tr><td colspan="6" class="empty">No findings -- no anomalies detected against current thresholds.</td></tr>'

    cards = "\n".join(
        CARD_TEMPLATE.format(user=u, score=s, color=_score_color(s))
        for u, s in sorted(risk_scores.items(), key=lambda kv: -kv[1])
    ) or '<div class="empty">No scored accounts.</div>'

    users = {f.user for f in findings}
    html = TEMPLATE.format(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        count=len(findings),
        user_count=len(users),
        risk_cards=cards,
        rows=rows,
    )
    with open(out_path, "w") as fh:
        fh.write(html)
