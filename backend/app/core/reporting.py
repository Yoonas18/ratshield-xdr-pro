from __future__ import annotations

from html import escape
from pathlib import Path

from backend.app.models.schemas import ScanResult

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)
LATEST_JSON = REPORT_DIR / "latest_scan.json"
LATEST_HTML = REPORT_DIR / "latest_scan.html"


def save_json_report(result: ScanResult) -> Path:
    LATEST_JSON.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return LATEST_JSON


def badge(sev: str) -> str:
    return f"<span class='badge {escape(sev)}'>{escape(sev.upper())}</span>"


def save_html_report(result: ScanResult) -> Path:
    rows = []
    for f in result.findings:
        evidence = "<br>".join(f"<b>{escape(e.key)}</b>: {escape(e.value)}" for e in f.evidence)
        recs = "<br>".join(f"&bull; {escape(r)}" for r in f.recommendations)
        mitre = "<br>".join(escape(m) for m in f.mitre)
        tags = " ".join(f"<span class='tag'>{escape(t)}</span>" for t in f.tags)
        rows.append(
            f"""
        <tr><td>{badge(f.severity)}</td><td><b>{f.risk_score}</b><br><small>{f.confidence}% confidence</small></td>
        <td>{escape(f.category)}</td><td><b>{escape(f.title)}</b><p>{escape(f.description)}</p><small>{tags}</small><p class='explain'>{escape(f.explanation)}</p></td>
        <td>{evidence}</td><td>{mitre}</td><td>{recs}</td></tr>
        """
        )

    timeline = "".join(
        f"<li><b>{escape(t.time)}</b> - {escape(t.title)}<br><small>{escape(t.details)}</small></li>"
        for t in result.timeline
    )
    html = f"""<!doctype html><html><head><meta charset='utf-8'><title>RATShield Pro Report</title>
<style>
body{{font-family:Inter,Arial,sans-serif;background:#080b12;color:#e5e7eb;margin:0;padding:28px}}.hero,.card{{background:linear-gradient(135deg,#111827,#0f172a);border:1px solid #243042;border-radius:22px;padding:24px;margin-bottom:18px;box-shadow:0 20px 60px #0007}}h1{{margin:0;font-size:34px}}.muted,small{{color:#94a3b8}}.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}}.metric{{background:#0b1220;border:1px solid #1e293b;border-radius:16px;padding:16px}}.num{{font-size:28px;font-weight:900}}table{{width:100%;border-collapse:collapse;background:#0b1220;border-radius:18px;overflow:hidden}}th,td{{border-bottom:1px solid #1e293b;padding:12px;text-align:left;vertical-align:top;font-size:13px}}th{{background:#111827;color:#cbd5e1}}.badge,.tag{{display:inline-block;border-radius:999px;padding:5px 9px;font-size:11px;font-weight:800}}.critical{{background:#7f1d1d;color:#fecaca}}.high{{background:#991b1b;color:#fee2e2}}.medium{{background:#92400e;color:#ffedd5}}.low{{background:#164e63;color:#cffafe}}.info{{background:#334155;color:#e2e8f0}}.tag{{background:#1e293b;color:#cbd5e1;margin:2px}}.explain{{color:#cbd5e1}}
</style></head><body><section class='hero'><h1>RATShield XDR Pro - Investigation Report</h1><p class='muted'>{escape(result.verdict)}</p></section>
<section class='grid'><div class='metric'><span class='muted'>Target</span><div>{escape(result.target)}</div></div><div class='metric'><span class='muted'>Platform</span><div>{escape(result.platform)}</div></div><div class='metric'><span class='muted'>Findings</span><div class='num'>{result.total_findings}</div></div><div class='metric'><span class='muted'>Highest Risk</span><div class='num'>{result.highest_risk}</div></div><div class='metric'><span class='muted'>Scan ID</span><div>{escape(result.scan_id[:8])}</div></div></section>
<section class='card'><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Risk</th><th>Category</th><th>Finding</th><th>Evidence</th><th>MITRE</th><th>Recommendations</th></tr></thead><tbody>{''.join(rows)}</tbody></table></section>
<section class='card'><h2>Timeline</h2><ul>{timeline}</ul></section></body></html>"""
    LATEST_HTML.write_text(html, encoding="utf-8")
    return LATEST_HTML


def save_reports(result: ScanResult) -> None:
    save_json_report(result)
    save_html_report(result)
