"""
IronVeil — Report generation (JSON, HTML, Markdown).
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional


def build_report(
    repo_name: str,
    language: Optional[str],
    findings: Dict[str, Any],
    llm_results: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a structured scan report."""
    vulns = findings.get("vulnerabilities", [])
    secrets = findings.get("secrets", [])
    quality = findings.get("issues", [])
    semgrep_hits = findings.get("findings", [])
    llm_findings = llm_results.get("findings", []) if llm_results else []

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def _count(items, severity_field="severity"):
        for item in items:
            sev = str(item.get(severity_field, "info")).lower()
            if sev in summary:
                summary[sev] += 1
            else:
                summary["info"] += 1

    # Secrets are always critical
    summary["critical"] += len(secrets)
    _count(vulns)
    _count(quality)
    _count(semgrep_hits, "extra")
    _count(llm_findings)

    return {
        "tool": "ironveil",
        "version": "1.0.0",
        "repository": repo_name,
        "language": language,
        "scan_date": datetime.now().isoformat(),
        "summary": summary,
        "findings": {
            "vulnerabilities": vulns,
            "secrets": secrets,
            "code_quality": quality,
            "semgrep": semgrep_hits,
            "llm_analysis": llm_findings,
        },
        "llm_token_usage": llm_results.get("token_usage") if llm_results else None,
    }


def save_json(report: Dict[str, Any], results_dir: str) -> str:
    """Save report as JSON."""
    os.makedirs(results_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    repo = report["repository"].replace("/", "_")
    path = os.path.join(results_dir, f"ironveil_{repo}_{ts}.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    return path


def format_markdown(report: Dict[str, Any]) -> str:
    """Format report as Markdown."""
    lines = [
        f"# 🛡️ IronVeil Scan Report",
        f"",
        f"**Repository:** `{report['repository']}`",
        f"**Language:** {report.get('language') or 'Unknown'}",
        f"**Date:** {report['scan_date']}",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}[sev]
        lines.append(f"| {emoji} {sev.title()} | {report['summary'][sev]} |")

    total = sum(report["summary"].values())
    lines.append(f"| **Total** | **{total}** |")

    findings = report.get("findings", {})
    for category, items in findings.items():
        if items:
            lines.append(f"\n## {category.replace('_', ' ').title()}\n")
            for i, item in enumerate(items, 1):
                if isinstance(item, dict):
                    title = item.get("title") or item.get("message") or item.get("check_id") or f"Finding {i}"
                    sev = item.get("severity", "info")
                    lines.append(f"**{i}. [{sev.upper()}] {title}**")
                    if item.get("description"):
                        lines.append(f"  {item['description']}")
                    if item.get("fix_suggestion"):
                        lines.append(f"  💡 *Fix:* {item['fix_suggestion']}")
                    if item.get("file"):
                        line_num = f":{item['line']}" if item.get('line') else ""
                    lines.append(f"  📄 `{item['file']}`{line_num}")
                    lines.append("")

    # Token usage
    tu = report.get("llm_token_usage")
    if tu and tu.get("total_tokens"):
        lines.append(f"\n## LLM Token Usage\n")
        lines.append(f"- Input: {tu['input_tokens']:,} tokens")
        lines.append(f"- Output: {tu['output_tokens']:,} tokens")
        lines.append(f"- Total: {tu['total_tokens']:,} tokens")
        lines.append(f"- Est. Cost: ${tu['estimated_cost_usd']:.4f}")
        lines.append(f"- Model: {tu.get('model', 'N/A')}")

    return "\n".join(lines)


def format_html(report: Dict[str, Any]) -> str:
    """Format report as a simple HTML page."""
    md = format_markdown(report)
    # Minimal markdown → HTML conversion
    html_lines = ["<!DOCTYPE html><html><head><meta charset='utf-8'>",
                  "<title>IronVeil Report</title>",
                  "<style>body{font-family:system-ui;max-width:900px;margin:2em auto;padding:0 1em;"
                  "background:#0d1117;color:#c9d1d9;} table{border-collapse:collapse;width:100%}"
                  "th,td{border:1px solid #30363d;padding:8px 12px;text-align:left}"
                  "th{background:#161b22} code{background:#161b22;padding:2px 6px;border-radius:4px}"
                  "h1{color:#58a6ff} h2{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:4px}"
                  "strong{color:#f0f6fc}</style></head><body>"]

    for line in md.splitlines():
        if line.startswith("# "):
            html_lines.append(f"<h1>{line[2:]}</h1>")
        elif line.startswith("## "):
            html_lines.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("| ") and "---" not in line:
            cells = [c.strip() for c in line.split("|")[1:-1]]
            row = "".join(f"<td>{c}</td>" for c in cells)
            html_lines.append(f"<tr>{row}</tr>")
        elif line.startswith("|"):
            pass  # skip separator
        elif line.startswith("**"):
            html_lines.append(f"<p><strong>{line}</strong></p>")
        elif line.startswith("  "):
            html_lines.append(f"<p style='margin-left:1em'>{line.strip()}</p>")
        elif line.strip():
            html_lines.append(f"<p>{line}</p>")

    html_lines.append("</body></html>")
    return "\n".join(html_lines)
