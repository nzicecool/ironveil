#!/usr/bin/env python3
"""
IronVeil — CLI entry point.

Usage:
    ironveil scan https://github.com/user/repo
    ironveil scan ./local/repo --llm --llm-max-files 10
    ironveil scan https://github.com/user/repo --output html --config ./my-config.json
    ironveil init-config
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, Any

from . import __version__
from .config import load_config
from .files import collect_files, detect_language, prioritize_files
from .llm import analyze_repository
from .report import build_report, format_html, format_markdown, save_json
from .scanners import (
    run_bandit,
    run_eslint,
    run_pylint,
    run_semgrep,
    run_snyk,
    run_trufflehog,
)


def _clone(repo_url: str, dest: str) -> bool:
    print(f"📥 Cloning {repo_url} ...")
    try:
        subprocess.run(["git", "clone", repo_url, dest], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        print("❌ Clone failed. Check the URL and access credentials.")
        return False


def _print_banner():
    print()
    print("  ╔═══════════════════════════════════════╗")
    print("  ║          🛡️  I R O N V E I L          ║")
    print("  ║     Security-first code scanner       ║")
    print(f"  ║            v{__version__}                    ║")
    print("  ╚═══════════════════════════════════════╝")
    print()


def cmd_scan(args):
    """Run a scan on a repository."""
    _print_banner()

    config = load_config(getattr(args, "config", ""))

    # Override LLM settings from CLI flags
    if args.llm:
        config["llm"]["enabled"] = True
    if args.model:
        config["llm"]["model"] = args.model
    if args.llm_max_files:
        config["llm"]["max_files"] = args.llm_max_files

    # Determine if local dir or remote URL
    is_local = os.path.isdir(args.repo)
    cleanup = False

    if is_local:
        repo_dir = os.path.abspath(args.repo)
        repo_name = os.path.basename(repo_dir)
    else:
        repo_dir = tempfile.mkdtemp(prefix="ironveil-")
        repo_name = args.repo.rstrip("/").split("/")[-1].replace(".git", "")
        if not _clone(args.repo, repo_dir):
            sys.exit(1)
        cleanup = True

    try:
        language = detect_language(repo_dir)
        print(f"🔎 Language: {language or 'Unknown (running generic scanners)'}")
        print()

        # ── Traditional scanners ──
        findings: Dict[str, Any] = {}

        print("🔐 Running TruffleHog (secret detection)...")
        th = run_trufflehog(repo_dir, config)
        findings["secrets"] = th.get("secrets", [])
        print(f"   → {len(findings['secrets'])} potential secrets\n")

        print("🔍 Running Semgrep (pattern matching)...")
        sg = run_semgrep(repo_dir, config)
        findings["findings"] = sg.get("findings", [])
        print(f"   → {len(findings['findings'])} findings\n")

        print("🛡️  Running Snyk (dependency CVEs)...")
        sk = run_snyk(repo_dir, config)
        findings["vulnerabilities"] = sk.get("vulnerabilities", [])
        print(f"   → {len(findings['vulnerabilities'])} vulnerabilities\n")

        if language == "python":
            print("🐍 Running Bandit (Python security)...")
            bt = run_bandit(repo_dir, config)
            findings["issues"] = findings.get("issues", []) + bt.get("issues", [])
            print(f"   → {len(bt.get('issues', []))} issues\n")

            print("🐍 Running Pylint (Python quality)...")
            py_files = collect_files(repo_dir, "python")
            pl = run_pylint(repo_dir, config, py_files)
            findings["issues"] = findings.get("issues", []) + pl.get("issues", [])
            print(f"   → {len(pl.get('issues', []))} issues\n")

        elif language in ("javascript", "typescript"):
            print("💻 Running ESLint (JS/TS quality)...")
            es = run_eslint(repo_dir, config)
            findings["issues"] = es.get("issues", [])
            print(f"   → {len(findings['issues'])} issues\n")

        # ── LLM deep analysis ──
        llm_results = None
        if config["llm"]["enabled"]:
            print("🤖 Running LLM deep analysis...")
            prioritized = prioritize_files(repo_dir)
            max_f = config["llm"]["max_files"]
            print(f"   🎯 {len(prioritized)} high-risk files found, analyzing top {max_f}")
            llm_results = analyze_repository(repo_dir, prioritized, config, max_files=max_f)
            print(f"   ✅ {llm_results['analyzed_count']} files analyzed, {len(llm_results['findings'])} findings")
            tu = llm_results.get("token_usage", {})
            if tu.get("total_tokens"):
                print(f"   📊 {tu['total_tokens']:,} tokens, ~${tu['estimated_cost_usd']:.4f}")
            print()
        else:
            print("⏭️  LLM analysis skipped (use --llm to enable)\n")

        # ── Build report ──
        report = build_report(repo_name, language, findings, llm_results)

        # Print summary
        print("═" * 50)
        print("  SCAN SUMMARY")
        print("═" * 50)
        for sev in ("critical", "high", "medium", "low", "info"):
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}[sev]
            print(f"  {emoji} {sev.title():10s} {report['summary'][sev]}")
        print("═" * 50)

        # Save output
        results_dir = config["results_dir"]
        json_path = save_json(report, results_dir)
        print(f"\n💾 JSON → {json_path}")

        output = args.output
        if output in ("markdown", "md") or "markdown" in output:
            md_path = json_path.replace(".json", ".md")
            with open(md_path, "w") as f:
                f.write(format_markdown(report))
            print(f"📝 Markdown → {md_path}")

        if output in ("html",) or "html" in output:
            html_path = json_path.replace(".json", ".html")
            with open(html_path, "w") as f:
                f.write(format_html(report))
            print(f"🌐 HTML → {html_path}")

        print("\n✅ Scan complete.")

    finally:
        if cleanup:
            shutil.rmtree(repo_dir, ignore_errors=True)


def cmd_init_config(args):
    """Generate a starter config file."""
    import json
    from .config import DEFAULTS

    path = args.output or "ironveil.json"
    with open(path, "w") as f:
        json.dump(DEFAULTS, f, indent=2)
    print(f"✅ Config template written to {path}")
    print("   Edit it with your API keys and preferences.")


def main():
    parser = argparse.ArgumentParser(
        prog="ironveil",
        description="🛡️ IronVeil — Security-first code scanner",
    )
    parser.add_argument("--version", action="version", version=f"ironveil {__version__}")
    sub = parser.add_subparsers(dest="command")

    # ── scan ──
    scan = sub.add_parser("scan", help="Scan a repository")
    scan.add_argument("repo", help="Repository URL or local directory path")
    scan.add_argument("--output", "-o", default="json",
                      help="Output format: json (default), markdown, html, or comma-separated")
    scan.add_argument("--config", "-c", default="", help="Path to ironveil.json config")
    scan.add_argument("--llm", action="store_true", help="Enable LLM deep analysis")
    scan.add_argument("--llm-max-files", type=int, default=5, help="Max files for LLM analysis")
    scan.add_argument("--model", "-m", default="", help="LLM model (gpt-4, claude-3-sonnet, etc.)")
    scan.add_argument("--severity", default="high,critical", help="Min severity filter")

    # ── init-config ──
    init = sub.add_parser("init-config", help="Generate a starter config file")
    init.add_argument("--output", "-o", default="ironveil.json", help="Output path")

    args = parser.parse_args()
    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "init-config":
        cmd_init_config(args)
    else:
        parser.print_help()
