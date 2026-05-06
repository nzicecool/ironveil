"""
IronVeil — Scanner runners (Snyk, TruffleHog, Semgrep, Pylint, ESLint, Bandit).

Each runner returns a dict of findings, regardless of whether the tool is installed.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def run_trufflehog(repo_dir: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Run TruffleHog secret detection."""
    if not config.get("scanners", {}).get("trufflehog", {}).get("enabled", True):
        return {"secrets": [], "skipped": True, "reason": "disabled"}

    if not _tool_available("trufflehog"):
        return {"secrets": [], "skipped": True, "reason": "not installed"}

    try:
        result = subprocess.run(
            ["trufflehog", "filesystem", "--json", repo_dir],
            capture_output=True, text=True, timeout=120,
        )
        secrets = []
        for line in result.stdout.strip().splitlines():
            try:
                secrets.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return {"secrets": secrets}
    except subprocess.TimeoutExpired:
        return {"secrets": [], "error": "timeout"}
    except Exception as e:
        return {"secrets": [], "error": str(e)}


def run_semgrep(repo_dir: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Run Semgrep security rules."""
    if not config.get("scanners", {}).get("semgrep", {}).get("enabled", True):
        return {"findings": [], "skipped": True, "reason": "disabled"}

    if not _tool_available("semgrep"):
        return {"findings": [], "skipped": True, "reason": "not installed"}

    rules_path = config.get("scanners", {}).get("semgrep", {}).get("rules_path", "")
    cmd = ["semgrep", "--json", "--config", "auto"]
    if rules_path:
        cmd.extend(["--config", rules_path])
    cmd.append(repo_dir)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        data = json.loads(result.stdout) if result.stdout else {}
        findings = data.get("results", [])
        return {"findings": findings}
    except subprocess.TimeoutExpired:
        return {"findings": [], "error": "timeout"}
    except Exception as e:
        return {"findings": [], "error": str(e)}


def run_pylint(repo_dir: str, config: Dict[str, Any], python_files: List[str]) -> Dict[str, Any]:
    """Run Pylint for Python code quality."""
    if not config.get("scanners", {}).get("pylint", {}).get("enabled", True):
        return {"issues": [], "skipped": True, "reason": "disabled"}

    if not _tool_available("pylint") or not python_files:
        return {"issues": [], "skipped": True, "reason": "not installed or no files"}

    try:
        result = subprocess.run(
            ["pylint", "--output-format=json", "--disable=all", "--enable=C,R,E,F,W"]
            + python_files[:20],
            capture_output=True, text=True, timeout=120,
        )
        try:
            return {"issues": json.loads(result.stdout)}
        except json.JSONDecodeError:
            return {"issues": []}
    except subprocess.TimeoutExpired:
        return {"issues": [], "error": "timeout"}
    except Exception as e:
        return {"issues": [], "error": str(e)}


def run_bandit(repo_dir: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Run Bandit for Python security issues."""
    if not config.get("scanners", {}).get("bandit", {}).get("enabled", True):
        return {"issues": [], "skipped": True, "reason": "disabled"}

    if not _tool_available("bandit"):
        return {"issues": [], "skipped": True, "reason": "not installed"}

    try:
        result = subprocess.run(
            ["bandit", "-r", repo_dir, "-f", "json"],
            capture_output=True, text=True, timeout=120,
        )
        data = json.loads(result.stdout) if result.stdout else {}
        return {"issues": data.get("results", [])}
    except subprocess.TimeoutExpired:
        return {"issues": [], "error": "timeout"}
    except Exception as e:
        return {"issues": [], "error": str(e)}


def run_eslint(repo_dir: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Run ESLint for JS/TS quality."""
    if not config.get("scanners", {}).get("eslint", {}).get("enabled", True):
        return {"issues": [], "skipped": True, "reason": "disabled"}

    if not _tool_available("eslint"):
        return {"issues": [], "skipped": True, "reason": "not installed"}

    try:
        result = subprocess.run(
            ["eslint", ".", "--format", "json"],
            cwd=repo_dir, capture_output=True, text=True, timeout=120,
        )
        try:
            return {"issues": json.loads(result.stdout)}
        except json.JSONDecodeError:
            return {"issues": []}
    except subprocess.TimeoutExpired:
        return {"issues": [], "error": "timeout"}
    except Exception as e:
        return {"issues": [], "error": str(e)}


def run_snyk(repo_dir: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """Run Snyk dependency scan."""
    snyk_cfg = config.get("scanners", {}).get("snyk", {})
    if not snyk_cfg.get("enabled", False):
        return {"vulnerabilities": [], "skipped": True, "reason": "disabled"}

    api_key = snyk_cfg.get("api_key", "")
    if not api_key or not _tool_available("snyk"):
        return {"vulnerabilities": [], "skipped": True, "reason": "not configured or not installed"}

    env = os.environ.copy()
    env["SNYK_TOKEN"] = api_key
    threshold = snyk_cfg.get("severity_threshold", "high")

    try:
        result = subprocess.run(
            ["snyk", "test", "--json", f"--severity-threshold={threshold}"],
            cwd=repo_dir, env=env, capture_output=True, text=True, timeout=60,
        )
        try:
            data = json.loads(result.stdout)
            return {"vulnerabilities": data.get("vulnerabilities", [])}
        except json.JSONDecodeError:
            return {"vulnerabilities": []}
    except subprocess.TimeoutExpired:
        return {"vulnerabilities": [], "error": "timeout"}
    except Exception as e:
        return {"vulnerabilities": [], "error": str(e)}
