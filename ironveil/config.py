"""
IronVeil — Configuration loader.

Searches for config in this order:
1. Path passed via --config
2. IRONVEIL_CONFIG env var
3. ./ironveil.json in current directory
4. ~/.ironveil.json
5. Built-in defaults
"""

import json
import os
from pathlib import Path
from typing import Any, Dict

DEFAULTS: Dict[str, Any] = {
    "scanners": {
        "snyk": {"enabled": False, "api_key": "", "severity_threshold": "high"},
        "trufflehog": {"enabled": True, "entropy_threshold": 4.5},
        "semgrep": {"enabled": True, "rules_path": ""},
        "pylint": {"enabled": True},
        "eslint": {"enabled": True},
        "bandit": {"enabled": True},
    },
    "languages": ["python", "javascript", "typescript", "java", "php", "go"],
    "results_dir": "",
    "output": {
        "dashboard": False,
        "dashboard_url": "",
        "email": False,
        "email_recipients": [],
    },
    "ignored_rules": {},
    "llm": {
        "enabled": False,
        "provider": "openai",
        "model": "gpt-4",
        "max_files": 5,
        "api_key": "",
        "base_url": "",
    },
}


def _default_results_dir() -> str:
    """Portable results directory."""
    # If running inside OpenClaw, use workspace
    openclaw_ws = os.environ.get("OPENCLAW_WORKSPACE")
    if openclaw_ws:
        return os.path.join(openclaw_ws, "ironveil", "results")
    return os.path.join(str(Path.home()), ".ironveil", "results")


def _resolve_results_dir(cfg: Dict[str, Any]) -> str:
    rd = cfg.get("results_dir", "")
    if rd:
        return os.path.expanduser(rd)
    return _default_results_dir()


def _search_config_path() -> str:
    """Find config file on disk."""
    candidates = [
        os.path.join(os.getcwd(), "ironveil.json"),
        os.path.expanduser("~/.ironveil.json"),
    ]
    env_path = os.environ.get("IRONVEIL_CONFIG", "")
    if env_path:
        candidates.insert(0, env_path)
    for p in candidates:
        if os.path.isfile(p):
            return p
    return ""


def load_config(config_path: str = "") -> Dict[str, Any]:
    """Load config with cascading fallbacks."""
    import copy
    cfg = copy.deepcopy(DEFAULTS)

    path = config_path or _search_config_path()
    if path and os.path.isfile(path):
        with open(path, "r") as f:
            user_cfg = json.load(f)
        _deep_merge(cfg, user_cfg)

    cfg["results_dir"] = _resolve_results_dir(cfg)
    return cfg


def _deep_merge(base: dict, override: dict) -> None:
    """Merge override into base (in-place), preserving nested dicts."""
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
