"""
IronVeil — OpenClaw skill integration.

When installed as an OpenClaw skill, this module registers the scanner
so it can be triggered via cron, heartbeat, or direct command.

The tool works identically outside OpenClaw — this module is purely optional.
"""

import json
import os
import sys
from typing import Any, Dict

# Import core (works standalone)
from .cli import cmd_scan
from .config import load_config


def register() -> Dict[str, Any]:
    """Register IronVeil as an OpenClaw skill."""
    return {
        "name": "ironveil",
        "description": "Security-first code scanner. Static analysis + LLM deep review.",
        "version": "1.0.0",
        "commands": {
            "scan": {
                "description": "Scan a Git repository for security issues",
                "args": ["repo_url_or_path"],
                "kwargs": {
                    "llm": {"type": "bool", "default": False, "help": "Enable LLM analysis"},
                    "output": {"type": "str", "default": "json", "help": "Output format"},
                },
            },
        },
    }


def scan_for_openclaw(repo: str, llm: bool = False, output: str = "json") -> str:
    """
    Convenience method for OpenClaw agents to call.
    Returns the JSON report path.
    """
    import argparse

    args = argparse.Namespace(
        command="scan",
        repo=repo,
        output=output,
        config="",
        llm=llm,
        llm_max_files=5,
        model="",
        severity="high,critical",
    )
    # Capture the output by redirecting stdout temporarily
    # The scan will still print to console but return the report path
    cmd_scan(args)

    config = load_config()
    return config["results_dir"]
