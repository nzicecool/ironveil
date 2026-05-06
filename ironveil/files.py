"""
IronVeil — Language detection and file utilities.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

LANGUAGE_MARKERS: Dict[str, Tuple[str, ...]] = {
    "python": ("requirements.txt", "setup.py", "pyproject.toml", "Pipfile"),
    "typescript": ("tsconfig.json",),
    "javascript": ("package.json",),
    "java": ("pom.xml", "build.gradle", "build.gradle.kts"),
    "php": ("composer.json",),
    "go": ("go.mod",),
}

# Mapping from extension to language (for file-level detection)
EXT_MAP: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".php": "php",
    ".go": "go",
}

SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", ".next", ".nuxt", "target", "vendor",
    ".tox", "eggs", "*.egg-info", ".mypy_cache", ".pytest_cache",
})


def detect_language(repo_dir: str) -> Optional[str]:
    """Detect the primary language of a repository."""
    # TypeScript takes priority over JavaScript (tsconfig implies JS too)
    for lang in ("typescript", "python", "java", "php", "go", "javascript"):
        for marker in LANGUAGE_MARKERS.get(lang, ()):
            if os.path.exists(os.path.join(repo_dir, marker)):
                return lang
    return None


def collect_files(repo_dir: str, language: Optional[str] = None) -> List[str]:
    """Collect source files matching the detected or specified language."""
    target_exts = set()
    if language:
        for ext, lang in EXT_MAP.items():
            if lang == language:
                target_exts.add(ext)
    else:
        target_exts = set(EXT_MAP.keys())

    files = []
    for root, dirs, filenames in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if Path(fn).suffix.lower() in target_exts:
                files.append(os.path.join(root, fn))
    return files


def risk_keywords() -> Dict[str, List[str]]:
    """Keywords for file risk prioritization."""
    return {
        "high": ["auth", "login", "password", "token", "session", "payment", "stripe", "paypal", "secret", "credential", "crypto"],
        "medium": ["validate", "sanitize", "filter", "escape", "sql", "query", "database", "middleware", "handler"],
        "low": ["config", "model", "controller", "service", "util", "helper", "const"],
    }


def prioritize_files(repo_dir: str) -> List[str]:
    """Return file paths sorted by risk priority (high → medium → low)."""
    keywords = risk_keywords()
    buckets: Dict[str, List[str]] = {"high": [], "medium": [], "low": []}

    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in files:
            if Path(fn).suffix.lower() not in EXT_MAP:
                continue
            path = os.path.join(root, fn)
            name_lower = fn.lower()
            for level, kws in keywords.items():
                if any(kw in name_lower for kw in kws):
                    buckets[level].append(path)
                    break

    seen = set()
    result = []
    for level in ("high", "medium", "low"):
        for f in buckets[level]:
            if f not in seen:
                seen.add(f)
                result.append(f)
    return result
