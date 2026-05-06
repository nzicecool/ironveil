<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue" alt="version">
  <img src="https://img.shields.io/badge/python-3.10+-blue" alt="python">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="license">
</p>

<h1 align="center">🛡️ IronVeil</h1>

<p align="center"><strong>Security-first code scanner.</strong><br>
Static analysis + optional LLM-powered deep review for Python, JS/TS, Java, PHP, and Go.</p>

---

## What It Does

IronVeil scans Git repositories for security vulnerabilities, hardcoded secrets, code quality issues, and best practice violations. It combines **fast traditional tools** with **optional LLM-based deep analysis** for comprehensive coverage.

| Layer | What It Finds | Speed |
|-------|---------------|-------|
| **TruffleHog** | Hardcoded secrets, API keys, credentials | ⚡ Seconds |
| **Semgrep** | SQL injection, XSS, auth bypass patterns | ⚡ Seconds |
| **Snyk** | Dependency CVEs, known vulnerabilities | ⚡ Seconds |
| **Bandit** | Python-specific security issues | ⚡ Seconds |
| **Pylint / ESLint** | Code quality, maintainability | ⚡ Seconds |
| **LLM Analysis** | Business logic flaws, architectural issues, auth bypass | 🧠 Minutes |

## Quick Start

### Install

```bash
pip install ironveil
```

Or install with all optional tools:

```bash
pip install ironveil[all]
```

### Scan a Repository

```bash
# Public repo — traditional scanners only (fast)
ironveil scan https://github.com/user/repo

# Local directory
ironveil scan ./my-project

# Enable LLM deep analysis (requires API key)
ironveil scan https://github.com/user/repo --llm

# LLM with specific model and more files
ironveil scan https://github.com/user/repo --llm --llm-max-files 10 --model gpt-4o

# Generate HTML report
ironveil scan https://github.com/user/repo --output html
```

### Configure LLM

Set your API key as an environment variable:

```bash
# OpenAI-compatible providers
export OPENAI_API_KEY="sk-..."

# Or use IronVeil-specific env var
export IRONVEIL_LLM_KEY="sk-..."

# For custom endpoints (e.g. local LLM, Azure, etc.)
export IRONVEIL_LLM_BASE_URL="http://localhost:11434/v1"
```

Or create a config file:

```bash
ironveil init-config
# Edit ironveil.json with your settings
ironveil scan ./my-project --config ironveil.json --llm
```

## Features

### 🔐 Secret Detection
Scans every file for accidentally committed API keys, passwords, tokens, and certificates using TruffleHog.

### 🎯 Pattern Matching
Runs Semgrep with the `auto` ruleset for known vulnerability patterns — SQL injection, XSS, CSRF, path traversal, and more.

### 📦 Dependency Scanning
Checks dependencies against known CVE databases via Snyk (requires free API key).

### 🐍 Language-Specific Analysis
- **Python:** Bandit (security) + Pylint (quality)
- **JavaScript/TypeScript:** ESLint (quality)
- **Java, PHP, Go:** Extensible via Semgrep rules

### 🤖 LLM Deep Analysis (Optional)
When enabled with `--llm`, IronVeil:
1. **Prioritizes high-risk files** — auth, payments, sessions, validation
2. **Sends code to an LLM** for semantic understanding
3. **Returns structured findings** — severity, CWE ID, fix suggestions with code

LLM analysis catches what pattern matchers miss: business logic flaws, missing authorization checks, race conditions, and architectural anti-patterns.

### 📊 Reports
- **JSON** — machine-readable, great for CI/CD pipelines
- **Markdown** — human-readable summaries
- **HTML** — styled reports for sharing

## Architecture

```
ironveil/
├── ironveil/
│   ├── __init__.py          # Version
│   ├── cli.py               # CLI entry point (argparse)
│   ├── config.py            # Config loader with cascading fallbacks
│   ├── files.py             # Language detection, file collection, risk prioritization
│   ├── scanners.py          # Traditional tool runners (TruffleHog, Semgrep, etc.)
│   ├── llm.py               # LLM analysis engine (OpenAI-compatible)
│   ├── report.py            # Report builder (JSON/Markdown/HTML)
│   └── openclaw_skill.py    # Optional OpenClaw integration
├── pyproject.toml
└── README.md
```

## Configuration

IronVeil uses a cascading config system:

1. `--config path/to/ironveil.json` (CLI flag)
2. `IRONVEIL_CONFIG` environment variable
3. `./ironveil.json` (current directory)
4. `~/.ironveil.json` (home directory)
5. Built-in defaults

Generate a starter config:

```bash
ironveil init-config
```

Example config:

```json
{
  "scanners": {
    "trufflehog": { "enabled": true },
    "semgrep": { "enabled": true },
    "snyk": { "enabled": true, "api_key": "your-key" },
    "bandit": { "enabled": true },
    "pylint": { "enabled": true },
    "eslint": { "enabled": true }
  },
  "llm": {
    "enabled": false,
    "model": "gpt-4o",
    "max_files": 5,
    "api_key": "",
    "base_url": ""
  },
  "results_dir": "~/.ironveil/results"
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install ironveil[all]
      - run: ironveil scan ./ --output json
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

### Exit Codes

IronVeil exits `0` on success regardless of findings. To fail on severity, wrap it:

```bash
ironveil scan ./my-repo --output json
# Check the JSON for critical/high findings in your pipeline
```

## OpenClaw Integration

IronVeil works as a **standalone CLI** and as an **OpenClaw skill**.

### Standalone (any machine)

```bash
pip install ironveil
ironveil scan https://github.com/user/repo --llm
```

### Inside OpenClaw

Place under `~/.openclaw/workspace/skills/ironveil/` and reference from your agent:

```python
from ironveil.openclaw_skill import scan_for_openclaw

results_path = scan_for_openclaw("https://github.com/user/repo", llm=True)
```

Or trigger via cron:

```bash
openclaw cron add --name "weekly-scan" --schedule "0 9 * * 1" \
  --task "Run ironveil scan on https://github.com/org/repo --llm and email the report"
```

The OpenClaw integration is **entirely optional** — IronVeil has zero OpenClaw dependencies.

## Token Cost Management

LLM analysis tracks token usage and estimates costs:

| Model | Approx Cost/Scan (5 files) |
|-------|---------------------------|
| GPT-4o | ~$0.05–$0.15 |
| GPT-4o-mini | ~$0.005–$0.01 |
| Claude 3.5 Sonnet | ~$0.03–$0.10 |
| GLM-4.7 | ~$0.02–$0.05 |

Use `--llm-max-files` to control costs. Start with 3–5 files and increase for deeper audits.

## Requirements

- **Python 3.10+**
- **Git** (for cloning remote repos)
- Optional: `trufflehog`, `semgrep`, `bandit`, `pylint`, `eslint`, `snyk` (installed separately or via `pip install ironveil[tools]`)
- Optional: `openai` Python package for LLM analysis (`pip install ironveil[llm]`)

## License

MIT © Kanchana Wickremasinghe

---

<p align="center">
  Built with 🛡️ by <a href="https://github.com/nzicecool">nzicecool</a>
</p>
