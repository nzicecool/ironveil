"""
IronVeil — LLM-powered deep code analysis.

Works standalone (reads OPENAI_API_KEY or IRONVEIL_LLM_KEY from env)
or inside OpenClaw (uses the gateway's model routing).
"""

import json
import os
from typing import Any, Dict, List, Optional


class TokenCounter:
    """Track LLM token usage for cost management."""

    def __init__(self):
        self.input_tokens = 0
        self.output_tokens = 0
        self.total_tokens = 0
        self.api_calls = 0
        self.model = "gpt-4"

    def add(self, inp: int, out: int = 0):
        self.input_tokens += inp
        self.output_tokens += out
        self.total_tokens += inp + out
        self.api_calls += 1

    def estimate_cost(self) -> float:
        pricing = {
            "gpt-4": (30.00, 60.00),
            "gpt-4-turbo": (10.00, 20.00),
            "gpt-4o": (2.50, 10.00),
            "gpt-4o-mini": (0.15, 0.60),
            "claude-3-opus": (15.00, 75.00),
            "claude-3-sonnet": (3.00, 15.00),
            "claude-3.5-sonnet": (3.00, 15.00),
            "glm-4.7": (1.50, 6.00),
            "glm-5.1": (1.50, 6.00),
        }
        inp_per_m, out_per_m = pricing.get(self.model, (30.00, 60.00))
        return (self.input_tokens / 1_000_000 * inp_per_m) + (self.output_tokens / 1_000_000 * out_per_m)

    def summary(self) -> Dict[str, Any]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "api_calls": self.api_calls,
            "estimated_cost_usd": round(self.estimate_cost(), 4),
            "model": self.model,
        }


SYSTEM_PROMPT = """You are IronVeil, an expert security code reviewer. Analyze the provided source code and return a JSON array of findings.

For each finding provide:
- severity: critical | high | medium | low
- type: security | logic | architecture | quality
- title: short description
- description: detailed explanation
- file: relative file path
- line: line number if identifiable
- code_snippet: the problematic code
- fix_suggestion: how to fix it
- cwe_id: CWE identifier if applicable (e.g. CWE-79)

Rules:
- Only report genuine issues, not style preferences
- Be specific with line numbers and code snippets
- Provide actionable fix suggestions with code
- Return ONLY a JSON array, no other text"""


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _get_api_key(config: Dict[str, Any]) -> str:
    return (
        config.get("llm", {}).get("api_key", "")
        or os.environ.get("IRONVEIL_LLM_KEY", "")
        or os.environ.get("OPENAI_API_KEY", "")
    )


def _get_base_url(config: Dict[str, Any]) -> str:
    return config.get("llm", {}).get("base_url", "") or os.environ.get("IRONVEIL_LLM_BASE_URL", "")


def analyze_file(
    file_path: str,
    repo_dir: str,
    config: Dict[str, Any],
    counter: TokenCounter,
    analysis_type: str = "comprehensive",
) -> Dict[str, Any]:
    """Analyze a single file with LLM."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    except Exception as e:
        return {"file": file_path, "error": str(e), "findings": []}

    if len(code) > 15_000:
        code = code[:15_000] + "\n\n# ... (truncated for analysis)"

    rel_path = os.path.relpath(file_path, repo_dir)
    api_key = _get_api_key(config)

    if not api_key:
        # Dry-run mode: estimate tokens but don't call LLM
        est = _estimate_tokens(code)
        counter.add(est, 350)
        return {
            "file": rel_path,
            "analyzed": False,
            "dry_run": True,
            "findings": [],
            "note": "No LLM API key configured. Set OPENAI_API_KEY or IRONVEIL_LLM_KEY.",
        }

    model = config.get("llm", {}).get("model", "gpt-4")
    counter.model = model

    prompt = f"""Analyze this code for {analysis_type} issues.

File: {rel_path}

```{os.path.splitext(file_path)[1]}
{code}
```"""

    try:
        from openai import OpenAI

        base_url = _get_base_url(config) or None
        client = OpenAI(api_key=api_key, base_url=base_url)

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=2000,
        )

        content = response.choices[0].message.content or "[]"
        # Strip markdown code fences if present
        if content.strip().startswith("```"):
            lines = content.strip().splitlines()
            content = "\n".join(lines[1:-1])

        try:
            findings = json.loads(content)
        except json.JSONDecodeError:
            findings = [{"raw_response": content, "severity": "info"}]

        # Track usage
        if response.usage:
            counter.add(response.usage.prompt_tokens, response.usage.completion_tokens)
        else:
            counter.add(_estimate_tokens(code), _estimate_tokens(content))

        return {"file": rel_path, "analyzed": True, "findings": findings}

    except ImportError:
        est = _estimate_tokens(code)
        counter.add(est, 350)
        return {
            "file": rel_path,
            "analyzed": False,
            "findings": [],
            "error": "openai package not installed. Run: pip install ironveil[llm]",
        }
    except Exception as e:
        return {"file": rel_path, "analyzed": False, "findings": [], "error": str(e)}


def analyze_repository(
    repo_dir: str,
    files: List[str],
    config: Dict[str, Any],
    max_files: int = 5,
) -> Dict[str, Any]:
    """Run LLM analysis on prioritized files."""
    counter = TokenCounter()
    counter.model = config.get("llm", {}).get("model", "gpt-4")

    to_analyze = files[:max_files]
    all_findings = []
    file_results = []

    for fp in to_analyze:
        rel = os.path.relpath(fp, repo_dir)
        print(f"  🤖 Analyzing: {rel}")
        result = analyze_file(fp, repo_dir, config, counter)
        file_results.append(result)
        if result.get("findings"):
            all_findings.extend(result["findings"])

    return {
        "analyzed_files": file_results,
        "findings": all_findings,
        "total_files": len(files),
        "analyzed_count": len(to_analyze),
        "token_usage": counter.summary(),
    }
