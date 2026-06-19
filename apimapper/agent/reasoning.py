"""
The "agent" layer: takes raw extraction/probe output and uses an LLM call
to cluster related endpoints, flag likely-sensitive ones, and draft
human-readable narrative for the report. It does not decide what to probe
or make any live network calls itself — those decisions are made by the
deterministic pipeline (orchestrator.py) under ScopeGuard before this
layer ever runs. This module is read-only over already-collected data.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict

import anthropic

from apimapper.core.models import ScanResult


_SYSTEM_PROMPT = """\
You are assisting a security analyst by organizing API recon data that has
ALREADY been collected through authorized static analysis and in-scope
active probing. You are not deciding what to scan or sending any requests
yourself — you are summarizing and prioritizing results that already exist.

Given a JSON dump of discovered endpoints and secret findings, return JSON
with:
{
  "endpoint_clusters": [
    {"cluster_name": str, "pattern": str, "endpoint_fingerprints": [str], "summary": str}
  ],
  "priority_findings": [
    {"fingerprint_or_type": str, "severity": "info|low|medium|high|critical",
     "reasoning": str, "recommended_next_step": str}
  ],
  "executive_summary": str   // 3-5 sentences, plain language, for a report intro
}

Rules:
- recommended_next_step must describe verification/reporting actions
  (e.g. "confirm with client whether this admin path is intentionally
  exposed", "rotate this key and audit access logs"), never exploitation
  steps, payloads, or bypass techniques.
- Base every claim only on the data given. Do not invent endpoints.
- Keep executive_summary free of jargon where possible.
- Respond with ONLY the JSON object, no markdown fences, no preamble.
"""


class AgentReasoningError(Exception):
    pass


def _serialize_for_llm(scan: ScanResult) -> dict:
    """Strip to what the LLM needs; never include raw secret values."""
    return {
        "target": scan.target,
        "target_type": scan.target_type,
        "endpoints": [
            {
                "fingerprint": e.fingerprint,
                "path": e.path,
                "method": e.method,
                "base_host": e.base_host,
                "source": e.source.value,
                "in_scope": e.in_scope,
                "probed": e.probed,
                "status_code": e.status_code,
                "tags": e.tags,
            }
            for e in scan.endpoints
        ],
        "secrets": [
            {
                "secret_type": s.secret_type,
                "value_redacted": s.value_redacted,
                "source_file": s.source_file,
                "severity": s.severity.value,
                "validated_live": s.validated_live,
                "associated_endpoint": s.associated_endpoint,
            }
            for s in scan.secrets
        ],
    }


def run_agent_analysis(scan: ScanResult, model: str = "claude-sonnet-4-6") -> dict:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise AgentReasoningError(
            "ANTHROPIC_API_KEY not set. The agent reasoning layer needs it; "
            "static results and raw probe data are still available without it "
            "(see --no-agent flag)."
        )

    client = anthropic.Anthropic(api_key=api_key)
    payload = _serialize_for_llm(scan)

    message = client.messages.create(
        model=model,
        max_tokens=4000,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": json.dumps(payload, indent=2)}],
    )

    text_blocks = [b.text for b in message.content if b.type == "text"]
    raw = "\n".join(text_blocks).strip()
    raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise AgentReasoningError(f"Agent did not return valid JSON: {e}\nRaw: {raw[:500]}")
