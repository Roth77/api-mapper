"""Shared data models passed between extractors, probes, agent, and reporting."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Source(str, Enum):
    JS_STATIC = "js_static"
    APK_STATIC = "apk_static"
    OPENAPI_SPEC = "openapi_spec"
    WORDLIST_PROBE = "wordlist_probe"
    LLM_INFERENCE = "llm_inference"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Endpoint:
    path: str
    method: str = "GET"
    base_host: Optional[str] = None
    source: Source = Source.JS_STATIC
    source_file: Optional[str] = None       # which JS file / smali class it came from
    confidence: float = 1.0
    in_scope: Optional[bool] = None         # set by ScopeGuard pass, None = not yet checked
    probed: bool = False
    status_code: Optional[int] = None
    response_snippet: Optional[str] = None
    notes: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)  # e.g. "admin", "internal", "v1-deprecated"

    @property
    def full_url(self) -> Optional[str]:
        if not self.base_host:
            return None
        host = self.base_host.rstrip("/")
        path = self.path if self.path.startswith("/") else f"/{self.path}"
        return f"{host}{path}"

    @property
    def fingerprint(self) -> str:
        raw = f"{self.method}:{self.base_host}:{self.path}"
        return hashlib.sha1(raw.encode()).hexdigest()[:12]


@dataclass
class SecretFinding:
    secret_type: str            # "aws_access_key", "firebase_api_key", "generic_jwt", etc.
    value_redacted: str         # never store full secret in reports; redact by default
    source: Source
    source_file: str
    line_number: Optional[int] = None
    severity: Severity = Severity.HIGH
    context: str = ""           # surrounding code/string, redacted
    validated_live: Optional[bool] = None   # did a (scope-checked) probe confirm it's active?
    associated_endpoint: Optional[str] = None
    notes: list[str] = field(default_factory=list)

    @staticmethod
    def redact(value: str, keep: int = 4) -> str:
        if len(value) <= keep * 2:
            return "*" * len(value)
        return f"{value[:keep]}{'*' * (len(value) - keep * 2)}{value[-keep:]}"


@dataclass
class ScanResult:
    target: str
    target_type: str            # "web" | "android"
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: Optional[str] = None
    endpoints: list[Endpoint] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scope_engagement: Optional[str] = None

    def dedupe_endpoints(self) -> None:
        seen = {}
        for ep in self.endpoints:
            seen[ep.fingerprint] = ep
        self.endpoints = list(seen.values())

    def summary(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "total_endpoints": len(self.endpoints),
            "in_scope_probed": sum(1 for e in self.endpoints if e.probed),
            "out_of_scope_discovered": sum(1 for e in self.endpoints if e.in_scope is False),
            "total_secrets": len(self.secrets),
            "secrets_validated_live": sum(1 for s in self.secrets if s.validated_live),
            "errors": len(self.errors),
        }
