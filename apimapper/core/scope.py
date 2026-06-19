"""
Scope enforcement.

Every active network call in apimapper goes through ScopeGuard.allow().
Static extraction (parsing JS / decompiling APKs you already possess)
does not require scope, since it touches no live system. Anything that
sends a packet to a host does.

Design intent: this is not a disclaimer, it's a gate. There is no
code path in probes/ that skips it.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml


class ScopeError(Exception):
    pass


@dataclass
class ScopeRule:
    pattern: str          # hostname glob, e.g. "*.example.com" or "api.example.com"
    note: str = ""


@dataclass
class Scope:
    engagement_name: str
    authorized_by: str
    allowed_hosts: list[ScopeRule] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    excluded_hosts: list[ScopeRule] = field(default_factory=list)
    max_requests_per_host: int = 200
    allow_active_probing: bool = False   # explicit opt-in, defaults safe
    rate_limit_rps: float = 2.0
    notes: str = ""

    @staticmethod
    def load(path: str | Path) -> "Scope":
        path = Path(path)
        if not path.exists():
            raise ScopeError(
                f"No scope file at {path}. apimapper refuses to run active "
                f"modules without one. Run `apimapper init-scope` to create one."
            )
        data = yaml.safe_load(path.read_text()) or {}

        required = ["engagement_name", "authorized_by"]
        missing = [k for k in required if not data.get(k)]
        if missing:
            raise ScopeError(
                f"scope.yaml is missing required field(s): {', '.join(missing)}. "
                f"A scope file must name the engagement and who authorized it."
            )

        if not data.get("allowed_hosts") and not data.get("allowed_cidrs"):
            raise ScopeError(
                "scope.yaml must define at least one entry in allowed_hosts "
                "or allowed_cidrs — otherwise nothing could ever be in scope."
            )

        allowed = [ScopeRule(**h) if isinstance(h, dict) else ScopeRule(pattern=h)
                   for h in data.get("allowed_hosts", [])]
        excluded = [ScopeRule(**h) if isinstance(h, dict) else ScopeRule(pattern=h)
                    for h in data.get("excluded_hosts", [])]

        return Scope(
            engagement_name=data["engagement_name"],
            authorized_by=data["authorized_by"],
            allowed_hosts=allowed,
            allowed_cidrs=data.get("allowed_cidrs", []),
            excluded_hosts=excluded,
            max_requests_per_host=data.get("max_requests_per_host", 200),
            allow_active_probing=bool(data.get("allow_active_probing", False)),
            rate_limit_rps=float(data.get("rate_limit_rps", 2.0)),
            notes=data.get("notes", ""),
        )


class ScopeGuard:
    """
    Call ScopeGuard(scope).allow(url_or_host) before every live request.
    Raises ScopeError on anything not explicitly authorized.
    """

    def __init__(self, scope: Scope):
        self.scope = scope
        self._request_counts: dict[str, int] = {}

    def _host_of(self, target: str) -> str:
        if "://" not in target:
            target = "https://" + target
        return urlparse(target).hostname or target

    def _matches_any(self, host: str, rules: list[ScopeRule]) -> bool:
        return any(fnmatch.fnmatch(host, r.pattern) for r in rules)

    def _in_cidr(self, host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        for cidr in self.scope.allowed_cidrs:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        return False

    def in_scope(self, target: str) -> bool:
        """
        Side-effect-free scope membership check — does NOT consume the
        per-host request budget. Use this for classification/reporting.
        Use allow() only immediately before an actual network call.
        """
        if not self.scope.allow_active_probing:
            return False
        host = self._host_of(target)
        if self._matches_any(host, self.scope.excluded_hosts):
            return False
        return self._matches_any(host, self.scope.allowed_hosts) or self._in_cidr(host)

    def allow(self, target: str) -> bool:
        if not self.scope.allow_active_probing:
            raise ScopeError(
                "allow_active_probing is false in scope.yaml. Static "
                "extraction results are still available; live probing is "
                "disabled until you explicitly opt in."
            )

        host = self._host_of(target)

        if self._matches_any(host, self.scope.excluded_hosts):
            raise ScopeError(f"{host} is explicitly excluded in scope.yaml.")

        if not (self._matches_any(host, self.scope.allowed_hosts) or self._in_cidr(host)):
            raise ScopeError(
                f"{host} is not in allowed_hosts/allowed_cidrs in scope.yaml. "
                f"Refusing to send any request to it."
            )

        count = self._request_counts.get(host, 0)
        if count >= self.scope.max_requests_per_host:
            raise ScopeError(
                f"max_requests_per_host ({self.scope.max_requests_per_host}) "
                f"reached for {host}. Raise the limit in scope.yaml if this "
                f"engagement genuinely needs more."
            )
        self._request_counts[host] = count + 1
        return True


DEFAULT_SCOPE_TEMPLATE = """\
# apimapper scope file — required for any live/active scanning.
# Static extraction (parsing JS bundles or APKs you already have) does not
# need this file. The moment apimapper would send a network request to a
# target, it loads this file and refuses to proceed unless the target is
# explicitly listed below.

engagement_name: "CHANGE_ME"
authorized_by: "CHANGE_ME — name/role of the person who authorized this test"

# Must be true to allow ANY live request. Defaults to false on purpose.
allow_active_probing: false

allowed_hosts:
  # - pattern: "api.example.com"
  #   note: "Primary API, authorized via pentest agreement #1234"
  # - pattern: "*.staging.example.com"

allowed_cidrs:
  # - "10.20.0.0/24"

excluded_hosts:
  # - pattern: "payments.example.com"
  #   note: "Out of scope — third-party PCI environment"

max_requests_per_host: 200
rate_limit_rps: 2.0

notes: >
  Optional free text — link to the signed authorization / SOW here.
"""
