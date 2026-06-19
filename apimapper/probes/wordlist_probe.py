"""
Wordlist-based endpoint discovery.

Given a base host already confirmed in-scope, this tries a list of common
API path segments with a single GET each and keeps anything that doesn't
404. This is how you find endpoints that aren't referenced anywhere in
the client-side JS/APK (e.g. internal-only routes, deprecated versions).

Same rules as active_probe.py: every request goes through ScopeGuard,
GET-only, no parameter fuzzing, no auth bypass attempts.
"""
from __future__ import annotations

from pathlib import Path

import httpx

from apimapper.core.models import Endpoint, Source
from apimapper.core.scope import ScopeGuard, ScopeError
from apimapper.probes.active_probe import Prober, ProbeConfig

DEFAULT_WORDLIST = Path(__file__).parent.parent / "wordlists" / "common_api_paths.txt"


def load_wordlist(path: str | Path | None = None) -> list[str]:
    p = Path(path) if path else DEFAULT_WORDLIST
    if not p.exists():
        raise FileNotFoundError(f"Wordlist not found: {p}")
    lines = [l.strip() for l in p.read_text().splitlines()]
    return [l for l in lines if l and not l.startswith("#")]


async def discover_via_wordlist(
    base_host: str,
    guard: ScopeGuard,
    wordlist_path: str | Path | None = None,
    config: ProbeConfig | None = None,
    not_found_status: tuple[int, ...] = (404,),
) -> list[Endpoint]:
    """
    Probe base_host with each wordlist entry. Returns only endpoints that
    didn't come back as a clean 404 — i.e. likely real routes, including
    ones that 401/403 (exists but requires auth) or 200 (exists, accessible).

    Caller must ensure base_host is already known in-scope; this still
    re-checks via ScopeGuard on every individual request as defense in depth.
    """
    words = load_wordlist(wordlist_path)
    candidates = [
        Endpoint(path=f"/{w}", base_host=base_host, source=Source.WORDLIST_PROBE, confidence=0.5)
        for w in words
    ]

    # Confirm scope before even attempting, fail loud and early if not.
    # Uses the read-only in_scope() check (not allow()) so this pre-flight
    # check doesn't itself consume a slot from max_requests_per_host.
    if not guard.in_scope(base_host):
        raise ScopeError(
            f"{base_host} is not in scope (or allow_active_probing is false) "
            f"— refusing to run wordlist discovery against it."
        )

    prober = Prober(guard, config or ProbeConfig())
    results = await prober.probe_all(candidates)

    found = [
        e for e in results
        if e.probed and e.status_code is not None and e.status_code not in not_found_status
    ]
    return found
