"""
Active probing of discovered endpoints.

Every function here that sends a network request takes a ScopeGuard and
calls .allow() before the request. This module deliberately does NOT
implement: auth bypass attempts, payload fuzzing, brute-forcing
credentials, or anything beyond "is this endpoint alive and what does
it benignly reveal" (status code, content-type, security headers,
whether a discovered key is accepted).

That boundary is intentional, not a placeholder to fill in later.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import httpx

from apimapper.core.models import Endpoint, SecretFinding
from apimapper.core.scope import ScopeGuard, ScopeError


@dataclass
class ProbeConfig:
    timeout_seconds: float = 8.0
    user_agent: str = "apimapper/0.1 (authorized-security-scan; see scope.yaml)"
    follow_redirects: bool = False
    max_concurrent: int = 5


class Prober:
    def __init__(self, scope_guard: ScopeGuard, config: ProbeConfig | None = None):
        self.guard = scope_guard
        self.config = config or ProbeConfig()
        self._last_request_time: dict[str, float] = {}
        self._host_locks: dict[str, asyncio.Lock] = {}

    def _lock_for(self, host: str) -> asyncio.Lock:
        if host not in self._host_locks:
            self._host_locks[host] = asyncio.Lock()
        return self._host_locks[host]

    async def _respect_rate_limit(self, host: str) -> None:
        # Locked per-host so concurrent tasks targeting the same host can't
        # both read a stale _last_request_time and race past the throttle.
        async with self._lock_for(host):
            min_interval = 1.0 / max(self.guard.scope.rate_limit_rps, 0.1)
            last = self._last_request_time.get(host, 0)
            elapsed = time.monotonic() - last
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            self._last_request_time[host] = time.monotonic()

    async def probe_endpoint(self, client: httpx.AsyncClient, endpoint: Endpoint) -> Endpoint:
        url = endpoint.full_url
        if not url:
            endpoint.notes.append("Skipped probe: no base_host resolved for this path.")
            return endpoint

        try:
            self.guard.allow(url)
        except ScopeError as e:
            endpoint.in_scope = False
            endpoint.notes.append(f"Not probed (out of scope): {e}")
            return endpoint

        endpoint.in_scope = True
        host = self.guard._host_of(url)
        await self._respect_rate_limit(host)

        try:
            resp = await client.get(
                url,
                timeout=self.config.timeout_seconds,
                follow_redirects=self.config.follow_redirects,
                headers={"User-Agent": self.config.user_agent},
            )
            endpoint.probed = True
            endpoint.status_code = resp.status_code
            endpoint.response_snippet = resp.text[:300] if resp.text else ""

            self._tag_security_headers(endpoint, resp.headers)

        except httpx.RequestError as e:
            endpoint.probed = True
            endpoint.notes.append(f"Request failed: {e.__class__.__name__}: {e}")

        return endpoint

    def _tag_security_headers(self, endpoint: Endpoint, headers: httpx.Headers) -> None:
        if "access-control-allow-origin" in headers and headers["access-control-allow-origin"] == "*":
            endpoint.tags.append("cors-wildcard")
        if "x-powered-by" in headers:
            endpoint.notes.append(f"x-powered-by: {headers['x-powered-by']}")
        if endpoint.status_code in (401, 403):
            endpoint.tags.append("auth-required")
        elif endpoint.status_code == 200 and any(
            kw in endpoint.path.lower() for kw in ("admin", "internal", "debug", "config")
        ):
            endpoint.tags.append("sensitive-path-accessible")

    async def probe_all(self, endpoints: list[Endpoint]) -> list[Endpoint]:
        sem = asyncio.Semaphore(self.config.max_concurrent)

        async def _bounded(ep, client):
            async with sem:
                return await self.probe_endpoint(client, ep)

        async with httpx.AsyncClient() as client:
            tasks = [_bounded(ep, client) for ep in endpoints]
            return await asyncio.gather(*tasks)


async def validate_secret_against_endpoint(
    client: httpx.AsyncClient,
    guard: ScopeGuard,
    secret: SecretFinding,
    secret_value: str,
    test_url: str,
    header_name: str = "Authorization",
    header_template: str = "Bearer {value}",
) -> SecretFinding:
    """
    Passive validation only: send the discovered key as auth on a single
    GET request and compare against an unauthenticated baseline (e.g.
    401 -> 200). Confirms the key is live without using it for anything
    beyond that one read-only confirming request.

    secret_value is taken as an explicit argument (not read off the
    SecretFinding object) so the redacted value living on SecretFinding
    can never accidentally be sent — callers must pass the real value
    they already hold from extraction, and it is never written back into
    any persisted/report field on `secret`.
    """
    try:
        guard.allow(test_url)
    except ScopeError as e:
        secret.notes.append(f"Not validated (out of scope): {e}")
        return secret

    try:
        baseline = await client.get(test_url, timeout=8.0)
        authed = await client.get(
            test_url,
            headers={header_name: header_template.format(value=secret_value)},
            timeout=8.0,
        )
        if baseline.status_code in (401, 403) and authed.status_code == 200:
            secret.validated_live = True
            secret.notes.append(
                f"Baseline returned {baseline.status_code}; with key returned 200 — key appears live."
            )
        else:
            secret.validated_live = False
    except httpx.RequestError as e:
        secret.notes.append(f"Validation request failed: {e}")

    return secret
