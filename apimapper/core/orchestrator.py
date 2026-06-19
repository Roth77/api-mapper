"""
Pipeline orchestrator. This is the only place that decides ordering:
1. static extraction (no scope needed)
2. scope resolution for every discovered host (read-only classification)
3. active probing (ONLY for in-scope hosts, only if allow_active_probing)
4. agent reasoning over the assembled ScanResult (no new network calls)
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from apimapper.core.models import ScanResult
from apimapper.core.scope import Scope, ScopeGuard
from apimapper.extractors.js_extractor import scan_js_path
from apimapper.extractors.apk_extractor import scan_apk
from apimapper.probes.active_probe import Prober, ProbeConfig


def run_web_scan(
    js_path: str | Path,
    scope_path: str | Path,
    do_active_probe: bool = True,
    base_host_hint: str | None = None,
) -> ScanResult:
    result = ScanResult(target=str(js_path), target_type="web")

    endpoints, secrets = scan_js_path(js_path)
    if base_host_hint:
        for e in endpoints:
            if not e.base_host:
                e.base_host = base_host_hint

    result.endpoints = endpoints
    result.secrets = secrets
    result.dedupe_endpoints()

    scope = Scope.load(scope_path)
    result.scope_engagement = scope.engagement_name
    guard = ScopeGuard(scope)

    # Classify in/out of scope regardless of whether we actively probe,
    # so the report always shows what was discovered vs what was tested.
    # Uses guard.in_scope() (read-only) rather than guard.allow() so this
    # classification pass doesn't itself burn into max_requests_per_host.
    for e in result.endpoints:
        if not e.base_host:
            e.in_scope = None  # can't resolve a host, can't classify
            continue
        if guard.in_scope(e.full_url):
            e.in_scope = True
        else:
            e.in_scope = False
            e.notes.append(f"{e.base_host} is not within scope.yaml's allowed_hosts/allowed_cidrs (or active probing is disabled).")

    if do_active_probe and scope.allow_active_probing:
        probable = [e for e in result.endpoints if e.in_scope]
        prober = Prober(guard, ProbeConfig())
        probed = asyncio.run(prober.probe_all(probable))
        by_fp = {e.fingerprint: e for e in probed}
        result.endpoints = [by_fp.get(e.fingerprint, e) for e in result.endpoints]
    elif do_active_probe and not scope.allow_active_probing:
        result.errors.append(
            "Active probing requested but allow_active_probing is false in "
            "scope.yaml — only static results are included."
        )

    return result


def run_android_scan(
    apk_path: str | Path,
    scope_path: str | Path,
    do_active_probe: bool = True,
) -> ScanResult:
    result = ScanResult(target=str(apk_path), target_type="android")

    endpoints, secrets, manifest_info = scan_apk(apk_path)
    result.endpoints = endpoints
    result.secrets = secrets
    result.dedupe_endpoints()
    if manifest_info.get("package"):
        result.errors.append(f"[info] package: {manifest_info['package']}")
    for comp in manifest_info.get("exported_components", []):
        result.errors.append(f"[info] exported {comp['type']}: {comp['name']}")

    scope = Scope.load(scope_path)
    result.scope_engagement = scope.engagement_name
    guard = ScopeGuard(scope)

    for e in result.endpoints:
        if not e.base_host:
            e.in_scope = None
            continue
        if guard.in_scope(e.full_url):
            e.in_scope = True
        else:
            e.in_scope = False
            e.notes.append(f"{e.base_host} is not within scope.yaml's allowed_hosts/allowed_cidrs (or active probing is disabled).")

    if do_active_probe and scope.allow_active_probing:
        probable = [e for e in result.endpoints if e.in_scope]
        prober = Prober(guard, ProbeConfig())
        probed = asyncio.run(prober.probe_all(probable))
        by_fp = {e.fingerprint: e for e in probed}
        result.endpoints = [by_fp.get(e.fingerprint, e) for e in result.endpoints]
    elif do_active_probe and not scope.allow_active_probing:
        result.errors.append(
            "Active probing requested but allow_active_probing is false in "
            "scope.yaml — only static results are included."
        )

    return result
