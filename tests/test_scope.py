import pytest
import yaml
from pathlib import Path

from apimapper.core.scope import Scope, ScopeGuard, ScopeError


def write_scope(tmp_path: Path, **overrides) -> Path:
    base = {
        "engagement_name": "Unit Test Engagement",
        "authorized_by": "Test Author",
        "allow_active_probing": True,
        "allowed_hosts": [{"pattern": "api.example.com"}, {"pattern": "*.staging.example.com"}],
        "excluded_hosts": [{"pattern": "payments.example.com"}],
        "max_requests_per_host": 3,
        "rate_limit_rps": 2.0,
    }
    base.update(overrides)
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.dump(base))
    return p


def test_missing_scope_file_raises(tmp_path):
    with pytest.raises(ScopeError):
        Scope.load(tmp_path / "does_not_exist.yaml")


def test_missing_required_fields_raises(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.dump({"engagement_name": "X"}))  # missing authorized_by, allowed_hosts
    with pytest.raises(ScopeError):
        Scope.load(p)


def test_allowed_host_passes(tmp_path):
    scope = Scope.load(write_scope(tmp_path))
    guard = ScopeGuard(scope)
    assert guard.allow("https://api.example.com/v1/test") is True


def test_wildcard_subdomain_passes(tmp_path):
    scope = Scope.load(write_scope(tmp_path))
    guard = ScopeGuard(scope)
    assert guard.allow("https://foo.staging.example.com/v1/test") is True


def test_unlisted_host_blocked(tmp_path):
    scope = Scope.load(write_scope(tmp_path))
    guard = ScopeGuard(scope)
    with pytest.raises(ScopeError):
        guard.allow("https://evil.com/x")


def test_excluded_host_blocked_even_if_pattern_could_match(tmp_path):
    scope = Scope.load(write_scope(tmp_path, allowed_hosts=[{"pattern": "*.example.com"}]))
    guard = ScopeGuard(scope)
    with pytest.raises(ScopeError):
        guard.allow("https://payments.example.com/charge")


def test_active_probing_disabled_blocks_everything(tmp_path):
    scope = Scope.load(write_scope(tmp_path, allow_active_probing=False))
    guard = ScopeGuard(scope)
    with pytest.raises(ScopeError):
        guard.allow("https://api.example.com/v1/test")


def test_max_requests_per_host_enforced(tmp_path):
    scope = Scope.load(write_scope(tmp_path, max_requests_per_host=2))
    guard = ScopeGuard(scope)
    guard.allow("https://api.example.com/v1/a")
    guard.allow("https://api.example.com/v1/b")
    with pytest.raises(ScopeError):
        guard.allow("https://api.example.com/v1/c")


def test_cidr_allows_ip_targets(tmp_path):
    scope = Scope.load(write_scope(tmp_path, allowed_hosts=[], allowed_cidrs=["10.20.0.0/24"]))
    guard = ScopeGuard(scope)
    assert guard.allow("http://10.20.0.5/api") is True
    with pytest.raises(ScopeError):
        guard.allow("http://10.30.0.5/api")
