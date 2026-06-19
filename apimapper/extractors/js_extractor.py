"""
Static extraction of API endpoints and likely secrets from JavaScript
source/bundles. Pure text/regex analysis — never touches the network,
so it needs no scope authorization.
"""
from __future__ import annotations

import re
from pathlib import Path

from apimapper.core.models import Endpoint, SecretFinding, Severity, Source

# --- Endpoint patterns -------------------------------------------------

_PATH_LIKE = re.compile(
    r"""["'\`](/(?:api|v[0-9]+|graphql|rest|internal|admin)[a-zA-Z0-9_\-/{}.:]*)["'\`]""",
    re.IGNORECASE,
)
_FULL_URL = re.compile(
    r"""["'\`](https?://[a-zA-Z0-9.\-]+(?::\d+)?(?:/[a-zA-Z0-9_\-/{}.:%]*)?)["'\`]"""
)
_FETCH_AXIOS_CALL = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|\.ajax)\s*\(\s*["'\`]([^"'\`]+)["'\`]"""
)

# --- Secret patterns -----------------------------------------------------
# Each entry: (name, regex, default severity)
_SECRET_PATTERNS = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("aws_secret_key", re.compile(r"""(?i)aws_secret[a-z_]*['"]?\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]"""), Severity.CRITICAL),
    ("firebase_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), Severity.HIGH),
    ("google_oauth_client_secret", re.compile(r"\bGOCSPX-[0-9A-Za-z\-_]{20,}\b"), Severity.HIGH),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), Severity.HIGH),
    ("stripe_live_key", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"), Severity.CRITICAL),
    ("stripe_test_key", re.compile(r"\bsk_test_[0-9A-Za-z]{20,}\b"), Severity.LOW),
    ("generic_bearer_jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"), Severity.MEDIUM),
    ("github_pat", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), Severity.CRITICAL),
    ("generic_api_key_assignment", re.compile(
        r"""(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)['"]?\s*[:=]\s*['"]([A-Za-z0-9\-_./+=]{16,})['"]"""
    ), Severity.MEDIUM),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), Severity.CRITICAL),
]

_NOISE_EXTS = {".png", ".jpg", ".jpeg", ".svg", ".css", ".woff", ".woff2", ".gif", ".ico"}


def _looks_like_static_asset(path: str) -> bool:
    return any(path.lower().endswith(ext) for ext in _NOISE_EXTS)


def extract_endpoints_from_js(content: str, source_file: str) -> list[Endpoint]:
    found: dict[str, Endpoint] = {}

    for m in _PATH_LIKE.finditer(content):
        path = m.group(1)
        if _looks_like_static_asset(path):
            continue
        found[path] = Endpoint(path=path, source=Source.JS_STATIC, source_file=source_file)

    for m in _FULL_URL.finditer(content):
        url = m.group(1)
        if _looks_like_static_asset(url):
            continue
        # split host/path so Endpoint.full_url reconstructs cleanly
        without_scheme = re.sub(r"^https?://", "", url)
        host, _, rest = without_scheme.partition("/")
        path = "/" + rest if rest else "/"
        ep = Endpoint(
            path=path,
            base_host=f"https://{host}",
            source=Source.JS_STATIC,
            source_file=source_file,
        )
        found[url] = ep

    for m in _FETCH_AXIOS_CALL.finditer(content):
        candidate = m.group(1)
        if candidate.startswith("http"):
            continue  # already captured above
        if _looks_like_static_asset(candidate):
            continue
        if candidate not in found:
            found[candidate] = Endpoint(
                path=candidate, source=Source.JS_STATIC, source_file=source_file, confidence=0.8
            )

    return list(found.values())


def extract_secrets_from_js(content: str, source_file: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    lines = content.splitlines()

    for name, pattern, severity in _SECRET_PATTERNS:
        for m in pattern.finditer(content):
            # The actual secret value is always the LAST capture group for
            # patterns with groups (e.g. generic_api_key_assignment has the
            # variable name in group 1 and the value in group 2). Patterns
            # with no groups (e.g. aws_access_key_id) match the value directly.
            value = m.groups()[-1] if m.groups() else m.group(0)
            line_no = content.count("\n", 0, m.start()) + 1
            context_line = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
            findings.append(
                SecretFinding(
                    secret_type=name,
                    value_redacted=SecretFinding.redact(value),
                    source=Source.JS_STATIC,
                    source_file=source_file,
                    line_number=line_no,
                    severity=severity,
                    context=SecretFinding.redact(context_line, keep=20) if len(context_line) > 40 else context_line,
                )
            )
    return findings


def scan_js_path(path: str | Path) -> tuple[list[Endpoint], list[SecretFinding]]:
    """Scan a single JS file or a directory tree of .js files."""
    p = Path(path)
    files = [p] if p.is_file() else list(p.rglob("*.js"))

    all_endpoints: list[Endpoint] = []
    all_secrets: list[SecretFinding] = []

    for f in files:
        try:
            content = f.read_text(errors="ignore")
        except Exception:
            continue
        all_endpoints.extend(extract_endpoints_from_js(content, str(f)))
        all_secrets.extend(extract_secrets_from_js(content, str(f)))

    return all_endpoints, all_secrets
