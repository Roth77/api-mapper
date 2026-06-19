# apimapper

An authorized red-team API endpoint and secret discovery agent for web apps and Android APKs.

apimapper statically extracts API endpoints and likely-leaked secrets (API keys, tokens, JWTs)
from JavaScript bundles and decompiled Android APKs, then — **only against hosts you've
explicitly authorized** — does light, non-destructive liveness probing and uses an LLM to
cluster findings and write a prioritized report.

## What this is / isn't

**Is:** a recon and discovery tool. Static string/pattern analysis, plus optional GET-only
liveness checks (status codes, security headers, "does this leaked key actually authenticate").

**Isn't:** an exploitation tool. It does not fuzz for injection, brute-force credentials, or
attempt auth bypass. Active probing is also hard-gated behind a `scope.yaml` file that you
must create and explicitly populate — there is no code path that sends a request to a host
not listed there.

Use this only against systems you are authorized to test.

## Install

```bash
git clone https://github.com/Roth77/api-mapper.git
cd apimapper
pip install -e .
# or, on Kali: pip install -e . --break-system-packages
```

Android scanning requires [jadx](https://github.com/skylot/jadx):
```bash
sudo apt install jadx   # Kali/Debian
```

The agent reasoning layer requires an Anthropic API key:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```
(Static extraction and probing work without it — pass `--no-agent` to skip that step.)

## Quickstart

```bash
# 1. Create and edit your scope file — required before any active scan
apimapper init-scope
$EDITOR scope.yaml   # add allowed_hosts, set allow_active_probing: true

# 2. Scan a web app's JS bundles
apimapper scan-web ./downloaded_bundles/ --scope scope.yaml -o report.md

# 3. Scan an Android APK
apimapper scan-apk ./target.apk --scope scope.yaml -o report.md

# Static analysis only, no live requests, no LLM call
apimapper scan-web ./downloaded_bundles/ --scope scope.yaml --no-active --no-agent -o report.json
```

## scope.yaml

Every active (network-touching) operation is gated by this file. See
[`examples/scope.example.yaml`](examples/scope.example.yaml). Key fields:

| Field | Purpose |
|---|---|
| `allow_active_probing` | Must be `true` or **no** live requests are sent, period. |
| `allowed_hosts` | Glob patterns of hosts you're authorized to probe. |
| `allowed_cidrs` | IP ranges you're authorized to probe (e.g. internal network tests). |
| `excluded_hosts` | Explicit denylist, checked before the allow-list, even if it would otherwise match. |
| `max_requests_per_host` | Hard cap per host per run. |
| `rate_limit_rps` | Requests/sec throttle per host. |

Static extraction (parsing JS/APK you already have on disk) never requires scope, since it
doesn't touch the network.

## How it works

1. **Extract** — regex/string analysis over JS bundles or decompiled APK Java source +
   resources for endpoint paths and known secret patterns (AWS, Firebase, Stripe, GitHub
   PATs, JWTs, generic key assignments, PEM blocks).
2. **Classify** — every discovered host is checked against `scope.yaml` and tagged
   in-scope/out-of-scope, before anything is sent over the wire.
3. **Probe** (in-scope only, opt-in) — single GET per endpoint: status code, CORS/security
   headers, and whether a discovered key flips a 401/403 to a 200 on its associated endpoint.
4. **Agent reasoning** — an LLM call clusters related endpoints, ranks findings by severity,
   and writes the report narrative. It only reads already-collected data; it cannot trigger
   new network requests.
5. **Report** — Markdown or JSON, with a full endpoint/secret table plus the agent's
   executive summary and prioritized next steps.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
