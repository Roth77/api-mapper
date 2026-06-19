# Usage Guide

## Before you scan anything live

Active probing in apimapper is opt-in and scope-gated by design, but the tool can't verify
that you actually *have* authorization — only that you've configured it as if you do. That's
on you. Before setting `allow_active_probing: true`:

- Get written authorization (a signed SOW, pentest agreement, or bug bounty program scope)
  for every host you list in `allowed_hosts`/`allowed_cidrs`.
- Respect any `excluded_hosts` the client/program specifies, even if a glob in `allowed_hosts`
  would technically match them — apimapper checks exclusions first for this reason.
- Keep `max_requests_per_host` and `rate_limit_rps` reasonable for the target's traffic profile.
  Defaults are conservative; raise them deliberately, not as a reflex.

## Static-only mode

You can extract endpoints and find leaked secrets in JS bundles or APKs with zero
authorization needed, because nothing touches the network:

```bash
apimapper scan-web ./bundles --scope scope.yaml --no-active --no-agent -o findings.json
```

This is useful for:
- Auditing your own org's client-side code for accidentally-shipped secrets, pre-release.
- Initial recon before an engagement's active-testing window opens.
- Bug bounty programs where active scanning isn't permitted but static review of public
  client code is.

## What "active probing" actually does

For each in-scope endpoint, apimapper sends **one GET request** and records:
- HTTP status code
- Whether CORS is wildcard-open
- Whether the response suggests an admin/debug/internal path is reachable without auth
- (Optionally, separately) whether a discovered key flips a 401/403 response to 200

It does not send POST/PUT/DELETE by default, does not fuzz parameters, does not attempt
authentication bypass, and does not chain findings into further exploitation. If your
engagement requires that kind of testing, do it manually/with purpose-built tools, under
its own explicit authorization — apimapper is a mapping/recon tool, not an exploit framework.

## Handling secrets you find

- Reports redact secret values by default (`value_redacted` field) — first/last 4 chars only.
- If `validated_live: true` appears, that secret authenticated successfully against its
  associated endpoint during the scan. Treat this as a critical finding requiring immediate
  client notification and key rotation, independent of anything else in the report.
- Don't paste raw report output (which may include redacted-but-identifiable fragments)
  into shared channels outside the engagement's agreed reporting process.

## Responsible disclosure

If a scan turns up something that looks like active unauthorized access to real user data,
stop, don't explore further, and follow your engagement's incident-escalation process (most
SOWs have a "stop testing and notify immediately" clause for exactly this scenario).
