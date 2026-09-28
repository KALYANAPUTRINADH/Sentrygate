# Milestone 2 - Website Protection

The local gateway listens on `SENTRYGATE_GATEWAY_HOST` and `SENTRYGATE_GATEWAY_PORT` (loopback and port 4310 by default). A protected website is mounted at `/site/<asset-id>/`; the prefix is removed and the remaining path/query is sent to that asset's configured HTTP(S) upstream. Request and response bodies stream through the gateway.

Each request creates an authenticated event with UTC timestamp, asset ID, socket-observed client IP, method, path, user agent, response status, matching rule, action, and reason. Sensitive-path and rate-limit matches also create alerts that state the matched evidence and explicitly avoid attributing the traffic to a person.

Rules are enabled by default and start in `observe` mode. `challenge-ready` is a pass-through placeholder; `block` returns 403 for sensitive paths and 429 for rate limits. Allowlisted addresses are exact IPv4/IPv6 values and bypass both rules. Rate limits use a process-local rolling window.

Forwarded IP headers are ignored by default. Administrators may configure exact trusted immediate peer addresses; only then is the rightmost `X-Forwarded-For` value used, and only if it is a valid IP. Configure a trusted proxy only when it overwrites/appends that header correctly.

Event ingestion requires a 256-bit bearer credential. SQLite stores its SHA-256 verifier and AES-GCM-encrypted runtime copy; the encryption key is derived from `SENTRYGATE_SESSION_SECRET`. Rotating the credential invalidates the previous value immediately and is audited.

WebSocket `Upgrade` requests return 501. The gateway is a local single-process evaluation service and is not intended to front a production domain in this milestone.
