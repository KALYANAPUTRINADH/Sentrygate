# SentryGate Threat Model

## Scope and Security Objective

Protect websites and Windows computers administered by the operator, preserve explainable evidence, and keep administrative and firewall actions explicit. The system does not identify people from IP addresses, inspect private application contents, read keystrokes/passwords/browser history, decrypt traffic, terminate processes, or automatically create firewall blocks.

## Components and Trust Boundaries

| Component | Sensitive assets | Trust boundary / primary risks |
| --- | --- | --- |
| Dashboard/browser | Admin session, incident evidence, one-time credentials | Browser to API; XSS, CSRF, session theft, role bypass, malicious evidence rendering |
| Backend API | Password verifiers, role checks, ingestion credentials, actions | Authenticated browser/device/gateway requests; authorization mistakes, request exhaustion, unsafe input |
| Website gateway | Upstream configuration, per-site credentials, observed request metadata | Untrusted internet request to proxy; forged forwarding headers, SSRF, event-sender outage, request flooding |
| Windows agent | Device credential, local event spool, firewall policy if opted in | Host to API over TLS; credential theft, replay, over-collection, elevated service compromise |
| Local SQLite | Events, snapshots, incidents, audit rows, encrypted credential material | Local filesystem/service account boundary; theft, tampering, corruption, exhaustion, backup disclosure |
| Update process | Node dependencies, SentryGate scripts/service executable, database schema | Operator-controlled package/filesystem boundary; malicious or incompatible update, rollback with newer schema |
| Windows Firewall adapter | Existing Windows rules and SentryGate-owned rules | Local OS privilege boundary; rule ownership confusion, expiry/removal failure, LocalSystem compromise |

Assume internet clients can send arbitrary paths, headers, bodies, and timing patterns. Assume an enrolled endpoint can be offline or compromised. The local host administrator and deployment operator are trusted; a stolen owner account or compromised host can alter local code/data.

## Principal Threats and Current Controls

- Credential disclosure: admin passwords use salted scrypt. Device and website tokens have per-asset verifiers; the website gateway's runtime token copy is AES-GCM encrypted using a key derived from the stable session secret. Agent credentials and spool contents use Windows DPAPI. Secrets must not enter source control or logs.
- Transport interception: API and gateway can use Node HTTPS with TLS 1.2 minimum and normal certificate/hostname validation. Agent and gateway HTTP clients do not disable verification. Cleartext is accepted only for loopback development; remote API/upstream URLs require HTTPS. Deployments need certificates and a trusted root on every client.
- Session/CSRF: session cookies are HttpOnly and SameSite=Strict; Secure is set whenever listener TLS is enabled. Mutating authenticated requests reject a mismatched scheme/host Origin. Sessions are signed for eight hours, logout revokes that session ID, and role lookup occurs against the database on each request. Failed logins are throttled per immediate peer (10 failures per 15 minutes); throttle state is process-local and resets on restart.
- Authorization: owner, security_analyst, and read_only_viewer are checked in API routes. Device bearer credentials identify one enrolled device; site credentials are checked against the submitted website asset. Action policy destinations must match the evidence asset. Firewall routes bind rule/device IDs and audit explicit approval.
- Forged source IP: X-Forwarded-For is ignored unless the immediate TCP peer is explicitly trusted. A source IP is observed network metadata, never verified identity.
- Unintended egress: runtime dependencies contain no analytics/crash-upload/cloud-storage/AI SDK. Agent and gateway event delivery resolve the configured API and require loopback/private/link-local addresses; browser assets/API are same-origin. The gateway separately connects to each explicitly configured website upstream. DNS uses the operating system's configured resolver. Private-address preflight is not cryptographic pinning and does not prevent an adversarial DNS rebinding race; use trusted private DNS and network egress ACLs as defense in depth.
- Gateway failure: website policy selects `open` or `closed` for detected requests when event telemetry cannot be delivered. Open forwards the request; closed returns 503 and does not forward the detected request. Normal upstream traffic is passed through in both modes; event loss is visible in structured logs and bounded by the event timeout. Upstream unavailability returns 502. WebSocket upgrades are unsupported.
- Input/resource abuse: JSON bodies have a size cap; passwords have a maximum; website policies validate upstream URL and restrict non-loopback HTTP. Database main/WAL/SHM size is bounded; event ingestion returns 507 at the configured limit. Retention runs periodically and compacts after deletions. The agent's DPAPI-protected outbox has byte/event limits and reports degraded health when full. Gateway rate counters remain process-local and are not distributed.
- Evidence and audit: dashboard HTML escapes request paths, user agents, and evidence. API failures are logged as structured JSON without bodies or credentials. Admin settings, credential lifecycle, and incident actions produce audit entries. Local administrators can still tamper with SQLite; audit log is not cryptographically tamper-evident.
- Agent/backend outages: endpoint spool uses stable event IDs and retains unacknowledged records; reporting retries after restart. Firewall removal remains pending until an authenticated device reports actual state. Health sweeps create alerts after missed heartbeats. A disconnected agent cannot confirm removal.
- Database loss/disclosure: `VACUUM INTO` creates a consistent local backup and validates SQLite integrity. Restore validates a staging copy, preserves the prior database, and requires the service to be stopped. SQLite itself is not encrypted by SentryGate. Use BitLocker/full-volume encryption, strict local ACLs, and equivalent protection for manually selected backups. Storage path/cap/free-space warnings are visible; at the cap ingestion is rejected and each website's configured gateway telemetry failure mode governs detected requests.
- Update compromise: there is no runtime update check or updater. Updates are optional, operator-sourced, verified out of band, reviewed, backed up, tested, and rolled back manually. SentryGate does not yet ship a signed update manifest or compatibility guarantee.

## Residual Risks / Pilot Limits

- This is a controlled-pilot candidate, not evidence of production readiness. No third-party penetration test, formal cryptographic audit, Windows fleet test, or long-duration availability test has been completed.
- The gateway and API are single-process Node services. Gateway rate limits are memory-local, and SQLite is a single local database. Neither is horizontally scalable.
- Gateway instance state currently represents the local gateway process serving configured website assets; it is not an independently provisioned worker per website.
- Website enforcement and telemetry share the same local API/database dependency. Fail-closed mode intentionally trades availability for enforcement on detected requests.
- No mutual TLS is implemented; high-entropy per-asset bearer credentials are protected in transit by server-authenticated TLS.
- SQLite and audit history are not encrypted or tamper-evident by SentryGate. Local-only storage relies on OS volume encryption and restrictive service ACLs; local backup paths are operator chosen and never uploaded automatically. Details and network destinations are enumerated in [Local Storage and Privacy](local-only-privacy.md).
- Windows service firewall mode runs the whole agent as LocalSystem. Keep disabled for the initial pilot unless specifically approved; the pilot plan does not require a firewall change.
- Dashboard responsiveness and load results are synthetic loopback measurements on the test host, not a capacity guarantee.
