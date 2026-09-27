# SentryGate Threat Model

## Scope

SentryGate protects websites and applications owned or administered by the operator, monitors one explicitly installed Windows computer in later milestones, manages approved firewall rules, and presents evidence-based alerts.

## Assets

- Administrator account and session.
- Local SQLite security database.
- Website request/event records.
- Gateway rule configuration and event-ingestion credential.
- Dashboard data and audit history.
- Windows device identity and collected process/TCP metadata.
- Per-device agent credential and encrypted local event outbox.
- Approved firewall rule specifications, protected management/backend addresses, and apply/rollback history.

## Trust Boundaries

- Browser to API over HTTP in local development, HTTPS in deployment.
- Gateway client to configured HTTP(S) upstream.
- Gateway event sender to authenticated local event-ingestion API.
- API to local SQLite database.
- Future reverse proxy to protected upstream applications.
- Windows agent to API using a unique device bearer credential.
- Optional elevated Windows agent to the Windows Firewall `NetSecurity` interface.

## Key Threats and Mitigations

- Credential disclosure: passwords are hashed with scrypt and a per-password random salt; plaintext passwords are not written to the database or audit log. The high-entropy gateway token is verified using SHA-256, while its runtime copy is encrypted with AES-GCM using a key derived from the configured secret.
- Session theft: sessions use signed HttpOnly cookies; production deployment must use HTTPS and secure cookies.
- Unauthorized administration: all security data endpoints require an authenticated administrator.
- Evidence confusion: alerts retain concrete evidence fields and avoid identifying a person from an IP address.
- Forged client IP headers: the gateway uses the socket peer address by default. It reads `X-Forwarded-For` only when that immediate peer is explicitly trusted.
- Request floods: configurable per-IP rolling-window counters can be observed or blocked; counters are in memory and reset on restart.
- Sensitive-path probing: configurable `/.env` and `/.git/` detection records an explainable event and can block in Block mode.
- Proxy destination changes: only authenticated administrators can set a website upstream or its protection rules, and each change is audited.
- Local data loss: SQLite is local; operators should back up the configured data path.
- Device credential compromise: every enrolled device has a unique random credential; only its SHA-256 verifier is stored by the API. Credential rotation invalidates the old value and revocation prevents future reports. Agent credential plaintext is shown once and protected with Windows DPAPI on the endpoint.
- Local agent data disclosure: event payloads in the outbox are DPAPI-protected. Service data is ACL-restricted to SYSTEM and Administrators. Development-mode files inherit the current user's profile permissions.
- Telemetry overcollection: the collector reads only process identity metadata (PID, parent PID, image name, start time) and TCP connection metadata (PID, state, endpoints, timestamp). It does not collect process command lines, file/application contents, keystrokes, passwords, browser history, or decrypt encrypted traffic.
- Agent report replay: event IDs are unique per device and persisted by the API, so buffered retries are acknowledged without duplicate event or alert rows.
- Observe-only detection: new listener, configured high outbound-count threshold, and repeated report failures produce evidence-backed events. The agent has no process termination or traffic-blocking capability.
- Unauthorized firewall changes: proposals are inert; apply and rollback require an authenticated administrator confirmation. A preview token binds approval to the proposal. Automatic rule creation is disabled.
- Overbroad firewall rules: only inbound IP/CIDR + TCP/UDP + one port Block rules are accepted, with a mandatory expiry. Loopback, resolved API backend addresses, and configured administrator management addresses are protected. New management addresses cannot conflict with pending or active rules.
- Unrelated firewall rule deletion: the agent addresses only rules carrying the exact generated `SentryGate-<id>` name, `SentryGate` group, and managed description. It never disables the Windows Firewall. Filter drift is reported as failure, not silently overwritten. Uninstall cleanup uses the same ownership checks.
- Delayed rollback/expiry: dashboard state remains pending until the enrolled agent reconnects and reports Windows state. Approved policy is DPAPI-protected locally so expiry can be enforced during backend outages; the agent must be running.
- Privilege expansion: foreground agent mode needs no elevation. The default Windows service runs as LocalService. Firewall application requires the explicit `-EnableFirewallManagement` installer option and a second typed confirmation, which runs the entire agent service as LocalSystem. This is a significant privilege increase and expands impact if the agent or its dependencies are compromised; use only on a device the operator administers.

## Non-Goals

- SentryGate does not intercept private app contents.
- SentryGate does not decrypt encrypted traffic.
- SentryGate does not claim an IP address identifies a person.
- Milestone 2 does not proxy WebSocket upgrades.
- The agent currently reports TCP connection metadata only; UDP inventory and process termination are not implemented.
- The gateway is a local single-process evaluation service, not a production edge deployment.
