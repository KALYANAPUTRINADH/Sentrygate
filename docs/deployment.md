# Deployment Instructions

Milestones 1-4 are intended for local development and evaluation. The API/dashboard and website gateway bind to loopback by default. The Windows agent is optional and explicitly enrolled. Firewall rules are preview-only until a logged-in administrator approves each proposal.

## Development

```bash
npm run dev:all
```

Open `http://127.0.0.1:4300`. The website gateway listens on `http://127.0.0.1:4310` by default. Use `npm run sample:site` in a second terminal to start the local upstream on port `4320`.

Do not route a production domain through the Milestone 2 gateway. WebSocket upgrades are not supported. Rate-limit counters are process-local and reset on restart. The local dashboard and proxy use plain HTTP; they are designed for loopback testing.

## Windows agent

The foreground agent runs as the interactive user and stores its credential with current-user DPAPI. Installing the Windows service requires administrator approval, registers `SentryGateAgent` as `NT AUTHORITY\LocalService`, protects its credential with machine-scope DPAPI, and restricts `%ProgramData%\SentryGate\Agent` to LocalService, SYSTEM, and Administrators. The service host launches the Node agent and propagates service stop requests. Uninstall removes the service and program files; local data is preserved unless explicitly requested for removal. Revoke the per-device credential from the dashboard when retiring a device.

The agent reports a heartbeat and bounded process/TCP metadata to the API. Its local SQLite outbox DPAPI-protects event payloads and deletes them only after API acknowledgement. Approved firewall specifications are separately DPAPI-protected so expiry and rollback can be processed while disconnected. The agent reports the exact observed state and per-rule failures after an authenticated sync. The API enforces configured per-device event retention during report ingestion; local buffered items older than the same policy are pruned on collection. Devices stale for more than three configured sample intervals are shown as stale. Endpoint detections remain observe-only; no automatic firewall rules are created.

The default LocalService agent cannot modify Windows Firewall. Enabling firewall application with `install-agent.ps1 -EnableFirewallManagement` requires an elevated PowerShell session and a typed confirmation; it changes the entire agent service to LocalSystem. This is a broad privilege grant, not an isolated helper. Assess that risk before opting in. The supported Windows interface is the `NetSecurity` PowerShell module. Only inbound, explicitly approved IP/CIDR + TCP/UDP + port block rules are managed, and expiry is mandatory. Never use this evaluation setup to route production traffic or to protect production availability.

For a non-mutating lifecycle demonstration, use `npm run demo:firewall`; it runs an in-memory API/database and mocked device responses, and does not invoke Windows firewall commands. To verify a real harmless rule on a test device and remove it, follow the PowerShell procedure in the root README. Uninstalling a registered agent removes only rules with the SentryGate generated name/group/description ownership markers; unrelated rules are left untouched.

Use HTTPS when the agent reports to an API on another host. The development API's loopback HTTP binding is not remotely reachable by design. Protect the SQLite database, `.env`, and backups. Do not run the service on a computer you do not administer.

## Future Deployment Requirements

Production use is outside this milestone. Before considering it, the gateway would need a deployment review, external TLS termination, monitoring, and distributed rate-limit storage.

- Serve the API and dashboard behind HTTPS.
- Set `SENTRYGATE_SESSION_SECRET` to a long random value.
- Keep `SENTRYGATE_SESSION_SECRET` stable: the gateway event credential's encrypted runtime copy is protected with this key.
- Store `SENTRYGATE_DB_PATH` on durable encrypted storage.
- Restrict file permissions on the database directory to the SentryGate service account.
- Configure backups for the SQLite database.
- Configure trusted proxy IPs only for exact immediate peers that you administer. Do not trust forwarded headers from arbitrary clients.
- Review audit logs after administrator setup and every gateway configuration change.

## Least Privilege

The dashboard/API needs read/write access to its configured database directory. Foreground agent mode needs current-user DPAPI and its local data directory. The default service runs under LocalService and has access only to its protected data directory; if Windows denies a metadata query, its health is reported as degraded rather than elevating further. The opt-in firewall mode changes the complete agent process to LocalSystem; keep it disabled unless the administrator accepts that privilege expansion and firewall changes are required.
