# SentryGate

SentryGate is a local-first security dashboard for systems you own or administer. The enrolled Windows endpoint agent reports process and TCP connection metadata and explainable observe-only alerts. Milestone 4 adds manually approved, narrowly scoped firewall rules; it does not create automatic blocks, terminate processes, inspect file contents, capture keystrokes, read passwords, inspect browser history, or decrypt network traffic.

## Project layout

```text
apps/
  api/                 Node API, SQLite migrations, website gateway, tests, demo commands
  web/                 Vanilla JavaScript dashboard
  agent/               Windows CIM/TCP collector, detection, DPAPI spool, service scripts
packages/shared/       Shared contract notes
docs/                  Threat model and deployment instructions
.env.example           Local configuration template
```

The stack uses Node.js 24+, built-in `node:sqlite`, built-in HTTP, and no npm runtime dependencies. The API/database and gateway run locally. The Windows service host is built from the included C# source using the .NET Framework compiler.

## Dashboard development (Windows PowerShell)

From the repository root:

```powershell
Copy-Item .env.example .env
$secret = node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"
$envText = (Get-Content .env -Raw) -replace '^SENTRYGATE_SESSION_SECRET=.*$', "SENTRYGATE_SESSION_SECRET=$secret"
[System.IO.File]::WriteAllText((Resolve-Path .env), $envText, [System.Text.UTF8Encoding]::new($false))
npm test
npm run typecheck
npm run build
npm run dev
```

Open [http://127.0.0.1:4300](http://127.0.0.1:4300). The first visit prompts you to create the administrator; there is no default password. Passwords are stored as salted scrypt hashes. Keep `.env` and `apps/api/data` private. The dashboard/API and website gateway bind to loopback by default.

If the default ports are occupied, set alternate ports before starting the API. For example, this workspace currently runs the dashboard/API on `4301` and gateway on `4312`:

```powershell
$env:SENTRYGATE_PORT = '4301'
$env:SENTRYGATE_GATEWAY_PORT = '4312'
npm run dev
```

## Demonstration data

In a second terminal, run:

```powershell
npm run demo:agent
```

The dashboard then shows a clearly marked **simulated** Windows device, a synthetic process/TCP snapshot, and one simulated “new listening TCP port” alert. This inserts demonstration rows into the configured local SQLite database; it does not enroll a real computer or collect host telemetry. The first admin account must be created in the dashboard before the data can be viewed.

## Enroll and run a real Windows agent

In **Devices**, enter a display name and the Windows device hostname/version, then choose **Create enrollment credential**. The credential is displayed once. In an ordinary PowerShell terminal on that Windows computer, from the repository root, save it using the protected prompt:

```powershell
$deviceId = Read-Host 'Device ID from SentryGate'
& .\apps\agent\scripts\configure-agent.ps1 -DeviceId $deviceId -ApiBaseUrl 'http://127.0.0.1:4300' -AgentRoot "$env:LOCALAPPDATA\SentryGate\Agent"
npm run agent:dev -- --once
```

The configure script prompts for the credential without echoing it and protects it with Windows DPAPI for the current user. For continuous foreground development, omit `--once`:

```powershell
npm run agent:dev
```

The dashboard is configured to collect process metadata, TCP connection metadata, sample every 30 seconds, alert at 40 established non-local TCP connections for one process, and retain device events for 30 days. Change these settings from the device detail page. The collector refreshes policy using its device credential before sampling.

### Install as a Windows service

Enrollment happens in the dashboard first. Open **an elevated PowerShell session** on the target computer in the repository directory and run:

```powershell
$deviceId = Read-Host 'Device ID from SentryGate'
& .\apps\agent\scripts\install-agent.ps1 -DeviceId $deviceId -ApiBaseUrl 'http://127.0.0.1:4300'
Get-Service SentryGateAgent
```

Administrator permission is required to register the service and protect its credential for the machine. Program files go under `%ProgramFiles%\SentryGate\Agent`; DPAPI-protected configuration and the event queue go under `%ProgramData%\SentryGate\Agent`, with access restricted to LocalService, SYSTEM, and Administrators. The service runs as LocalService, not LocalSystem. It requires Node.js 24+ and the .NET Framework C# compiler. Use HTTPS for a remote API; plain HTTP is suitable only for loopback development.

### Firewall management (Milestone 4)

Firewall management is preview-only until an administrator explicitly approves a specific rule in **Firewall**. Automatic rule creation is disabled. Rules are inbound blocks only, scoped to one IP/CIDR, TCP/UDP port, enrolled device, and mandatory expiry (maximum one year). Loopback, the configured API address, and administrator management IPs are rejected. Add management IPs on the Firewall page before proposing rules. The agent receives approved policy using its per-device credential, stores the policy with DPAPI, removes expired rules locally while offline, and reports observed Windows rule state when connected.

The default service remains LocalService and cannot apply firewall rules. To opt into firewall management on a device you administer, reinstall the agent from **elevated PowerShell** and explicitly confirm the installer prompt. This runs the entire agent as LocalSystem, a broad privilege increase; use the foreground agent for preview/testing and only enable the service option when needed:

```powershell
& .\apps\agent\scripts\uninstall-agent.ps1
& .\apps\agent\scripts\install-agent.ps1 -DeviceId $deviceId -ApiBaseUrl 'http://127.0.0.1:4300' -EnableFirewallManagement
```

The Windows adapter uses supported `NetSecurity` PowerShell cmdlets. It creates only inbound Block rules with the `SentryGate` group, a generated `SentryGate-<rule-id>` name, and a managed-rule description. It never disables Windows Firewall. If an existing owned identifier has filters different from the approved preview, it reports failure rather than overwriting it. Rollback and expiry are queued until an authenticated agent sync; the dashboard shows pending state and then the device-reported result. The service must be running to enforce expiry while the backend is unavailable.

#### Harmless Windows verification

First run the app, enroll a test device in **Devices**, configure and run the agent on that Windows device, then set management IPs in **Firewall**. Do not use a production source address. In the dashboard, preview `198.51.100.24/32`, TCP, port `65000`, a short expiry such as ten minutes, and synthetic test evidence. Review the exact device and expiry; approve only if correct. After the agent reports **Active**, use elevated PowerShell to verify the owned rule (enter the UUID shown in the dashboard):

```powershell
$ruleId = Read-Host 'Firewall rule UUID from SentryGate'
Get-NetFirewallRule -Name "SentryGate-$ruleId" -Group 'SentryGate' | Format-List Name,DisplayName,Group,Direction,Action,Enabled,Description
Get-NetFirewallRule -Name "SentryGate-$ruleId" -Group 'SentryGate' | Get-NetFirewallAddressFilter | Format-List RemoteAddress
Get-NetFirewallRule -Name "SentryGate-$ruleId" -Group 'SentryGate' | Get-NetFirewallPortFilter | Format-List Protocol,LocalPort
```

Choose **Rollback** for that rule in the dashboard and confirm. Wait for **Removed**, then verify:

```powershell
Get-NetFirewallRule -Name "SentryGate-$ruleId" -Group 'SentryGate' -ErrorAction SilentlyContinue
```

No output means the rule is absent. This procedure checks rule configuration; it does not send traffic or alter any other firewall rule. To exercise preview and rollback without Windows firewall access or modifying the local machine, run the isolated mock demo:

```powershell
npm run demo:firewall
```

To stop and uninstall the service from elevated PowerShell:

```powershell
& .\apps\agent\scripts\uninstall-agent.ps1
Get-Service SentryGateAgent -ErrorAction SilentlyContinue
```

Uninstall removes the service and program files. It leaves local telemetry/configuration data by default. To remove those data too, pass `-RemoveData`. Revoke the device credential in **Devices** as a separate step.

## Agent data and detection

The collector uses Windows CIM `Win32_Process` and `Get-NetTCPConnection`. It stores PID, parent PID, process name/start time, TCP state, local/remote endpoint, and observation timestamps only. It does not collect process command lines, file contents, credentials, keystrokes, browser data, or decrypted traffic. TCP metadata is supported; UDP socket inventory is not currently collected.

Explainable observe-only rules establish a baseline for listening endpoints and then report newly observed listeners; compare a process's established non-local TCP connection count to its configured threshold; and emit one alert after three consecutive failed report attempts. Evidence includes the observed endpoint/PID or exact count/threshold, and all events state that no process or network action was taken. Reports use unique event IDs, per-device bearer credentials, server-side SHA-256 verifiers, TLS for remote deployment, and API acknowledgement before removing buffered events. Local credential and event payload protection uses Windows DPAPI. The outbox retains encrypted payloads and minimal event IDs/timestamps in SQLite while disconnected.

### Incident investigation (Milestone 5)

Incidents are created only when distinct, non-informational events meet the configured threshold for the same owned asset (or explicitly linked computer), observed IP, exact detection rule, and correlation window. Default threshold is three events within ten minutes. Website, application, and device records are preserved as evidence; unrelated assets, endpoints, rules, allowlisted events, and informational events do not correlate. The correlation is an investigative grouping, not proof of common authorship or intent. An IP address, user agent, or hostname is never presented as a verified person's identity.

Open **Investigation** to filter incidents by observed IP, device, website, rule, severity, status, and time. The detail view separates recorded facts from inference, includes the event timeline and audit trail, and supports analyst notes, status changes, and JSON/PDF reports. A firewall action is included only when an administrator explicitly links a proposal to an incident; its configured rule target is labeled as configuration, not an observed source. Automatic firewall blocking remains disabled.

From the repository root, start the dashboard in one PowerShell terminal:

```powershell
npm run dev
```

In a second terminal at the same repository root, generate synthetic related website, application, and device events:

```powershell
npm run demo:incidents
```

Sign in at [http://127.0.0.1:4300](http://127.0.0.1:4300), create the first administrator if this is a fresh database, then open **Investigation** and select the new website and workstation incidents. The generated records use `198.51.100.77` (documentation-only) and are marked synthetic; this command sends no traffic and applies no firewall changes. If the API uses a custom `SENTRYGATE_DB_PATH`, set the same value in both terminals before running either command.

Correlation threshold/window and raw-event/report retention are configurable under **Settings**. Retention cleanup removes old raw event evidence (which also removes incident evidence links by cascade) and expires stored report snapshots; run cleanup from Settings after changing policy. JSON/PDF exports are snapshots and expire under the configured report retention. Audit records remain available according to the existing audit retention cleanup.

### Response suggestions (Milestone 6)

Create policies on **Actions**. Each policy is fixed to **suggestion-only** mode and evaluates the chosen asset, minimum severity, event count, exact detection rule (or `*`), and rolling time window. A qualifying incident creates one idempotent proposal with the contributing event IDs and evidence, the observed IP as a single-host target, destination, expected effect, and expiry. Allowlists, loopback, configured administrator management IPs, trusted proxies, and device-reported backend addresses suppress unsafe proposals and are checked again at approval. Automatic blocking is disabled.

Website approvals install a temporary SentryGate-owned gateway deny entry. Device approvals create a SentryGate-owned Windows rule and remain **approved / awaiting agent** until the enrolled agent reports actual operating-system state. Expiry queues device-rule removal; the dashboard does not call removal successful until the agent confirms it. A removal failure raises a high-severity alert. Emergency pause stops new suggestions and approvals but does not silently alter already active rules. Use **Actions** to approve, inspect state, or roll back.

Safe local demonstration, from the repository root:

```powershell
npm run dev
```

Sign in at [http://127.0.0.1:4300](http://127.0.0.1:4300), create the first administrator on a fresh database, and in a second PowerShell terminal run:

```powershell
npm run demo:incidents
```

The command creates a suggestion-only policy and proposed action for the generated demo website: severity `high`, threshold `3`, window `10` minutes, and a five-minute duration. The incident has three synthetic events from `198.51.100.77`; review the event evidence and proposed effect on **Actions**, approve it explicitly, then choose **Rollback**. This demonstrates proposal → administrator approval → rollback using a local gateway block only. It sends no external traffic and does not modify Windows Firewall. For a separate preview/rollback walkthrough against mocked Windows firewall operations, run:

```powershell
npm run demo:firewall
```

To run the complete incident-policy proposal → approval → rollback flow in an isolated in-memory API and database, without touching the dashboard database, run:

```powershell
npm run demo:actions
```

Do not approve a device-target action on a real computer unless you administer it and have reviewed its exact IP, port, and expiry. Keep automatic blocking disabled.

## Tests and checks

```powershell
npm test
npm run typecheck
npm run build
```

Existing gateway behavior remains available: `npm run sample:site` starts the local HTTP upstream, and `npm run demo:gateway` runs the safe gateway smoke test. WebSocket upgrades are not supported by the website gateway. Do not route a production domain through this local development setup.

Review [docs/threat-model.md](docs/threat-model.md) and [docs/deployment.md](docs/deployment.md) before deployment. Firewall changes remain administrator-approved only; SentryGate does not create automatic blocks or disable the existing firewall.
