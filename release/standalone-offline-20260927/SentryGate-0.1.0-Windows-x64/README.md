# SentryGate

The Windows installer creates a separate, loopback-only SentryGate installation on each computer. It requires no central server, account service, VPN, or internet after the package is copied locally. See [INSTALL-WINDOWS.md](INSTALL-WINDOWS.md) for exact setup, service, health, backup/restore, offline update, and uninstall commands. The isolated two-installation test is `npm run test:standalone`.

SentryGate is local-first: security records stay in the configured host-local SQLite data directory; no cloud database/object storage, analytics, crash uploads, or external AI API is used. See [local storage, backup, offline behavior, and network destinations](docs/local-only-privacy.md). SQLite is not internally encrypted; use BitLocker/full-volume encryption and restrictive ACLs.

Configure local storage on Windows after creating `.env` from `.env.example`:

```powershell
if (-not (Test-Path -LiteralPath .env)) { Copy-Item .env.example .env } else { Write-Host 'Preserving existing .env configuration.' }
.\scripts\configure-storage.ps1 -DataDirectory 'D:\SentryGate\Data' -MaxDatabaseBytes 2147483648 -WarningPercent 80 -MinimumFreeDiskBytes 1073741824
```

The script updates only storage settings and preserves other `.env` values. It does not move existing data; stop SentryGate, back up and verify locally, migrate/restore the DB into the chosen directory, then restart. In the Settings page, check the displayed path, usage, cap, and free-space warning.

SentryGate is a local-first security dashboard for systems you own or administer. The enrolled Windows endpoint agent reports process and TCP connection metadata and explainable observe-only alerts. Milestone 4 adds manually approved, narrowly scoped firewall rules; it does not create automatic blocks, terminate processes, inspect file contents, capture keystrokes, read passwords, inspect browser history, or decrypt network traffic.

## Project layout

```text
apps/
  api/                 Node API, SQLite migrations, website gateway, tests, demo commands
  web/                 Vanilla JavaScript dashboard
  agent/               Windows CIM/TCP collector, detection, DPAPI spool, service scripts
packages/shared/       Shared contracts and local/private network policy
scripts/               Windows lifecycle, offline packaging, and storage helpers
docs/                  Threat model and deployment instructions
.env.example           Local configuration template
```

The stack uses Node.js 24+, built-in `node:sqlite`, built-in HTTP, and no npm runtime dependencies. The API/database and gateway run locally. The Windows service host is built from the included C# source using the .NET Framework compiler.

Milestone 8 adds HTTPS listeners for controlled deployment, session revocation and sign-in throttling, per-site gateway outage behavior, bounded local/API storage with scheduled retention, structured operational logs, SQLite backup/restore, heartbeat alerts, and an isolated synthetic load test. Local loopback HTTP remains available only for development. See [the controlled-pilot deployment runbook](docs/deployment.md) and [updated threat model](docs/threat-model.md); this is not a production-readiness certification.

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

## Local Installation Runtime

The installer package has no npm runtime dependencies. It includes a portable Node.js runtime and uses Node's built-in SQLite, HTTP(S), and cryptography modules. Node.js 24+ and npm are needed only for development, tests, and creating the offline package. The Windows agent's optional service installer additionally needs the Windows .NET Framework C# compiler. No runtime internet access is required for the dashboard, API, database, or local analysis worker.

For a local install from this checkout, create `.env` only when it does not already exist, then start the complete local application:

```powershell
if (-not (Test-Path -LiteralPath .env)) { Copy-Item .env.example .env }
.\scripts\start-sentrygate.ps1
```

Open `http://127.0.0.1:4300`. The script uses `%LOCALAPPDATA%\SentryGate\Data` for SQLite and `%LOCALAPPDATA%\SentryGate\Runtime` for logs and process state; it generates and DPAPI-protects a session secret when one is not configured. The API and website gateway bind to `127.0.0.1`; local analysis runs as a separate process and can be disabled in Settings.

```powershell
.\scripts\health-sentrygate.ps1
.\scripts\stop-sentrygate.ps1
```

Make a local backup and restore it with explicit confirmation (restore stops and restarts the application):

```powershell
$backup = Join-Path $env:LOCALAPPDATA "SentryGate\Backups\sentrygate-$(Get-Date -Format yyyyMMdd-HHmmss).db"
New-Item -ItemType Directory -Force (Split-Path $backup) | Out-Null
.\scripts\backup-sentrygate.ps1 -OutputFile $backup
.\scripts\restore-sentrygate.ps1 -Source $backup -Confirm
```

To stage a self-contained offline runtime package, run this on a development machine with Node.js 24+:

```powershell
.\scripts\package-local.ps1 -OutputDirectory 'D:\SentryGate-Offline'
```

Transfer that directory using your approved offline process. On the target computer, start it with `& 'D:\SentryGate-Offline\scripts\start-sentrygate.ps1'`; the bundled Node executable is used and no npm install is performed. Configure storage, backups, and restore with scripts under `scripts`. Backups must remain on a local filesystem. See [local-only privacy and network behavior](docs/local-only-privacy.md).

Remote dashboard/API access is intentionally disabled. To enable it, set `SENTRYGATE_REMOTE_ACCESS_ENABLED=true`, configure a certificate and matching key, and bind the API to the intended private interface. Accounts still require authenticated sessions. Do not expose the listener directly to the public internet. Agent credentials only permit enrolled-agent API operations. The website gateway's non-loopback listener also requires TLS. Keep the default loopback configuration unless remote administration is specifically required.

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

Enrollment happens in the dashboard first. On the target computer, create an owner-approved enrollment credential. Run the following from **elevated PowerShell** in the installed SentryGate directory (or repository root during development). The installer runs the monitor as `NT AUTHORITY\LocalService`, uses a bundled Node runtime when present, and installs it for automatic startup with Windows restart-on-failure recovery (5, 15, then 60 seconds). The monitoring service does not require the separate firewall helper.

```powershell
$deviceId = Read-Host 'Device ID from SentryGate'
& .\apps\agent\scripts\install-agent.ps1 -DeviceId $deviceId -ApiBaseUrl 'http://127.0.0.1:4300'
Start-Service SentryGateAgent
Get-Service SentryGateAgent
sc.exe qfailure SentryGateAgent
```

Administrator permission is required to register the service, set recovery actions/ACLs, and protect its credential with machine DPAPI. Program files go under `%ProgramFiles%\SentryGate\Agent`; protected configuration, baseline, and encrypted event queue go under `%ProgramData%\SentryGate\Agent`. The installer preserves the app/shared module layout so it runs from the offline package without npm or network access. If no bundled Node runtime is present, Node.js 24+ and the .NET Framework C# compiler are required at install time. Use HTTPS for a remote API; plain HTTP is suitable only for loopback development. The **Devices** detail page displays the last authenticated Windows service state/start mode reported by the agent and its heartbeat health. A stopped or unreachable service is reflected as stale/offline after the heartbeat window.

To check, start, stop, or uninstall the agent from elevated PowerShell:

```powershell
Get-Service SentryGateAgent
sc.exe qfailure SentryGateAgent
Start-Service SentryGateAgent
Stop-Service SentryGateAgent
& .\apps\agent\scripts\uninstall-agent.ps1
```

Uninstall removes the monitoring and optional firewall-helper services and SentryGate-owned temporary rules only. It keeps enrollment data by default; add `-RemoveData` only when you also intend to delete the local protected spool/configuration. Revoke the device credential from **Devices**. Windows Firewall itself is never disabled.

### Observe, Recommend, and Enforce

Every new policy starts in **Observe**. Observe records evidence and alerts only; Recommend creates a specific expiring proposal for owner review; Enforce is restricted to an enrolled computer and requires both an individually enabled Enforce policy and a separate owner-confirmed global gate. The global Enforce gate defaults off, including on upgrades. Before enabling it, install and verify the separate privileged firewall helper; the helper remains independently controlled from the dashboard. A policy action is scoped to the incident's observed single IP, one destination computer, protocol/port, threshold/window, and expiry. Protected management/backend/trusted-proxy addresses and existing website allowlists are rechecked, and no more than ten active temporary blocks are permitted by default (the owner may set a 1–50 cap on the Actions page). The system only creates SentryGate-owned inbound rules, verifies state on agent sync, expires/removes them, and records rollback state. Emergency pause stops future automated actions; existing temporary rules remain until expiry or rollback. The Actions page supports restoring the previous enabled/mode policy state, recorded in audit history.

Run the isolated local demonstration to see Observe record events without proposing, then Recommend create a pending action with no firewall or gateway change:

```powershell
npm run demo:policy-modes
```

The demo uses an in-memory database and synthetic documentation-range IPs. Enforce stays disabled and no operating-system firewall API is called.

### Firewall management (Milestone 4)

Firewall management is preview-only until an administrator explicitly approves a specific rule in **Firewall**. Automatic rule creation is disabled. Rules are inbound blocks only, scoped to one IP/CIDR, TCP/UDP port, enrolled device, and mandatory expiry (maximum one year). Loopback, the configured API address, and administrator management IPs are rejected. Add management IPs on the Firewall page before proposing rules. The agent receives approved policy using its per-device credential, stores the policy with DPAPI, removes expired rules locally while offline, and reports observed Windows rule state when connected.

The monitoring agent remains `LocalService`. To opt into firewall management on a device you administer, install the separate `SentryGateFirewallHelper` from **elevated PowerShell** with the explicit switch and interactive confirmation. The helper alone runs as LocalSystem; the monitoring agent is still configured as LocalService:

```powershell
& .\apps\agent\scripts\uninstall-agent.ps1
& .\apps\agent\scripts\install-agent.ps1 -DeviceId $deviceId -ApiBaseUrl 'http://127.0.0.1:4300' -EnableFirewallManagement
```

The Windows adapter uses supported `NetSecurity` PowerShell cmdlets. It creates only SentryGate-owned inbound rules with generated `SentryGate-<rule-id>` or `SentryGate-App-<policy-id>` names and managed-rule descriptions. Application allow/block policies affect inbound traffic for one observed executable only. It never disables Windows Firewall. If an existing owned identifier has filters different from the approved preview, it reports failure rather than overwriting it. The helper's local timer removes newly created expired owned rules even while the backend is unavailable; the dashboard reconciles the reported OS state when the agent reconnects. The helper must remain running for offline expiry cleanup.

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

## Milestone 7: multiple assets and administrators

Each protected website has its own encrypted-at-rest gateway credential; the gateway presents it only for that website's event submissions. Each Windows enrollment is linked to exactly one computer asset (a dedicated computer asset is created automatically if you do not select one) and has its own agent credential. Rotating or revoking one credential does not change any other asset. A computer asset cannot be linked to a second active agent.

The asset list and asset investigation view show connection state, agent version/heartbeat, recent evidence, alerts, configuration delivery, and SentryGate-owned rules. Website thresholds and allowlists are already stored per website. Device settings are queued by version per device; the agent retries the latest pending version after reconnecting and acknowledges it with its device credential. Status is visible as pending/applied/failed.

The first administrator is an `owner`. Owners can create additional administrators through the authenticated API (`POST /api/admins`) with `email`, a 12-character-minimum `password`, and role `owner`, `security_analyst`, or `read_only_viewer`. Analysts can add incident notes, change incident status, and create suggestion-only policies. Viewers have read-only API access. All other writes, including enrollment, credential lifecycle, website settings, and firewall approvals, are owner-only; enforcement is in the API.

Asset removal is a soft removal, retains historical evidence, and revokes the linked agent credential. The API refuses to remove a computer while any SentryGate-owned rule remains proposed, active, failed, expired-awaiting-verification, or pending removal. Roll back the rule and wait for the agent to report it removed, then retry. For websites, active gateway actions must be rolled back or expire first. No unrelated firewall rule is touched.

### Two-site / two-agent local demo

Start SentryGate and create the owner account using the setup commands above. In **Protected Assets**, register `Demo Site A` and `Demo Site B`, each with its own sample upstream address; configure each website separately. In a second PowerShell terminal, start a sample site:

```powershell
$env:SAMPLE_SITE_PORT = '4320'
npm run sample:site
```

For a second sample website, open another terminal and run the sample site on port `4321` (the sample script reads `SAMPLE_SITE_PORT`). Set Site A upstream to `http://127.0.0.1:4320` and Site B to `http://127.0.0.1:4321`; use the distinct gateway paths shown in each website's Configure panel. Configure a different threshold or allowlist per website to confirm settings do not bleed across assets.

Enroll two simulated Windows agents as separate devices (omit **Computer asset** to auto-create a distinct asset for each). The dashboard returns a one-time credential for each. For safe API-only simulation, use separate device identities and credentials with the agent development script or the enrollment UI; `npm run demo:agent` remains a single clearly marked synthetic fixture and does not enroll a host. Verify each computer's asset page shows only its own heartbeat, snapshot, events, config queue, and rules. A website credential rotated under its asset remains isolated from the other site. Never route a production domain through this local demo.

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

Review [docs/threat-model.md](docs/threat-model.md), [docs/deployment.md](docs/deployment.md), and [docs/pilot.md](docs/pilot.md) before deployment. Milestone 9 adds a safe loopback simulation, pilot preflight checks, dashboard measurements, JSON reports, and a scoped rollback command. Do not route a live website until local and staging gates pass and you approve the change. Firewall changes remain administrator-approved only; SentryGate does not create automatic blocks or disable the existing firewall.

### Offline local analysis (Milestone 10)

Offline analysis is optional and disabled by default. It reads only event metadata already in the local SQLite database; it does not install or download a model, call a cloud AI API, collect additional host data, or enforce firewall rules. The API, gateway, and Windows agent are separate processes and continue independently if the analysis worker is stopped. Analysis produces reviewable leads only.

Start the dashboard/API in one PowerShell terminal:

```powershell
npm run dev
```

Create the administrator on first use, then open **Offline Analysis** and configure thresholds, batch size, polling, retention, and enablement. In another terminal start the optional worker:

```powershell
npm run analysis:worker
```

Alternative local controls (same `.env` and database path as the API):

```powershell
npm run analysis:status
npm run analysis:enable
npm run analysis:disable
```

Enabling analysis does not start its worker; run `npm run analysis:worker` separately. Ctrl+C stops only the worker. The worker stores its event-ID cursor and findings in SQLite, reads at most the configured batch size (maximum 500), uses idempotent finding keys, and resumes after a restart. Finding retention is configurable on **Offline Analysis**; raw events remain governed by existing event retention. Feedback changes threshold multipliers only after at least three reviews per rule category; false-positive-heavy feedback raises thresholds by 25%, useful-heavy feedback lowers them by 10%, and the base settings remain visible.

The explainable rules group repeated sensitive-path events by asset and gateway-observed endpoint, compare per-endpoint request windows against a rolling local history plus a configured floor, and compare Windows outbound-connection-volume event metadata against a process-name history or configured floor. Evidence snapshots include event IDs and observed fields. The displayed 0–100 heuristic score is not a calibrated attack probability. Results are not proof of attack, intent, or identity. Connection baselines are necessarily sparse because this milestone analyzes event rows and does not turn routine process snapshots into new events. If event retention removes source rows, the finding snapshot remains until its own retention expires.

Run the documented synthetic resource measurement from PowerShell:

```powershell
npm run analysis:benchmark
npm run analysis:benchmark -- 10000
```

The benchmark creates and deletes an isolated temporary SQLite database, measures elapsed analysis time, throughput, p95 batch latency, process CPU time, RSS growth, and database bytes, and generates synthetic normal traffic, baseline windows, a request burst, and sensitive-path events. Results are specific to the local machine and synthetic sample; they are not a capacity promise. Statistical baselines need comparable event history and have limited value for new endpoints or sparse hosts. The current analyzer does not inspect packet contents, derive identity, use ML, create proposed actions, or analyze process snapshots beyond events already stored.

### Windows host security controls (Milestone 11)

The endpoint inventory uses Windows CIM (`Win32_Process`, `Win32_Service`), `Get-NetTCPConnection`, uninstall and startup registry metadata, startup-folder file names, `Get-NetFirewallProfile`, and `Get-MpComputerStatus`. It reports executable paths and process IDs to map listening sockets to processes. It does not use `Win32_Product`, read file contents, collect process command lines or startup arguments, inspect browser/application contents, record keystrokes, or inspect passwords. Collection for each inventory class is independently configurable from **Devices → device → Collection settings**; event retention uses that device's existing retention setting.

**Windows permissions by feature**

- Foreground development and ordinary inventory need a supported Windows PowerShell, Node.js 24+, and access under the current user to query current-user uninstall/Run registry keys, CIM metadata, TCP metadata, service metadata, and startup-folder names. Some Defender or firewall status providers may be unavailable to a non-admin identity; the agent records that limitation rather than changing the setting.
- Installed service mode requires one elevated PowerShell install to copy application files under Program Files, create ProgramData storage, configure DPAPI-protected credentials, and register `SentryGateAgent` as `NT AUTHORITY\LocalService` with a dedicated Windows service SID. The protected data directory and helper pipe grant access to that service SID rather than all LocalService processes. This monitoring service is not LocalSystem and does not need administrator privileges for its ordinary reporting loop.
- Actual firewall application-policy changes are optional. Installing `SentryGateFirewallHelper` requires the separate `-EnableFirewallManagement` switch and an interactive `INSTALL HELPER` confirmation from elevated PowerShell. That helper runs as LocalSystem because supported Windows Firewall cmdlets require elevation. Only the dedicated agent service SID can call its named pipe or read its DPAPI-protected HMAC key; the helper rejects replayed/expired envelopes, validates each command, and invokes the fixed SentryGate firewall script. A local helper sweep removes expired, ownership-marked rules every 30 seconds, including while the backend is unavailable; the dashboard's last reported state is reconciled on agent reconnect. The script changes only rules in group `SentryGate` with SentryGate names/descriptions. It cannot disable Windows Firewall or edit unrelated rules. Dashboard enforcement is off by default, every rule needs a preview and explicit owner approval, and automatic blocking remains disabled.
- Administrator approval and policy changes are owner-only backend operations, audited with target, evidence, reason, expiry, approver, and resulting OS state. A disconnected device leaves an action pending; after reconnect it reports observed rule state. The agent continues inventory/reporting if the helper is missing or unavailable.

**Safe local demonstration (no Windows API collection or firewall operation)**

In one PowerShell terminal:

```powershell
npm run dev
```

On a fresh database, create the first administrator at [http://127.0.0.1:4300](http://127.0.0.1:4300). In another repository-root terminal:

```powershell
npm run demo:host-security
```

Open **Devices** and inspect the simulated computer. The fixture shows an application/process owning a listener, installed app/service/startup metadata, a synthetic disabled-Defender checkup finding, and associated alerts. It does not enroll a real device or touch Windows Firewall. On **Firewall**, per-application enforcement should say **Preview only**. A simulated device cannot receive a policy command.

**Review, disable, rollback, and uninstall**

1. Keep the Firewall page's per-application enforcement switch off for observe/preview-only operation. Turning it on requires an owner, a browser confirmation, and a second explicit approval for each temporary policy. Turning it off queues removal of existing SentryGate application rules; leave the agent/helper running until the dashboard reports removal verified.
2. To stop monitoring without uninstalling (elevated PowerShell):

```powershell
Stop-Service SentryGateAgent
```

To stop the optional helper too:

```powershell
Stop-Service SentryGateFirewallHelper -ErrorAction SilentlyContinue
```

3. To uninstall (elevated PowerShell, from the repository root), which stops both services and removes only matching SentryGate-owned rules before deleting the services and program files:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\apps\agent\scripts\uninstall-agent.ps1
```

To also delete the agent's DPAPI-protected local queue/configuration after uninstall:

```powershell
.\apps\agent\scripts\uninstall-agent.ps1 -RemoveData
```

Revoke the device credential in the dashboard separately; uninstall cannot revoke a credential while offline. Never use `-RemoveData` before preserving events needed for investigation. The uninstall script matches only SentryGate's own group, name, and description markers.

The helper is a pilot-stage local service, not a substitute for a Windows security baseline. Review the preview against actual application/access requirements before enabling enforcement. Controls target inbound application traffic only; they do not provide application sandboxing, outbound control, kernel protection, or tamper resistance against a local administrator.
### Windows installer (Milestone 13)

Build an offline-capable Windows x64 PowerShell/ZIP release on Windows with Node.js 24+:

```powershell
npm test
npm run typecheck
npm run build
.\scripts\build-release.ps1 -OutputDirectory .\release
Get-FileHash .\release\SentryGate-0.1.0-Windows-x64.zip -Algorithm SHA256
```

The generated release contains `INSTALL-WINDOWS.md`, a private Node runtime, the local backend/dashboard/SQLite code, the agent, and lifecycle scripts. No `.env`, database, or default administrator password is bundled. Extract it and run `Install-SentryGate.ps1` from ordinary PowerShell. It starts the dashboard locally, takes administrator setup through the dashboard, then requests UAC separately to install the automatically starting least-privilege Windows agent service. Firewall helper/rules remain uninstalled/unchanged; Observe and preview-only defaults remain in force. See [INSTALL-WINDOWS.md](INSTALL-WINDOWS.md) for setup, health, repair, upgrade, backup, restore, rollback, uninstall, and clean-VM qualification commands.
