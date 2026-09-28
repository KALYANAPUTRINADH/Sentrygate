# Multi-Computer Private Deployment

SentryGate supports one self-hosted central API/dashboard and independently installed Windows agents. It uses local SQLite on the central host and a DPAPI-protected, per-computer event spool on each Windows host. It does not require a domain, hosted database, cloud storage, or telemetry service.

## Network and trust boundary

Create or use an administrator-controlled private VPN/overlay between the central computer and the computers you administer (for example, a self-managed WireGuard network). Assign stable private IP addresses, such as `10.77.0.1` for the central host and `10.77.0.11` through `.13` for agents. The agent initiates HTTPS requests to the central IP; it opens no listening control port. Do not port-forward SentryGate's TCP API port and do not expose it on a public interface. The VPN endpoint itself must be managed and secured separately.

The API and dashboard share a listener. Bind it only to the central VPN interface IP, require TLS with that exact IP in the certificate's `subjectAltName` as an `IP:` entry, and restrict VPN membership/routes so only administrators can reach the dashboard/API listener. SentryGate does not configure Windows Firewall, router ACLs, VPN policy, or NAT. Dashboard writes require an authenticated administrator session with owner authorization where applicable; each agent route also requires that computer's unique bearer credential over TLS. This is network restriction plus application authentication, not a substitute for a security review.

Example network plan (replace values with your private VPN allocation):

| Role | VPN address | Initiated SentryGate connection |
|---|---|---|
| Central SentryGate host | `10.77.0.1` | HTTPS listener TCP `4300` on its VPN interface only |
| Windows computer A | `10.77.0.11` | outbound HTTPS to `10.77.0.1:4300` |
| Windows computer B | `10.77.0.12` | outbound HTTPS to `10.77.0.1:4300` |
| Windows computer C | `10.77.0.13` | outbound HTTPS to `10.77.0.1:4300` |

No agent listener, inbound port, domain, or public DNS record is needed. If the VPN is unavailable, agents continue local observation and queue events. On recovery they resend stable event IDs; the central database ignores already-seen event IDs and acknowledges the spool only after database acceptance.

## Central host setup

Run on the central Windows host from the repository/release root in PowerShell. Obtain a certificate/key from a CA you control. The certificate must contain `IP:10.77.0.1`; install the CA trust on administrator browsers and every agent. Protect the private key and `.env` with Windows ACLs. Do not use `0.0.0.0` or the public/NAT interface as `SENTRYGATE_HOST`.

```powershell
Copy-Item .env.example .env
$secret = node -e "process.stdout.write(require('node:crypto').randomBytes(48).toString('base64url'))"
$envText = Get-Content .env -Raw
$envText = $envText -replace '^SENTRYGATE_SESSION_SECRET=.*$', "SENTRYGATE_SESSION_SECRET=$secret"
$envText += "`r`nNODE_ENV=production`r`nSENTRYGATE_HOST=10.77.0.1`r`nSENTRYGATE_GATEWAY_HOST=127.0.0.1`r`nSENTRYGATE_PORT=4300`r`nSENTRYGATE_REMOTE_ACCESS_ENABLED=true`r`nSENTRYGATE_TLS_CERT=C:/SentryGate/certs/central.crt`r`nSENTRYGATE_TLS_KEY=C:/SentryGate/certs/central.key`r`nSENTRYGATE_API_BASE_URL=https://10.77.0.1:4300`r`nSENTRYGATE_DATA_DIR=C:/ProgramData/SentryGate/Data`r`nSENTRYGATE_DB_PATH=C:/ProgramData/SentryGate/Data/sentrygate.db`r`n"
[IO.File]::WriteAllText((Resolve-Path .env), $envText, [Text.UTF8Encoding]::new($false))
# Restrict .env and the private key to Administrators and the dedicated backend service identity before deployment.
$env:NODE_EXTRA_CA_CERTS = 'C:\SentryGate\certs\private-ca.pem'
npm run dev
```

Create the first owner at `https://10.77.0.1:4300` from the central computer after trusting the CA. Verify the certificate from the central host and one remote private-network computer:

```powershell
Invoke-WebRequest https://10.77.0.1:4300 -UseBasicParsing | Select-Object StatusCode
Invoke-RestMethod https://10.77.0.1:4300/api/health
```

The health endpoint requires administrator authentication for non-loopback clients. Dashboard and device APIs are on the same port; network ACL/VPN membership must prevent non-administrator computers from accessing that listener. SentryGate never opens or changes firewall rules as part of this procedure. For production, run the backend under a restricted service manager and configure its data directory ACLs and backups per `docs/local-only-privacy.md`.

## Build an agent-only package

On a build host with Node.js 24+ and PowerShell:

```powershell
$bundle = Join-Path $env:TEMP 'SentryGate-Agent-0.3.0-Windows-x64'
& .\scripts\package-agent.ps1 -OutputDirectory $bundle
Get-FileHash "$bundle\SentryGate-Agent-0.3.0-Windows-x64.zip" -Algorithm SHA256
```

Verify the hash out of band, then copy the ZIP and CA certificate to each computer using your private administration channel. The bundle contains the agent files, shared policy helpers, private Node runtime, installer/upgrade/rollback scripts, and this document. It contains no device ID, credential, config, database, or event spool. **Build a fresh enrollment for every computer; never clone an installed agent's ProgramData folder or DPAPI files.**

## Enroll and install each computer

For each computer, sign in to the central dashboard as an owner, open **Devices**, create an enrollment with that computer's name and hostname, and securely transfer the one-time device ID and credential to that computer's administrator. Creation is the owner approval; enrollment is audited. The credential is shown once. Do not email or put it in command history. Transfer the ZIP, its expected SHA-256 verified out of band, and the CA PEM using your private administration channel. On each target, use a fresh extraction folder and verify before extracting:

```powershell
$archive = 'C:\SentryGate\Transfer\SentryGate-Agent-0.3.0-Windows-x64.zip'
$expectedSha256 = Read-Host 'Enter the SHA-256 verified through your separate trusted channel'
$actualSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
if ($actualSha256 -ne $expectedSha256.Trim().ToUpperInvariant()) { throw 'Agent package SHA-256 mismatch; do not install.' }
$bundle = 'C:\SentryGate\AgentBundle-0.3.0'
if (Test-Path -LiteralPath $bundle) { throw 'Bundle directory already exists; select a new path.' }
Expand-Archive -LiteralPath $archive -DestinationPath $bundle
Set-Location $bundle
```

On the target Windows computer, extract the verified bundle and run elevated PowerShell in the extracted bundle directory. The install command starts a Windows service with automatic startup and SCM recovery. It stores the unique credential using machine DPAPI, stores the event spool locally, and keeps the monitoring service at LocalService. Supply the CA PEM and, if needed, an individual per-device spool cap:

```powershell
$deviceId = Read-Host 'Paste this computer device ID'
& .\apps\agent\scripts\install-agent.ps1 `
  -DeviceId $deviceId `
  -ApiBaseUrl 'https://10.77.0.1:4300' `
  -CaCertificatePath 'C:\SentryGate\certs\private-ca.pem' `
  -SpoolMaxBytes 268435456
Get-Service SentryGateAgent
sc.exe qc SentryGateAgent
```

`configure-agent.ps1` securely prompts for the one-time credential. Remote HTTP is rejected; certificate validation is not disabled. After roughly one collection interval, inspect **Devices** on the central dashboard for health, contact time, version, policy version, open alerts, and per-computer evidence. Agent/API traffic is outbound HTTPS from the agent. Do not install the optional firewall helper for this procedure; firewall actions remain preview-only and automatic blocking is disabled.

## Offline, retention, and revocation

The per-computer encrypted spool defaults to 256 MiB and a 30-day age window. Use `-SpoolMaxBytes` at installation for a per-device size cap (minimum 1 MiB, maximum 10 GiB); it is stored in that machine's local agent configuration. The server-provided per-device **Retain device events (days)** setting governs both central event cleanup and the agent spool's age pruning. The central server has its own overall database cap (`SENTRYGATE_MAX_DB_BYTES`, default 2 GiB) and global incident/report retention under **Settings**. Each event is sent with a stable UUID; the central database deduplicates retries, and the agent removes it only after acknowledgement.

To revoke one computer immediately, an owner opens **Devices → Inspect → Revoke device**. Revocation denies its old credential on report, policy/configuration, and command endpoints; other devices are unaffected. If a device is offline, revoke it as soon as compromise is suspected; its queued events cannot be accepted after revocation. Preserve/review local evidence before uninstalling.

Device firewall/application policies are addressed by exact device ID. Backend validation ties proposals and approvals to that device's registered computer asset; agent routes are device-scoped. Every operating-system change still requires the existing preview and explicit owner approval. No central policy silently changes another device or creates an automatic block.

## Staged updates and rollback

Build and hash a new agent-only bundle. Pilot it on one selected computer first; inspect its version, health, and reporting before updating another. On the target, run from the extracted candidate bundle in elevated PowerShell:

```powershell
& .\apps\agent\scripts\upgrade-agent.ps1 -BundleDirectory (Get-Location).Path
Get-Service SentryGateAgent
```

Upgrade snapshots the old Program Files binaries to `C:\Program Files\SentryGate\Agent.rollback-<timestamp>` and preserves the separate ProgramData DPAPI credential and event spool. It verifies/restarts the service, and restores old files if the upgrade itself fails. To explicitly roll back after a later health regression, replace the timestamp with the actual snapshot directory:

```powershell
$snapshot = 'C:\Program Files\SentryGate\Agent.rollback-20260927-120000'
& .\apps\agent\scripts\rollback-agent.ps1 -BackupDirectory $snapshot
Get-Service SentryGateAgent
```

Run on one computer at a time; verify authenticated contact before proceeding to the next. Revoking credentials is independent of a software rollback.

## Three-computer local simulation

From the repository root, this isolated demonstration starts a temporary in-memory API, creates three distinct owner-approved simulated enrollments, reports two devices, persists the third device's event spool while offline, reconnects and resends it, verifies no duplicate event, then revokes the second device and confirms its old credential receives HTTP 401. The demo spool uses a test protection adapter; installed Windows agents use machine-scoped DPAPI. It changes no host settings and prints no credentials:

```powershell
npm run demo:multi-device
npm test
```
