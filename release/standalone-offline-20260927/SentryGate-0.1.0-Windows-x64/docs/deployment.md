# Controlled Pilot Deployment

SentryGate is not certified or generally production-ready. This procedure is for one noncritical website and one Windows computer, with an operator available to roll back. Do not point a production domain at the gateway or approve firewall rules during the initial pilot.

## Requirements

- Patched Windows host with Node.js 24+, a dedicated non-administrator service identity, BitLocker/encrypted storage, restrictive ACLs, and protected local backups. SentryGate does not upload backups; any separate copy is an explicit administrator operation outside SentryGate.
- CA-issued certificate with correct DNS/IP SANs for both listener names. Install the issuing CA in every client trust store. Never disable certificate validation.
- Restrictive network ACLs exposing only the API/gateway to the pilot operator, test client, and enrolled computer. Do not expose SQLite.
- One noncritical owned website with an HTTPS upstream; never point at an unowned or production asset for this procedure.

## TLS Setup and Verification

Use PEM files issued by your organization CA. For loopback testing only, OpenSSL can make a short-lived leaf; explicitly trust it on the test client and do not use it as a production trust anchor:

```powershell
New-Item -ItemType Directory -Force .\certs | Out-Null
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 7 -keyout .\certs\pilot.key -out .\certs\pilot.crt -subj "/CN=sentrygate.test" -addext "subjectAltName=DNS:sentrygate.test,IP:127.0.0.1"
Copy-Item .\certs\pilot.crt .\certs\pilot-ca.pem
```

Configure an ACL-protected `.env` (never commit it). Set SANs and hostname to the pilot DNS name. Production mode requires an explicit 32+ character session secret and TLS keypair; remote API/gateway listeners require TLS. Use the same certificate only if it covers both names:

```powershell
if (Test-Path .env) { throw 'An existing .env was found. Preserve it and edit only the pilot settings.' }
Copy-Item .env.example .env
$secret = node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"
$envText = (Get-Content .env -Raw) -replace '^SENTRYGATE_SESSION_SECRET=.*$', "SENTRYGATE_SESSION_SECRET=$secret"
$envText += "`r`nNODE_ENV=production`r`nSENTRYGATE_TLS_CERT=certs/pilot.crt`r`nSENTRYGATE_TLS_KEY=certs/pilot.key`r`nSENTRYGATE_API_BASE_URL=https://sentrygate.test:4300`r`nSENTRYGATE_HOST=0.0.0.0`r`nSENTRYGATE_GATEWAY_HOST=0.0.0.0`r`n"
[System.IO.File]::WriteAllText((Resolve-Path .env), $envText, [System.Text.UTF8Encoding]::new($false))
$env:NODE_ENV = 'production'
# For a private CA, set this before Node starts; omit for a publicly trusted CA.
$env:NODE_EXTRA_CA_CERTS = (Resolve-Path .\certs\pilot-ca.pem).Path
npm run dev
```

Clients validate certificate chain, expiry, and hostname by default. For a private CA, install its root/intermediate in Windows trust and, if needed for Node, provide its PEM bundle before Node starts. Foreground development:

```powershell
$env:NODE_EXTRA_CA_CERTS = (Resolve-Path .\certs\pilot-ca.pem).Path
npm run agent:dev
```

For a Windows service, pass the CA bundle during installation; the service host supplies it to the child Node process at startup:

```powershell
& .\apps\agent\scripts\install-agent.ps1 -DeviceId $deviceId -ApiBaseUrl 'https://sentrygate.test:4300' -CaCertificatePath .\certs\pilot-ca.pem
```

Do not set `NODE_TLS_REJECT_UNAUTHORIZED=0`, use `--ignore-certificate-errors`, or set `rejectUnauthorized:false`. Agent URLs must be HTTPS except loopback development. Non-loopback HTTP upstreams are rejected; HTTPS upstream validation is on.

Verify both listeners, status, and TLS hostname/chain:

```powershell
Invoke-RestMethod https://sentrygate.test:4300/api/health
Invoke-WebRequest https://sentrygate.test:4300 -UseBasicParsing | Select-Object StatusCode
openssl s_client -connect sentrygate.test:4300 -servername sentrygate.test -verify_return_error
openssl s_client -connect sentrygate.test:4310 -servername sentrygate.test -verify_return_error
```

From a test client, try an untrusted CA or mismatched hostname and verify the handshake fails. Windows service private-CA trust must be available to its service identity; restart it and verify authenticated heartbeat after setting trust.

## Backup and Restore

Online `VACUUM INTO` backup makes a consistent SQLite snapshot and validates it:

```powershell
$backup = Join-Path $env:ProgramData "SentryGate\Backups\sentrygate-$(Get-Date -Format yyyyMMdd-HHmmss).db"
npm run db:backup -- --out $backup
```

Restore is offline-only. Stop SentryGate, verify the path, and restore; the utility validates the source and staging copy and preserves the current DB as `.pre-restore-*`. It refuses while WAL/SHM sidecars exist:

```powershell
# Stop the SentryGate process with Ctrl+C, or stop the service.
npm run db:restore -- --source $backup --confirm
npm run dev
Invoke-RestMethod https://sentrygate.test:4300/api/health
```

The automated test checks snapshot contents, integrity, confirmation, and preservation of the previous DB. Run a restore drill and record its result before pilot; integrity does not prove freshness. Encrypt backups and restrict access like the live DB.

## Operations and Failure Behavior

`GET /api/health` checks SQLite and reports combined DB/WAL/SHM size and cap. JSON operational logs go to stdout/stderr; configure the service manager to collect and rotate them. Default `SENTRYGATE_MAX_DB_BYTES` is 2 GiB; ingestion returns 507 at the cap. Agent outbox defaults to 256 MiB/100,000 events (set `spoolMaxBytes` in its protected config, 1 MiB to 10 GiB); on pressure, the agent marks health degraded and stops queueing newer detections until delivery or age-based retention frees space. Retention runs every 15 seconds based on Settings and compacts SQLite after deleting data. A stale authenticated device heartbeat (three intervals) or website gateway heartbeat (90 seconds) opens an evidence-backed alert. Monitor health failures, `storage.limit_reached`, event-delivery errors, disk use, and service exit.

Per website, **Protected Assets → Configure** has an enforcement telemetry failure mode:

- **Fail open** (default): if a detected request's event cannot be delivered, forward it upstream; event evidence for that request can be missing. Structured error is logged.
- **Fail closed**: if event delivery fails for a detected request, return 503 without forwarding it. This prioritizes enforcement over site availability.
- Normal requests continue upstream in both modes. Upstream failure/timeout returns 502. WebSocket upgrades return 501. Uploads stream. Rate counters are process-local and reset on restart.

## Pilot Checklist

For the staged local → staging → one approved live-website procedure, exact commands, expected checks, report, simulation constraints, and rollback command, see [pilot.md](pilot.md).

1. Confirm owner access, storage encryption/ACLs, trusted cert and SANs, listener ACLs, backup destination and restore drill, log rotation, disk alerting, and an operator contact.
2. Run `npm test`, `npm run typecheck`, `npm run build`, and `npm run load:test` on the candidate revision; record Windows and Node versions.
3. Start HTTPS listeners; verify `/api/health`, both certificates, and dashboard cookie flags `HttpOnly; Secure; SameSite=Strict`.
4. Register one noncritical owned website with an HTTPS upstream. Start in **Observe**, choose fail-open, and test only with the local gateway URL; do not change DNS.
5. Enroll one administered Windows computer using the default LocalService service. Keep firewall management disabled. Verify version, heartbeat, config acknowledgement, scoped events, and no private-content collection.
6. During a test window, restart the agent and briefly interrupt API reachability. Verify buffered events retry without duplicates, heartbeat alert appears/clears, and site failure mode behaves as configured.
7. Make a second backup, perform a restore rehearsal, inspect the audit trail and evidence, review DB growth, event loss and latency. Record gaps.
8. Monitor the short pilot period. Stop test routing and roll back upstream configuration for errors, certificate warnings, unexpected blocking, event loss, or abnormal growth. Broader deployment needs separate change approval.

## Upgrade and Rollback

There is no auto-updater or schema downgrade. Pin and verify the source and Node runtime; review scripts before execution. For backend/gateway: test/build, back up DB, stop service, deploy candidate, start, verify health/login/proxy, and inspect logs. On failure stop service, restore the matching pre-upgrade DB with the command above, restore prior verified code/runtime, then recheck health and proxy. Never open a newer schema with older code without its matching DB snapshot.

For the Windows agent: record version/service identity, preserve DPAPI config/spool under approved Windows backup controls, stop service, deploy reviewed code, restart, and verify service state and authenticated heartbeat. Roll back by reinstalling the prior verified agent while preserving device ID, credential, and protected data. Do not rotate credentials as part of a binary update; rotate separately only for suspected exposure.

## Least Privilege and Gaps

Run API/gateway as a dedicated non-admin identity with access to DB, `.env`, and private key. Keep agent firewall management off; enabling it raises the entire service to LocalSystem. SQLite is not encrypted or tamper-evident by SentryGate. There is no HA, distributed rate limit, mutual TLS, signed updater, external alert integration, formal penetration test, or long-duration availability evidence. A pilot is not a production-readiness claim.
