# SentryGate Controlled Pilot

This runbook separates local validation, staging validation, and a later operator-approved live change. Milestone 9 tooling does not change DNS, install an agent on a different computer, or approve/apply an operating-system firewall rule. Detection must remain enabled in `observe`; firewall actions stay preview-only and automatic blocking remains disabled.

## Stage 1: Local Test

Requirements: Node.js 24+, dependencies installed, and the local administrator account created. In PowerShell, use separate terminals:

```powershell
npm install
npm run sample:site
```

Expected: `Sample website running at http://127.0.0.1:4320`.

In a second terminal:

```powershell
npm run dev
```

Expected: API on `127.0.0.1:4300`, gateway on `127.0.0.1:4310`; open `http://127.0.0.1:4300` and sign in. Register a website asset with address `http://127.0.0.1:4320`, then **Protected Assets → Configure** and set upstream to `http://127.0.0.1:4320`, enabled, mode **observe**, sensitive paths enabled, rate limit `3` requests / `60` seconds, and failure behavior **fail open**. Record the asset ID from its row or the local SQLite `assets` table. These are loopback-only HTTP settings for local development.

In a third terminal, run the bounded simulation:

```powershell
npm run pilot:simulate -- --asset-id 1
```

Replace `1` with the test website asset ID. Expected: a JSON summary with a normal request and sensitive-path request returning the sample site's HTTP 200, a small burst returning HTTP 200 in observe mode, `sensitive_path` and `rate_limit` detections observed, and `"firewallChanges": 0`. The simulation refuses a non-loopback upstream/gateway or a non-observe policy. It sends at most eight total local requests.

Review **Pilot**, **Events**, and **Alerts**. Mark a detection false positive only after human review; the evidence is preserved and the reviewer/time are audited. Pilot latency samples start when this version is installed; earlier events have no gateway timing record.

## Stage 2: Staging

Only proceed after local results and a backup restore drill pass. Configure a staging URL and trusted CA as described in [deployment.md](deployment.md). Use certificates that validate for the API, gateway, and upstream; never bypass certificate validation. Keep staging DNS and routing separate from production.

First validate the staging website/API/gateway certificates and routing manually, then create a verified database backup and record the prior website upstream. Register a computer asset and enroll only the Windows computer you administer. On that same computer, configure and run the agent in the foreground (the credential is prompted securely and saved with DPAPI):

```powershell
$deviceId = Read-Host 'Device ID shown once by SentryGate enrollment'
$env:NODE_EXTRA_CA_CERTS = (Resolve-Path .\certs\pilot-ca.pem).Path # Omit for a publicly trusted CA.
& .\apps\agent\scripts\configure-agent.ps1 -DeviceId $deviceId -ApiBaseUrl 'https://sentrygate-staging.example.test:4300' -AgentRoot "$env:LOCALAPPDATA\SentryGate\Agent" -CaCertificatePath .\certs\pilot-ca.pem
npm run agent:dev
```

Keep the foreground process running until its heartbeat is shown as healthy. For service mode instead, open elevated PowerShell on this same computer and use the reviewed `install-agent.ps1` command in [deployment.md](deployment.md); leave `-EnableFirewallManagement` absent. This runbook does not install the agent remotely or on another host.

Then run the combined preflight:

```powershell
$backup = Join-Path $PWD "sentrygate-pilot-$(Get-Date -Format yyyyMMdd-HHmmss).db"
npm run db:backup -- --out $backup
$assetId = 1 # Replace with the staging website's asset ID.
$deviceId = "00000000-0000-0000-0000-000000000000" # Replace with the enrolled staging computer's device ID.
$env:SENTRYGATE_PILOT_GATEWAY_URL = "https://sentrygate-staging.example.test:4310" # Use the verified gateway DNS name/SAN.
npm run pilot:check -- --asset-id $assetId --device-id $deviceId --backup $backup
```

Expected: each preflight line says `PASS`; a successful run ends `Pilot preflight: N/N checks passed.` The checks validate asset/policy, upstream response and certificate validation, API/database health, gateway reachability/certificate validation, configured certificate files, the selected non-demo enrolled agent and recent heartbeat, SQLite backup integrity, and at least 2 GiB free disk. `FAIL` exits nonzero. The preflight's gateway `HEAD /` creates a normal gateway event/measurement and does not submit a probe.

Run the same observe-only simulation against the staging asset only after explicitly reviewing that its configured upstream is staging and owned/administered by you. The simulator itself intentionally rejects non-loopback hosts; staging checks use `pilot:check`, and staging traffic must be generated manually using an approved staging test client. Do not run the local simulator with a staging or live URL.

Run the automated suite and verify all checks before seeking approval for a separate live change request:

```powershell
npm test
npm run typecheck
npm run build
npm run load:test
Invoke-RestMethod https://sentrygate-staging.example.test:4300/api/health
openssl s_client -connect sentrygate-staging.example.test:4300 -servername sentrygate-staging.example.test -verify_return_error
openssl s_client -connect sentrygate-staging.example.test:4310 -servername sentrygate-staging.example.test -verify_return_error
```

Expected: tests/typecheck/build exit 0; load test reports request counts, throughput, p50/p95/p99, errors and stored/lost event totals; health returns `ok: true` and `database: ready`; both OpenSSL commands report successful certificate verification. Keep output as the staging evidence record.

## Stage 3: One Approved Live Website

This is a change-controlled manual step, not an automated command. Require asset-owner approval, a maintenance window, a fresh verified backup, a named rollback operator, validated certificates, staging evidence, confirmed origin reachability, and the website owner's routing procedure. Start with `observe` and fail-open unless the asset owner specifically approves a documented availability tradeoff. Change only the single approved website's routing; do not alter unrelated DNS or firewall configuration. Verify the site's normal behavior, event delivery, latency, upstream errors, agent heartbeat, and rollback readiness. Any failed gate means do not activate or roll back.

## Report and Decision

Download the seven-day report from **Pilot → Export JSON report**, or generate one from the local database:

```powershell
npm run pilot:report -- --days 7 --asset-id $assetId --out .\sentrygate-pilot-report.json
```

Expected: JSON containing request/event/alert counts, p50/p95/p99 gateway latency, upstream error rate, reviewed false positives, incidents, limitations, and recommendation. `rollback` is recommended at 2% or greater server-error rate; `adjust` is recommended for insufficient samples or a 25%+ reviewed false-positive rate; otherwise the result is `continue`. These are conservative pilot heuristics, not a safety certification. False positives are explicit administrator labels, not inferred classifications.

## Rollback

Record the previous configured upstream before any change. To restore that configured origin, put website rules into observe mode, remove this website's SentryGate gateway blocks, and queue SentryGate-owned temporary rules on the selected enrolled computer:

```powershell
npm run pilot:rollback -- --asset-id $assetId --previous-upstream "https://prior-origin.example.test" --device-id $deviceId --confirm true
```

Expected: output shows the restored upstream, `mode: observe`, gateway blocks removed, and device firewall removals queued. In the SentryGate server terminal press **Ctrl+C**; API and gateway run in one process. Restore external load balancer/DNS routing manually using the website owner's approved procedure. Keep the test computer agent online, then inspect **Firewall** and verify actual OS state says removed; a queued request is not proof of removal. If the agent is offline, reconnect it and verify again. Only SentryGate-owned rows are queued; unrelated Windows firewall rules are never read for deletion or modified. Preserve the backup/report and review the `pilot.rollback` audit entry.

Do not roll back by deleting database files or by disabling Windows Firewall. For a failed DB restore or stale schema, use the offline procedure in [deployment.md](deployment.md).
