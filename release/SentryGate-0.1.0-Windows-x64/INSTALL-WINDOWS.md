# SentryGate Windows Installation

This is a PowerShell installer bundle, not a signed MSI. It packages the local API/dashboard, SQLite initialization/migrations, local analysis worker, Windows agent, scripts, and a private Node.js 24 runtime. It installs no npm packages and needs no internet after the release ZIP is available.

## Permissions and paths

- Dashboard installer: run as the normal Windows user. It writes program files by default to `%LOCALAPPDATA%\Programs\SentryGate`, local database/reports to `%LOCALAPPDATA%\SentryGate\Data`, and logs/runtime configuration to `%LOCALAPPDATA%\SentryGate\Runtime`.
- Agent service: UAC Administrator consent is requested separately when the installer calls `install-agent.ps1`. The monitor runs as `NT AUTHORITY\LocalService`, uses machine-scoped DPAPI for its credential, and configures Windows Service Control Manager recovery. The separate LocalSystem firewall helper is not installed by this setup.
- The dashboard/API/gateway bind to `127.0.0.1`; remote access remains disabled. No firewall rule or DNS/routing change is made.
- Every new detection policy is Observe. Firewall policy is preview-only and automatic enforcement is disabled. The installer does not enable Enforce.
- Administrator password is created by the local first-run dashboard. No password is embedded, generated, or written by this installer.

## Build and verify release

Build on Windows x64 with Node.js 24+ and PowerShell 7:

```powershell
npm test
npm run typecheck
npm run build
.\scripts\build-release.ps1 -OutputDirectory .\release
Get-FileHash .\release\SentryGate-0.1.0-Windows-x64.zip -Algorithm SHA256
Get-Content .\release\RELEASE-CHECKLIST.md
```

Compare the SHA-256 with `release\SentryGate-0.1.0-Windows-x64.zip.sha256` after copying the artifact. Transfer the ZIP through an approved offline channel, extract it to a directory separate from the install location, then use ordinary (not elevated) PowerShell:

```powershell
Expand-Archive .\SentryGate-0.1.0-Windows-x64.zip .\SentryGateBundle
Set-Location .\SentryGateBundle
Unblock-File .\Install-SentryGate.ps1
Set-ExecutionPolicy -Scope Process Bypass
.\Install-SentryGate.ps1
```

The wizard prints the install/data/runtime directories and permission scope. Type `INSTALL`. It starts the local dashboard, registers a current-user logon task, and opens the first-run page. Expected screen: **SentryGate** with **Create your administrator**. Choose the owner email and a unique password of at least 12 characters, then sign in. Nothing supplies a default password.

In **Devices**, enroll the computer and copy its one-time device ID and credential. Return to the installer and press Enter. Enter the device ID when prompted; Windows displays UAC for service registration. In the elevated console, paste the one-time credential into the secure prompt. The credential is stored using DPAPI, not printed or added to command arguments.

## Health verification

The installer performs a dashboard HTTP 200 and backend/SQLite health check. After service install it prompts for a local administrator sign-in and waits for a recent authenticated agent heartbeat:

```powershell
.\scripts\health-sentrygate.ps1 -BaseUrl http://127.0.0.1:4300 -DeviceId '<device-guid>'
Get-Service SentryGateAgent
sc.exe qc SentryGateAgent
sc.exe qfailure SentryGateAgent
```

Expected output: Dashboard `PASS`, Backend `PASS`, Database `ready`, AgentService `Running`, AgentEventDelivery `authenticated heartbeat received ...`, and `RemoteAccessEnabled=False`. In **Devices**, the same computer should show a current heartbeat, Observe collection, and healthy status. A service heartbeat proves authenticated report delivery, not successful event detection on every Windows configuration.

Expected dashboard descriptions (screenshots are intentionally not included in this source package):

- First launch: centered **Create your administrator** form; after setup it becomes **Sign in**.
- Overview: local event counts and recent alerts, initially empty until the agent reports.
- Devices: enrolled hostname, service state/start mode, agent version, health and last heartbeat.
- Actions/Firewall: new policies show Observe; Enforce is disabled and firewall changes remain preview-only.
- Settings: local data path, database usage and local backup controls.

## Start, stop, backup, restore

The dashboard starts for the installing Windows user at sign-in. The enrolled agent starts at boot as a Windows service and continues collecting while the dashboard is closed; reports are buffered locally while the API is offline.

```powershell
Get-Service SentryGateAgent
Start-Service SentryGateAgent
Stop-Service SentryGateAgent
Invoke-RestMethod http://127.0.0.1:4300/api/health
& "$env:LOCALAPPDATA\Programs\SentryGate\scripts\backup-sentrygate.ps1" -OutputFile "$env:USERPROFILE\Documents\sentrygate-backup.db"
```

Restore is destructive to the current database. Stop the agent first, close the dashboard, then run from the extracted installed directory in PowerShell:

```powershell
& .\scripts\restore-sentrygate.ps1 -Source "$env:USERPROFILE\Documents\sentrygate-backup.db" -Confirm
```

The restore script stops the local dashboard, verifies/restores the SQLite database while preserving the previous database, then restarts the dashboard. Verify `/api/health`, login, assets and event history afterward.

## Repair, upgrade, rollback

Repair validates the static package and restarts local services without replacing the database:

```powershell
& "$env:LOCALAPPDATA\Programs\SentryGate\scripts\Repair-SentryGate.ps1"
```

Extract the new release outside the installed application folder. Confirm the archive checksum, then upgrade; the script makes a local SQLite backup and a timestamped program-file rollback copy before changing code. User data is never part of the code replacement:

```powershell
& .\scripts\Upgrade-SentryGate.ps1 -BundleDirectory .\SentryGateBundle
```

If post-upgrade checks fail, the script automatically restores prior application files. For a manual rollback to a retained copy:

```powershell
& "$env:LOCALAPPDATA\Programs\SentryGate\scripts\Rollback-SentryGate.ps1" -PreviousInstallDirectory "$env:LOCALAPPDATA\Programs\SentryGate.rollback-YYYYMMDD-HHMMSS"
```

Restore a database backup only when required; application rollback alone keeps the current database. Schema migrations are designed to be additive, but rollback across a migration should be rehearsed against a copy before a pilot.

If an agent service is installed, upgrade requests a separate UAC approval after the dashboard is healthy. The service upgrader preserves ProgramData credentials, baselines, and its encrypted event queue; it retains a timestamped program-file rollback copy and restores old agent code if startup fails.

## Uninstall

Run ordinary PowerShell from the installed folder. The script asks before deleting local data; leaving the response blank/anything other than `DELETE DATA` preserves it. UAC is requested to remove the agent service. Its cleanup targets only SentryGate-labeled rules:

```powershell
& "$env:LOCALAPPDATA\Programs\SentryGate\scripts\Uninstall-SentryGate.ps1"
Get-Service SentryGateAgent -ErrorAction SilentlyContinue
Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object DisplayName -Like 'SentryGate*'
```

Check that the service is absent. If the optional helper had been separately installed, its SentryGate-owned rules are removed by its ownership-limited cleanup. Unrelated Windows Firewall rules and the Windows Firewall service are not changed. Review and revoke the device credential in the dashboard before final data removal when possible.

## Pilot qualification status

Automated tests and packaging checks are not a substitute for Windows lifecycle testing. Before calling a release verified, use a disposable Windows 11 VM snapshot and test fresh install, reboot/logon behavior, forced agent child crash/recovery, offline report buffering/replay, upgrade with retained data, failed-upgrade rollback, restore verification, and uninstall with a before/after firewall-rule inventory. This repository build does not claim those clean-VM checks have passed.
