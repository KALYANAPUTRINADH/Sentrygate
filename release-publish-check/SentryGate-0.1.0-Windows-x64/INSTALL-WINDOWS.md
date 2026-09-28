# SentryGate Windows Installation

This is a PowerShell installer bundle, not a signed MSI. It packages the local API/dashboard, SQLite initialization/migrations, local analysis worker, Windows agent, scripts, and a private Node.js 24 runtime. It installs no npm packages and needs no internet after the release ZIP is available. Each computer is an independent standalone installation: no domain, VPN, central server, cloud account, remote enrollment, or update service is used. The package contains no database, administrator password, device identity, or credential.

## Permissions and paths

- Dashboard installer: run as the normal Windows user. It writes program files by default to `%LOCALAPPDATA%\Programs\SentryGate`, local database/reports to `%LOCALAPPDATA%\SentryGate\Data`, and logs/runtime configuration to `%LOCALAPPDATA%\SentryGate\Runtime`.
- Agent service: UAC Administrator consent is requested separately when the installer calls `install-agent.ps1`. The monitor runs as `NT AUTHORITY\LocalService`, uses machine-scoped DPAPI for its credential, and configures Windows Service Control Manager recovery. The wizard separately offers the optional LocalSystem firewall helper; installing it changes no rules.
- The installer forces standalone mode and binds the dashboard/API/gateway to `127.0.0.1`, even if inherited environment settings request remote listeners. No outside network connection, firewall rule, or DNS/routing change is needed or made by default.
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

The current package version is read from `package.json`; for this checkout the release assets are `SentryGate-0.1.0-Windows-x64.zip` and `SentryGate-0.1.0-Windows-x64.zip.sha256`. The tag must be `v0.1.0`. The tagged workflow runs tests and uploads a candidate artifact first. Its release job waits at the protected GitHub Environment `windows-clean-vm-qualified` and also requires environment variable `SENTRYGATE_CLEAN_WINDOWS_VM_VERIFIED=true`. Configure required reviewers and this variable for that Environment. Do not set the variable or approve the job until the exact candidate ZIP has passed the clean Windows VM procedure below. No release is published by a local build.

For a tagged release, the maintainer performs these exact repository steps after reviewing the changes:

```powershell
npm test
npm run typecheck
npm run build
git tag v0.1.0
git push origin v0.1.0
```

Download `sentrygate-windows-release-candidate` from that workflow run and test the included ZIP in a clean Windows 11 VM snapshot before approving the waiting publish job. The candidate ZIP/checksum are the exact files the publish job attaches. Verify a fresh independent installation, reboot/automatic service startup, stop/start/restart, heartbeat, temporary backend outage recovery, and clean uninstall; confirm unrelated firewall rules remain unchanged. Only after all checks pass, set the Environment variable `SENTRYGATE_CLEAN_WINDOWS_VM_VERIFIED` to `true` and approve the protected deployment. If any check fails, leave the variable unset, do not approve, and fix/rebuild. The workflow publishes these actual assets: `SentryGate-0.1.0-Windows-x64.zip`, `SentryGate-0.1.0-Windows-x64.zip.sha256`, `INSTALL-WINDOWS.md`, `RELEASE-NOTES.md`, and `RELEASE-CHECKLIST.md`.

The release bootstrap downloads the named public GitHub Release, requires both exact asset names, verifies the SHA-256 file and archive bytes before extraction, refuses packages containing a live `.env` or database, then runs the bundled local installer. From ordinary PowerShell, download the bootstrap from the repository and request an explicit version:

```powershell
$bootstrap = Join-Path $env:TEMP 'Install-SentryGate.ps1'
Invoke-WebRequest 'https://raw.githubusercontent.com/KALYANAPUTRINADH/Sentrygate/main/Install-SentryGate.ps1' -OutFile $bootstrap
Unblock-File $bootstrap
Set-ExecutionPolicy -Scope Process Bypass
& $bootstrap -Version v0.1.0 -Repository KALYANAPUTRINADH/Sentrygate
```

For a later tagged release (for example `v0.2.0`), update through the same verified downloader. It invokes the existing data-preserving upgrade/rollback workflow rather than reinstalling over the local database:

```powershell
& $bootstrap -Version v0.2.0 -Repository KALYANAPUTRINADH/Sentrygate -Update
Get-Service -Name SentryGateAgent
sc.exe qc SentryGateAgent
Invoke-RestMethod http://127.0.0.1:4300/api/health
```

If the post-upgrade checks fail, use the newest retained rollback directory shown by the upgrade command:

```powershell
$install = "$env:LOCALAPPDATA\Programs\SentryGate"
$previous = Get-ChildItem -LiteralPath "$install.rollback-*" -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $previous) { throw 'No SentryGate rollback copy exists.' }
& "$install\scripts\Rollback-SentryGate.ps1" -PreviousInstallDirectory $previous.FullName
Get-Service -Name SentryGateAgent
```

Uninstall, with an explicit prompt before deleting local data, from ordinary PowerShell:

```powershell
& "$env:LOCALAPPDATA\Programs\SentryGate\scripts\Uninstall-SentryGate.ps1"
Get-Service -Name SentryGateAgent -ErrorAction SilentlyContinue
```

Missing release, installer asset, checksum asset, malformed checksum, checksum mismatch, package files, service, automatic-start configuration, backend, or database causes a terminating error. The bootstrap retains its verified archive and extracted bundle at `%LOCALAPPDATA%\SentryGate\ReleaseCache\v0.1.0`; it refuses to overwrite an existing release cache. Remove only that named cache directory after confirming no process is using it to retry. The archive checksum detects transfer corruption; it is not a publisher signature, so use GitHub's authenticated release page and organizational code-signing policy for publisher assurance.

### Clean Windows VM acceptance (release gate)

Use a disposable, freshly reverted Windows 11 VM, not a computer with existing SentryGate data. Run the installer and complete a fresh owner account and local device enrollment. From elevated PowerShell in the installed directory:

```powershell
Get-Service -Name SentryGateAgent
Get-CimInstance Win32_Service -Filter "Name='SentryGateAgent'" | Select-Object Name,StartMode,State,ProcessId
sc.exe qfailure SentryGateAgent
Invoke-RestMethod http://127.0.0.1:4300/api/health
```

Expected: `SentryGateAgent` is `Running`, `StartMode` is `Auto`, failure actions include restart delays, API health is `ok`, database is `ready`, `standalone` is true, and remote access is false. Restart the VM. After signing in, repeat those checks and run `health-sentrygate.ps1` with the device GUID; expect a recent authenticated heartbeat. To test crash recovery on this disposable VM, terminate only the service-host PID (not the Node child):

```powershell
$svc = Get-CimInstance Win32_Service -Filter "Name='SentryGateAgent'"
Stop-Process -Id $svc.ProcessId -Force
Start-Sleep -Seconds 20
Get-Service -Name SentryGateAgent
```

Expected: SCM restarts the automatic service and it returns to `Running`. Separately stop the local backend using `scripts\stop-sentrygate.ps1`, confirm the agent service remains up and logs its local-backend wait/retry, restart the backend using `scripts\start-sentrygate.ps1`, then verify a fresh heartbeat. Finally uninstall through `Uninstall-SentryGate.ps1`, choose whether to retain data, and verify `Get-Service SentryGateAgent -ErrorAction SilentlyContinue` returns no service. Compare the before/after firewall-rule inventory; the default installation must create no firewall helper or rule and must leave unrelated rules unchanged. Save this checklist's results with the exact candidate SHA-256 before setting the Environment variable and approving publication.

For an offline transfer, first compare the local hash with the separately transferred `.sha256`, then extract and run the bundled local installer directly. Do not use the downloader for an already extracted bundle:

```powershell
Expand-Archive .\SentryGate-0.1.0-Windows-x64.zip .\SentryGateBundle
Set-Location .\SentryGateBundle
Unblock-File .\scripts\Install-SentryGate.ps1
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\Install-SentryGate.ps1
```

The wizard prints the install/data/runtime directories and permission scope. Type `INSTALL`. It starts the local dashboard, registers a current-user logon task, and opens the first-run page. Expected screen: **SentryGate** with **Create your administrator**. Choose the owner email and a unique password of at least 12 characters, then sign in. Nothing supplies a default password.

In **Devices**, create a local enrollment for this computer and copy its one-time device ID and credential. This record and unique credential exist only in this installation's database. Return to the installer and press Enter. Enter the device ID when prompted; Windows displays UAC for service registration. In the elevated console, paste the one-time credential into the secure prompt. It is stored using machine DPAPI, not printed or added to command arguments. Repeat setup independently on each computer; never copy its database, ProgramData agent files, or DPAPI material to another computer.

The wizard offers a separate `INSTALL HELPER` confirmation for the optional privileged firewall helper. Accepting installs the helper but creates or enables no firewall rule. Leave the default to keep firewall changes preview-only. Approved local rules can operate offline only when this helper is installed and an owner approves them in that computer's own dashboard. Automatic enforcement remains disabled.

## Health verification

The installer performs a dashboard HTTP 200 and backend/SQLite health check. After service install it prompts for a local administrator sign-in and waits for a recent authenticated agent heartbeat:

```powershell
.\scripts\health-sentrygate.ps1 -BaseUrl http://127.0.0.1:4300 -DeviceId '<device-guid>' -RequireStandalone
Get-Service SentryGateAgent
sc.exe qc SentryGateAgent
sc.exe qfailure SentryGateAgent
```

Expected output: Dashboard `PASS`, Backend `PASS`, Database `ready`, Standalone `True`, AgentService `Running`, AgentEventDelivery `authenticated heartbeat received ...`, and `RemoteAccessEnabled=False`. In **Devices**, the same computer should show a current heartbeat, Observe collection, and healthy status. A service heartbeat proves authenticated local report delivery, not successful event detection on every Windows configuration.

Expected dashboard descriptions (screenshots are intentionally not included in this source package):

- First launch: centered **Create your administrator** form; after setup it becomes **Sign in**.
- Overview: local event counts and recent alerts, initially empty until the agent reports.
- Devices: enrolled hostname, service state/start mode, agent version, health and last heartbeat.
- Actions/Firewall: new policies show Observe; Enforce is disabled and firewall changes remain preview-only.
- Settings: local data path, database usage and local backup controls.

## Start, stop, backup, restore

The dashboard/API starts for the installing Windows user at sign-in. The locally enrolled agent starts at boot as a Windows service and continues collecting while the dashboard is closed; reports are buffered on that computer while its local API is unavailable. Database, reports, audit, and settings stay in its local data directory. The API health endpoint reports database/WAL/SHM usage against its cap; retention is configurable in Settings.

```powershell
Get-Service SentryGateAgent
Start-Service SentryGateAgent
Stop-Service SentryGateAgent
& "$env:LOCALAPPDATA\Programs\SentryGate\scripts\health-sentrygate.ps1" -BaseUrl http://127.0.0.1:4300 -RequireStandalone
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

Updates are offline and administrator-controlled: transfer a checksum-verified release ZIP by USB or another trusted medium, extract locally, and run the commands above. SentryGate never polls an update service or installs silently. If an agent service is installed, upgrade requests a separate UAC approval after the dashboard is healthy. The service upgrader preserves ProgramData credentials, baselines, and its encrypted event queue; it retains a timestamped program-file rollback copy and restores old agent code if startup fails.

## Uninstall

Run ordinary PowerShell from the installed folder. The script asks before deleting local data; leaving the response blank/anything other than `DELETE DATA` preserves it. UAC is requested to remove the agent service. Its cleanup targets only SentryGate-labeled rules:

```powershell
& "$env:LOCALAPPDATA\Programs\SentryGate\scripts\Uninstall-SentryGate.ps1"
Get-Service SentryGateAgent -ErrorAction SilentlyContinue
Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object DisplayName -Like 'SentryGate*'
```

Check that the service is absent. If the optional helper had been installed, its SentryGate-owned rules are removed by its ownership-limited cleanup. Unrelated Windows Firewall rules and the Windows Firewall service are not changed. The enrollment credential is local to this installation and is removed if its data is deliberately deleted.

## Independent-Installation Check

This automated test creates two isolated standalone API/SQLite installations with separate administrator sessions, device identities, credentials, and event rows. It verifies loopback binding and rejects one installation's credential against the other:

```powershell
npm run test:standalone
```

The package smoke check also starts the bundled backend with deliberately hostile remote-listener environment values and verifies that standalone mode still forces loopback:

```powershell
.\scripts\test-packaged-smoke.ps1 -ArchivePath .\release\SentryGate-0.1.0-Windows-x64.zip
```

## Pilot qualification status

Automated tests and packaging checks are not a substitute for Windows lifecycle testing. Before calling a release verified, use two clean Windows 11 VM snapshots and test fresh independent installs, reboot/logon behavior, forced agent child crash/recovery, report buffering/replay with internet disabled, offline upgrade with retained data, failed-upgrade rollback, restore verification, and uninstall with a before/after firewall-rule inventory. This repository build does not claim those clean-VM service-lifecycle checks have passed.
