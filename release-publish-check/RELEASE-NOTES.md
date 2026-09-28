# SentryGate 0.1.0 for Windows

This is a standalone per-computer Windows x64 ZIP installer candidate. Each installation creates its own local SQLite database, owner account, Device ID, and DPAPI-protected agent credential. No account, password, Device ID, credential, database, `.env` file, or event data is included in the release archive.

## Windows support

- Target operating system: Windows 11 x64.
- Windows 10, Windows Server, ARM64, and non-Windows systems are not qualified by this release.
- This candidate has passed automated Windows package checks, but clean-VM installation, reboot, service recovery, and uninstall are still required before it can be declared supported or published.

## Install

The archive is `SentryGate-0.1.0-Windows-x64.zip`; verify it against `SentryGate-0.1.0-Windows-x64.zip.sha256`. The release bootstrap downloads both named assets and verifies the checksum before extraction:

```powershell
$bootstrap = Join-Path $env:TEMP 'Install-SentryGate.ps1'
Invoke-WebRequest 'https://raw.githubusercontent.com/KALYANAPUTRINADH/Sentrygate/main/Install-SentryGate.ps1' -OutFile $bootstrap
Unblock-File $bootstrap
Set-ExecutionPolicy -Scope Process Bypass
& $bootstrap -Version v0.1.0 -Repository KALYANAPUTRINADH/Sentrygate
```

Complete the local administrator setup and device enrollment when prompted. The required monitoring service is `SentryGateAgent`, configured for Automatic startup under LocalService. The local dashboard/backend starts through the current user's `SentryGate Dashboard` logon task. `SentryGateFirewallHelper` is optional and is not installed by default. Detection starts in Observe; firewall enforcement remains disabled and preview-only.

## Limitations

- Clean-VM lifecycle qualification has not yet passed; do not use this candidate for production or publish it until that gate passes.
- The distribution is an unsigned PowerShell/ZIP installer, not a signed MSI. SHA-256 detects accidental corruption but does not establish publisher identity.
- The dashboard/backend runs at the installing user's sign-in, not as a Windows service. The agent service waits for the local API and retries when it is unavailable.
- Automatic OS updates are not performed. Upgrades are administrator-controlled and need a verified new release.

## Update and rollback

For a later release, use the same checksum-verifying bootstrap with `-Update`:

```powershell
& $bootstrap -Version v0.2.0 -Repository KALYANAPUTRINADH/Sentrygate -Update
Get-Service -Name SentryGateAgent
sc.exe qc SentryGateAgent
Invoke-RestMethod http://127.0.0.1:4300/api/health
```

Use the timestamped rollback copy printed by the upgrade command:

```powershell
$install = "$env:LOCALAPPDATA\Programs\SentryGate"
$previous = Get-ChildItem -LiteralPath "$install.rollback-*" -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $previous) { throw 'No SentryGate rollback copy exists.' }
& "$install\scripts\Rollback-SentryGate.ps1" -PreviousInstallDirectory $previous.FullName
```

## Uninstall

From ordinary PowerShell, run the installed uninstaller. It requests Administrator approval to remove the agent service and asks separately before deleting local data:

```powershell
& "$env:LOCALAPPDATA\Programs\SentryGate\scripts\Uninstall-SentryGate.ps1"
Get-Service -Name SentryGateAgent -ErrorAction SilentlyContinue
```
