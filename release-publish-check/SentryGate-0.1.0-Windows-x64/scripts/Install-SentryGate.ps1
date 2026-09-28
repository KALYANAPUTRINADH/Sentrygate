param(
  [string]$InstallDirectory = "$env:LOCALAPPDATA\Programs\SentryGate",
  [string]$DataDirectory = "$env:LOCALAPPDATA\SentryGate\Data",
  [string]$RuntimeDirectory = "$env:LOCALAPPDATA\SentryGate\Runtime",
  [switch]$SkipAgentService
)
$ErrorActionPreference = 'Stop'
$source = if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'apps')) { (Resolve-Path $PSScriptRoot).Path } else { (Resolve-Path (Join-Path $PSScriptRoot '..')).Path }
$install = [IO.Path]::GetFullPath($InstallDirectory).TrimEnd('\')
$data = [IO.Path]::GetFullPath($DataDirectory)
$runtime = [IO.Path]::GetFullPath($RuntimeDirectory)
foreach ($path in @($install,$data,$runtime)) {
  if ($path.StartsWith('\\')) { throw 'SentryGate installation, data, and runtime paths must be on local disks.' }
}
if ($install -eq $source -or $source.StartsWith($install + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Extract the installer bundle to a separate directory before running it.' }

Write-Host 'SentryGate local installer' -ForegroundColor Cyan
Write-Host "Program files: $install"
Write-Host "Local data:    $data"
Write-Host "Runtime/logs:  $runtime"
Write-Host 'Permissions: current-user files and a localhost-only dashboard. Agent service registration requests Administrator consent separately.'
Write-Host 'Detection starts in Observe. Firewall changes remain preview-only and automatic enforcement is disabled.'
if ((Read-Host 'Type INSTALL to continue') -cne 'INSTALL') { throw 'Installation cancelled.' }

if (Test-Path -LiteralPath $install) { throw 'An installation already exists. Use scripts\Upgrade-SentryGate.ps1 so data and rollback copies are preserved.' }
New-Item -ItemType Directory -Path $install,$data,$runtime -Force | Out-Null
foreach ($name in @('apps','packages','scripts','docs','runtime')) { Copy-Item -LiteralPath (Join-Path $source $name) -Destination $install -Recurse -Force }
foreach ($name in @('package.json','README.md','INSTALL-WINDOWS.md','RELEASE-NOTES.md')) { Copy-Item -LiteralPath (Join-Path $source $name) -Destination $install -Force }
[IO.File]::WriteAllText((Join-Path $install '.sentrygate-install'), 'SentryGate installation marker',[Text.Encoding]::ASCII)
[IO.File]::WriteAllText((Join-Path $data '.sentrygate-data'), 'SentryGate local data marker',[Text.Encoding]::ASCII)

$start = Join-Path $install 'scripts\start-sentrygate.ps1'
& $start -DataDirectory $data -RuntimeDirectory $runtime -LocalOnly
$taskCommand = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$start`" -DataDirectory `"$data`" -RuntimeDirectory `"$runtime`" -LocalOnly"
& schtasks.exe /Create /SC ONLOGON /TN 'SentryGate Dashboard' /TR $taskCommand /F /RL LIMITED | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not register the current-user dashboard startup task.' }
$baseUrl = 'http://127.0.0.1:4300'
$healthScript = Join-Path $install 'scripts\health-sentrygate.ps1'
& $healthScript -BaseUrl $baseUrl -SkipAgent -RequireStandalone
Start-Process $baseUrl
Write-Host "Create the first administrator at $baseUrl. The password is entered only in the local dashboard and is never placed in installer files." -ForegroundColor Yellow
Read-Host 'Press Enter after creating the administrator account in the browser' | Out-Null
$session=Invoke-RestMethod "$baseUrl/api/session" -TimeoutSec 5
if ($session.setupRequired) { throw 'Administrator setup is still required. Reopen the local dashboard and finish owner account creation.' }
Write-Host 'Administrator account initialized; no password was stored by the installer.' -ForegroundColor Green
Read-Host 'Locally enroll this computer in Devices in the localhost dashboard, then press Enter to continue' | Out-Null

if (-not $SkipAgentService) {
  $deviceId = Read-Host 'Device ID from Devices'
  if ($deviceId -notmatch '^[0-9a-fA-F-]{36}$') { throw 'Device ID must be a GUID. Dashboard installation is complete; rerun this step after device enrollment.' }
  $agentInstaller = Join-Path $install 'apps\agent\scripts\install-agent.ps1'
  $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$agentInstaller`"",'-DeviceId',$deviceId,'-ApiBaseUrl',$baseUrl)
  $installHelper = (Read-Host 'Install the optional privileged helper for explicitly approved local firewall rules? Type INSTALL HELPER (default: preview only)') -ceq 'INSTALL HELPER'
  if ($installHelper) { $args += '-EnableFirewallManagement' }
  $quoted = $args -join ' '
  $elevated = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $quoted -Wait -PassThru
  if ($elevated.ExitCode -ne 0) { throw 'Elevated agent service installation failed. Dashboard remains installed; see INSTALL-WINDOWS.md for repair.' }
  & $healthScript -BaseUrl $baseUrl -DeviceId $deviceId -RequireStandalone
} else {
  Write-Warning 'Agent service installation was skipped by request. Run apps\agent\scripts\install-agent.ps1 after local device enrollment.'
}
Write-Host "SentryGate installed. Dashboard: $baseUrl; data: $data" -ForegroundColor Green
