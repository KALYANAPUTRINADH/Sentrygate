param([string]$InstallDirectory = "$env:LOCALAPPDATA\Programs\SentryGate",[string]$DataDirectory = "$env:LOCALAPPDATA\SentryGate\Data",[string]$RuntimeDirectory = "$env:LOCALAPPDATA\SentryGate\Runtime")
$ErrorActionPreference='Stop'
$installFull=[IO.Path]::GetFullPath($InstallDirectory).TrimEnd('\')
if (-not (Test-Path -LiteralPath (Join-Path $installFull '.sentrygate-install'))) { throw 'Installation marker missing; refusing to remove this directory.' }
if ($installFull -eq [IO.Path]::GetPathRoot($installFull)) { throw 'Refusing to uninstall from a volume root.' }
Write-Host "Application: $InstallDirectory`nData: $DataDirectory`nRuntime: $RuntimeDirectory"
Write-Host 'The agent service uninstall requires Administrator. SentryGate-owned temporary firewall rules are removed by its ownership-limited cleanup script; unrelated rules are not touched.'
if ((Read-Host 'Type UNINSTALL to stop and remove SentryGate') -cne 'UNINSTALL') { throw 'Uninstall cancelled.' }
$root=(Resolve-Path -LiteralPath $InstallDirectory).Path
& (Join-Path $root 'scripts\stop-sentrygate.ps1')
$null = & schtasks.exe /Delete /TN 'SentryGate Dashboard' /F
$agentUninstaller=Join-Path $root 'apps\agent\scripts\uninstall-agent.ps1'
$deleteData = $false
if (Test-Path -LiteralPath $DataDirectory) { $deleteData = (Read-Host 'Delete local database, reports, queued events, and agent enrollment data? Type DELETE DATA') -ceq 'DELETE DATA' }
if ((Get-Service SentryGateAgent -ErrorAction SilentlyContinue) -or (Get-Service SentryGateFirewallHelper -ErrorAction SilentlyContinue)) {
  $removeFlag = if ($deleteData) { ' -RemoveData' } else { '' }
  $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$agentUninstaller`"$removeFlag"
  $elevated = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arguments -Wait -PassThru
  if ($elevated.ExitCode -ne 0) { throw 'Elevated Windows service uninstall failed; application files and data were preserved.' }
}
if ((Test-Path -LiteralPath $DataDirectory) -and -not $deleteData) {
  Write-Host 'Local data retained.'
} elseif (Test-Path -LiteralPath $DataDirectory) {
  $target=[IO.Path]::GetFullPath($DataDirectory)
  if (-not (Test-Path -LiteralPath (Join-Path $target '.sentrygate-data'))) { throw 'Local data marker missing; refusing to delete this directory.' }
  Remove-Item -LiteralPath $target -Recurse -Force
}
Remove-Item -LiteralPath $installFull -Recurse -Force
Write-Host 'SentryGate application removed. Verify SentryGateAgent is absent and unrelated Windows Firewall rules remain unchanged.'
