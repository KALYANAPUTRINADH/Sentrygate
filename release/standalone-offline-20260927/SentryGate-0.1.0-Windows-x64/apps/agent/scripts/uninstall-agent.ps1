param([ValidateSet('SentryGateAgent')][string]$ServiceName = 'SentryGateAgent', [string]$InstallRoot = "$env:ProgramFiles\SentryGate\Agent", [string]$DataRoot = "$env:ProgramData\SentryGate\Agent", [switch]$RemoveData)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator permission is required to remove the Windows service.' }
$resolvedInstall = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
$resolvedData = [IO.Path]::GetFullPath($DataRoot).TrimEnd('\')
if (-not $resolvedInstall.StartsWith(([IO.Path]::GetFullPath($env:ProgramFiles) + '\'),[StringComparison]::OrdinalIgnoreCase) -or -not $resolvedInstall.EndsWith('\SentryGate\Agent',[StringComparison]::OrdinalIgnoreCase)) { throw 'InstallRoot must be a SentryGate Agent directory under Program Files.' }
if (-not $resolvedData.StartsWith(([IO.Path]::GetFullPath($env:ProgramData) + '\'),[StringComparison]::OrdinalIgnoreCase) -or -not $resolvedData.EndsWith('\SentryGate\Agent',[StringComparison]::OrdinalIgnoreCase)) { throw 'DataRoot must be a SentryGate Agent directory under ProgramData.' }
$service = Get-Service $ServiceName -ErrorAction SilentlyContinue
$helper = Get-Service SentryGateFirewallHelper -ErrorAction SilentlyContinue
if ($service -or $helper) {
  if ($service -and $service.Status -ne 'Stopped') { Stop-Service $ServiceName -Force }
  if ($helper -and $helper.Status -ne 'Stopped') { Stop-Service SentryGateFirewallHelper -Force }
  $cleanup = Join-Path $InstallRoot 'scripts\remove-owned-firewall-rules.ps1'
  if (Test-Path -LiteralPath $cleanup) { & $cleanup }
  foreach ($name in @($ServiceName,'SentryGateFirewallHelper')) {
    if (Get-Service $name -ErrorAction SilentlyContinue) {
      sc.exe delete $name | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "Windows did not remove service $name." }
      for ($i=0; $i -lt 30 -and (Get-Service $name -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Seconds 1 }
      if (Get-Service $name -ErrorAction SilentlyContinue) { throw "Service deletion for $name is pending; close Service Control Manager handles and retry." }
    }
  }
}
if (Test-Path $InstallRoot) { Remove-Item -LiteralPath $InstallRoot -Recurse -Force }
if ($RemoveData -and (Test-Path $DataRoot)) { Remove-Item -LiteralPath $DataRoot -Recurse -Force }
Write-Output 'SentryGate Agent service and program files removed. Device credentials should also be revoked in the dashboard.'
