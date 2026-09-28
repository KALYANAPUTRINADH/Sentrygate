param([Parameter(Mandatory=$true)][string]$BackupDirectory,[string]$InstallRoot="$env:ProgramFiles\SentryGate\Agent")
$ErrorActionPreference='Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator permission is required to roll back the Windows service.' }
$install = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
$expected = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'SentryGate\Agent')).TrimEnd('\')
if (-not $install.Equals($expected,[StringComparison]::OrdinalIgnoreCase)) { throw 'InstallRoot must be the SentryGate Agent directory under Program Files.' }
$backup = (Resolve-Path -LiteralPath $BackupDirectory).Path.TrimEnd('\')
$allowedParent = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'SentryGate')) + '\'
if (-not $backup.StartsWith($allowedParent,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $backup -Leaf) -notmatch '^Agent\.rollback-\d{8}-\d{6}$') { throw 'BackupDirectory must be a SentryGate Agent.rollback-* directory under Program Files\SentryGate.' }
foreach ($relative in @('apps\agent\src\agent.js','packages\shared\network-policy.js','runtime\node.exe','SentryGateAgentService.exe')) { if (-not (Test-Path -LiteralPath (Join-Path $backup $relative))) { throw "Rollback snapshot is missing $relative" } }
$service = Get-Service SentryGateAgent -ErrorAction Stop
if ($service.Status -ne 'Stopped') { Stop-Service SentryGateAgent -Force; (Get-Service SentryGateAgent).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) }
foreach ($relative in @('apps\agent','packages\shared','runtime\node.exe','SentryGateAgentService.exe')) {
  $source = Join-Path $backup $relative
  $destination = Join-Path $install $relative
  if ((Get-Item -LiteralPath $source).PSIsContainer) { Copy-Item -LiteralPath $source -Destination (Split-Path $destination -Parent) -Recurse -Force }
  else { Copy-Item -LiteralPath $source -Destination $destination -Force }
}
Start-Service SentryGateAgent
(Get-Service SentryGateAgent).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
Write-Output "Previous SentryGate agent binaries restored from $backup. DPAPI credentials, device identity, and buffered local event data under ProgramData were preserved."
