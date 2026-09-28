param([Parameter(Mandatory=$true)][string]$BundleDirectory,[string]$InstallDirectory = "$env:LOCALAPPDATA\Programs\SentryGate",[string]$DataDirectory = "$env:LOCALAPPDATA\SentryGate\Data",[string]$RuntimeDirectory = "$env:LOCALAPPDATA\SentryGate\Runtime")
$ErrorActionPreference='Stop'
$install=(Resolve-Path -LiteralPath $InstallDirectory).Path
$bundle=(Resolve-Path -LiteralPath $BundleDirectory).Path
if (-not (Test-Path (Join-Path $install '.sentrygate-install'))) { throw 'Install marker missing; refusing to upgrade a directory not installed by SentryGate.' }
if (-not (Test-Path (Join-Path $bundle 'runtime\node.exe')) -or -not (Test-Path (Join-Path $bundle 'apps\api\src\server.js'))) { throw 'Bundle is incomplete.' }
if ($bundle.StartsWith($install + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Extract the upgrade bundle outside the installed application directory.' }
if ((Read-Host "Upgrade SentryGate at $install? Local data will be preserved. Type UPGRADE") -cne 'UPGRADE') { throw 'Upgrade cancelled.' }
$stamp=Get-Date -Format yyyyMMdd-HHmmss
$backup=Join-Path $DataDirectory "backups\preupgrade-$stamp.db"
New-Item -ItemType Directory -Path (Split-Path $backup -Parent) -Force | Out-Null
& (Join-Path $install 'scripts\backup-sentrygate.ps1') -OutputFile $backup
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw 'Database backup failed; upgrade stopped.' }
$rollback="$install.rollback-$stamp"
Copy-Item -LiteralPath $install -Destination $rollback -Recurse -Force
& (Join-Path $install 'scripts\stop-sentrygate.ps1')
try {
  foreach ($name in @('apps','packages','scripts','docs','runtime')) { Copy-Item -LiteralPath (Join-Path $bundle $name) -Destination $install -Recurse -Force }
  foreach ($name in @('package.json','README.md','INSTALL-WINDOWS.md','RELEASE-NOTES.md')) { Copy-Item -LiteralPath (Join-Path $bundle $name) -Destination $install -Force }
  & (Join-Path $install 'scripts\start-sentrygate.ps1') -DataDirectory $DataDirectory -RuntimeDirectory $RuntimeDirectory -LocalOnly
  & (Join-Path $install 'scripts\health-sentrygate.ps1') -BaseUrl 'http://127.0.0.1:4300' -SkipAgent -RequireStandalone
  if (Get-Service SentryGateAgent -ErrorAction SilentlyContinue) {
    $agentUpgrade=Join-Path $bundle 'apps\agent\scripts\upgrade-agent.ps1'
    $agentArgs="-NoProfile -ExecutionPolicy Bypass -File `"$agentUpgrade`" -BundleDirectory `"$bundle`""
    $agentResult=Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $agentArgs -Wait -PassThru
    if($agentResult.ExitCode -ne 0){throw 'Elevated agent service upgrade failed; dashboard rollback will run and the agent upgrader restores its previous code.'}
  }
  Write-Output "Upgrade passed. Data backup: $backup; application rollback copy: $rollback"
} catch {
  try { & (Join-Path $install 'scripts\stop-sentrygate.ps1') } catch {}
  foreach ($name in @('apps','packages','scripts','docs','runtime')) { $path=Join-Path $install $name; if (Test-Path $path) { Remove-Item -LiteralPath $path -Recurse -Force } }
  foreach ($name in @('package.json','README.md','INSTALL-WINDOWS.md','RELEASE-NOTES.md')) { $path=Join-Path $install $name; if (Test-Path $path) { Remove-Item -LiteralPath $path -Force } }
  Get-ChildItem -LiteralPath $rollback -Force | Copy-Item -Destination $install -Recurse -Force
  & (Join-Path $install 'scripts\start-sentrygate.ps1') -DataDirectory $DataDirectory -RuntimeDirectory $RuntimeDirectory -LocalOnly
  throw "Upgrade failed and previous application files were restored from $rollback. Database backup remains at $backup."
}
