param([Parameter(Mandatory=$true)][string]$BundleDirectory,[string]$InstallRoot="$env:ProgramFiles\SentryGate\Agent")
$ErrorActionPreference='Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator permission is required to upgrade the Windows service.' }
$install=(Resolve-Path -LiteralPath $InstallRoot).Path.TrimEnd('\')
$expected=[IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'SentryGate\Agent')).TrimEnd('\')
if (-not $install.Equals($expected,[StringComparison]::OrdinalIgnoreCase)) { throw 'Agent upgrade is restricted to the SentryGate directory under Program Files.' }
$bundle=(Resolve-Path -LiteralPath $BundleDirectory).Path
foreach($relative in @('apps\agent\src\agent.js','apps\agent\scripts\service-host.cs','packages\shared\network-policy.js','runtime\node.exe')) { if(-not(Test-Path (Join-Path $bundle $relative))){throw "Upgrade bundle is missing $relative"} }
$service=Get-Service SentryGateAgent -ErrorAction Stop
$nodeVersion=[version]((& (Join-Path $bundle 'runtime\node.exe') --version).TrimStart('v'))
if($nodeVersion -lt [version]'24.0'){throw 'Bundled Node.js 24 or later is required.'}
$stamp=Get-Date -Format yyyyMMdd-HHmmss
$backup="$install.rollback-$stamp"
Copy-Item -LiteralPath $install -Destination $backup -Recurse -Force
$serviceExe=Join-Path $install 'SentryGateAgentService.exe'
$stagedService="$serviceExe.new"
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(-not(Test-Path $compiler)){$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'}
if(-not(Test-Path $compiler)){throw '.NET Framework C# compiler is required to update the service host.'}
try {
  if($service.Status -ne 'Stopped'){Stop-Service SentryGateAgent -Force; (Get-Service SentryGateAgent).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))}
  Copy-Item -LiteralPath (Join-Path $bundle 'apps\agent') -Destination (Join-Path $install 'apps') -Recurse -Force
  Copy-Item -LiteralPath (Join-Path $bundle 'packages\shared') -Destination (Join-Path $install 'packages') -Recurse -Force
  Copy-Item -LiteralPath (Join-Path $bundle 'runtime\node.exe') -Destination (Join-Path $install 'runtime\node.exe') -Force
  & $compiler /nologo /target:exe "/out:$stagedService" (Join-Path $install 'apps\agent\scripts\service-host.cs')
  if($LASTEXITCODE -ne 0){throw 'Could not compile the upgraded service host.'}
  Move-Item -LiteralPath $stagedService -Destination $serviceExe -Force
  Start-Service SentryGateAgent
  (Get-Service SentryGateAgent).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
  Write-Output "SentryGate agent service upgraded and running. Previous program files: $backup. DPAPI data and buffered events were preserved."
} catch {
  try { if((Get-Service SentryGateAgent -ErrorAction SilentlyContinue).Status -ne 'Stopped'){Stop-Service SentryGateAgent -Force} } catch {}
  Remove-Item -LiteralPath (Join-Path $install 'apps\agent') -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath (Join-Path $install 'packages\shared') -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath (Join-Path $install 'runtime\node.exe') -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $serviceExe,$stagedService -Force -ErrorAction SilentlyContinue
  Get-ChildItem -LiteralPath $backup -Force | Copy-Item -Destination $install -Recurse -Force
  Start-Service SentryGateAgent
  throw "Agent upgrade failed; prior service files restored from $backup. $($_.Exception.Message)"
}
