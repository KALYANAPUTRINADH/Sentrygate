param([string]$InstallRoot = "$env:ProgramFiles\SentryGate\Agent", [string]$DataRoot = "$env:ProgramData\SentryGate\Agent", [Parameter(Mandatory=$true)][string]$DeviceId, [string]$ApiBaseUrl = 'http://127.0.0.1:4300', [string]$CaCertificatePath = '', [ValidateRange(1048576,10737418240)][long]$SpoolMaxBytes = 268435456, [switch]$EnableFirewallManagement)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator permission is required to install the Windows service.' }
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$bundledNode = Join-Path $repoRoot 'runtime\node.exe'
$node = if (Test-Path -LiteralPath $bundledNode) { $bundledNode } else { (Get-Command node.exe -ErrorAction Stop).Source }
$nodeVersion = [version]((& $node --version).TrimStart('v'))
if ($nodeVersion -lt [version]'24.0') { throw 'Node.js 24 or later is required.' }
if (Get-Service SentryGateAgent -ErrorAction SilentlyContinue) { throw 'SentryGateAgent service already exists. Uninstall it before reinstalling.' }
New-Item -ItemType Directory -Path $InstallRoot,$DataRoot -Force | Out-Null
$agentRoot = Join-Path $InstallRoot 'apps\agent'
New-Item -ItemType Directory -Path (Join-Path $InstallRoot 'apps'),(Join-Path $InstallRoot 'packages') -Force | Out-Null
Copy-Item (Join-Path $repoRoot 'apps\agent') (Join-Path $InstallRoot 'apps') -Recurse -Force
Copy-Item (Join-Path $repoRoot 'packages\shared') (Join-Path $InstallRoot 'packages') -Recurse -Force
New-Item -ItemType Directory -Path (Join-Path $InstallRoot 'runtime') -Force | Out-Null
Copy-Item -LiteralPath $node -Destination (Join-Path $InstallRoot 'runtime\node.exe') -Force
$node = Join-Path $InstallRoot 'runtime\node.exe'
$configureArgs = @{ DeviceId=$DeviceId; ApiBaseUrl=$ApiBaseUrl; AgentRoot=$DataRoot; DpapiScope='LocalMachine'; InstallContext=$true; CaCertificatePath=$CaCertificatePath; SpoolMaxBytes=$SpoolMaxBytes }
& (Join-Path $agentRoot 'scripts\configure-agent.ps1') @configureArgs
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $compiler)) { $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $compiler)) { throw 'The .NET Framework C# compiler is required to build the service host.' }
$hostSource = Join-Path $agentRoot 'scripts\service-host.cs'
$serviceExe = Join-Path $InstallRoot 'SentryGateAgentService.exe'
& $compiler /nologo /target:exe /out:$serviceExe $hostSource
if ($LASTEXITCODE -ne 0) { throw 'Could not build the Windows service host.' }
if ($EnableFirewallManagement) {
  Write-Warning 'This installs a separate LocalSystem helper for authenticated, narrowly scoped SentryGate firewall commands. Monitoring stays LocalService. Enforcement remains disabled until enabled by an owner in the dashboard.'
  if ((Read-Host 'Type INSTALL HELPER to install the privileged firewall helper') -cne 'INSTALL HELPER') { throw 'Firewall helper installation was not confirmed.' }
  if (Get-Service SentryGateFirewallHelper -ErrorAction SilentlyContinue) { throw 'SentryGateFirewallHelper already exists. Uninstall it before reinstalling.' }
  $helperSource = Join-Path $agentRoot 'scripts\firewall-helper-service.cs'
  $helperExe = Join-Path $InstallRoot 'SentryGateFirewallHelper.exe'
  & $compiler /nologo /target:exe /out:$helperExe /reference:System.ServiceProcess.dll /reference:System.Security.dll /reference:System.Web.Extensions.dll $helperSource
  if ($LASTEXITCODE -ne 0) { throw 'Could not build the privileged firewall helper.' }
  $key = [byte[]]::new(32); [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
  $plainKey = [Convert]::ToBase64String($key)
  $protectedKey = $plainKey | & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $agentRoot 'scripts\dpapi.ps1') -Action Protect -Scope LocalMachine
  if ($LASTEXITCODE -ne 0 -or -not $protectedKey) { throw 'Could not protect the helper credential with machine DPAPI.' }
  [IO.File]::WriteAllText((Join-Path $DataRoot 'firewall-helper.key.dpapi'), ($protectedKey -join '').Trim(), [Text.Encoding]::UTF8)
  [Array]::Clear($key,0,$key.Length); $plainKey = $null
  $helperDataRoot = Join-Path $DataRoot 'FirewallHelper'
  New-Item -ItemType Directory -Path $helperDataRoot -Force | Out-Null
  $helperAcl = Get-Acl $helperDataRoot
  $helperAcl.SetAccessRuleProtection($true, $false)
  $helperAcl.Access | ForEach-Object { $helperAcl.RemoveAccessRule($_) | Out-Null }
  foreach ($principal in @('SYSTEM','BUILTIN\Administrators')) { $helperAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow')) }
  Set-Acl -Path $helperDataRoot -AclObject $helperAcl
  $helper = New-Service -Name SentryGateFirewallHelper -DisplayName 'SentryGate Firewall Helper' -Description 'Narrow privileged helper for authenticated SentryGate-owned Windows Firewall rules.' -BinaryPathName "`"$helperExe`"" -StartupType Automatic
  & sc.exe failure SentryGateFirewallHelper reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
  & sc.exe failureflag SentryGateFirewallHelper 1 | Out-Null
  Start-Service $helper.Name
}
$entry = Join-Path $agentRoot 'src\agent.js'
$config = Join-Path $DataRoot 'config.json'
$caArgument = if ($CaCertificatePath) { " `"$((Resolve-Path -LiteralPath $CaCertificatePath).Path)`"" } else { '' }
$service = New-Service -Name SentryGateAgent -DisplayName 'SentryGate Windows Agent' -Description 'Observe-only endpoint metadata and security event reporting.' -BinaryPathName "`"$serviceExe`" `"$node`" `"$entry`" `"$config`"$caArgument" -StartupType Automatic
 $serviceConfig = & sc.exe config SentryGateAgent obj= 'NT AUTHORITY\LocalService' password= ''
if ($LASTEXITCODE -ne 0) { sc.exe delete SentryGateAgent | Out-Null; if (Get-Service SentryGateFirewallHelper -ErrorAction SilentlyContinue) { Stop-Service SentryGateFirewallHelper -Force; sc.exe delete SentryGateFirewallHelper | Out-Null }; throw 'Could not configure the least-privilege LocalService account.' }
$null = & sc.exe sidtype SentryGateAgent unrestricted
if ($LASTEXITCODE -ne 0) { sc.exe delete SentryGateAgent | Out-Null; if (Get-Service SentryGateFirewallHelper -ErrorAction SilentlyContinue) { Stop-Service SentryGateFirewallHelper -Force; sc.exe delete SentryGateFirewallHelper | Out-Null }; throw 'Could not enable the dedicated agent service SID.' }
$dataAcl = Get-Acl $DataRoot
$dataAcl.SetAccessRuleProtection($true, $false)
$dataAcl.Access | ForEach-Object { $dataAcl.RemoveAccessRule($_) | Out-Null }
foreach ($principal in @('SYSTEM','BUILTIN\Administrators','NT SERVICE\SentryGateAgent')) { $dataAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow')) }
Set-Acl -Path $DataRoot -AclObject $dataAcl
$helperKeyPath = Join-Path $DataRoot 'firewall-helper.key.dpapi'
if (Test-Path -LiteralPath $helperKeyPath) {
  $keyAcl = Get-Acl $helperKeyPath
  $keyAcl.SetAccessRuleProtection($true, $false)
  $keyAcl.Access | ForEach-Object { $keyAcl.RemoveAccessRule($_) | Out-Null }
  foreach ($principal in @('SYSTEM','BUILTIN\Administrators','NT SERVICE\SentryGateAgent')) { $keyAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','None','None','Allow')) }
  Set-Acl -Path $helperKeyPath -AclObject $keyAcl
}
$null = & sc.exe failure SentryGateAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000
if ($LASTEXITCODE -ne 0) { sc.exe delete SentryGateAgent | Out-Null; throw 'Could not configure Windows service crash recovery.' }
$null = & sc.exe failureflag SentryGateAgent 1
if ($LASTEXITCODE -ne 0) { sc.exe delete SentryGateAgent | Out-Null; throw 'Could not enable recovery for non-zero service failures.' }
Start-Service $service.Name
Write-Output 'SentryGate Windows Agent installed as an automatic LocalService with Windows restart-on-failure recovery.'
Write-Output 'Dashboard/API and ordinary monitoring remain unprivileged; only the separately installed firewall helper uses LocalSystem.'
Write-Output 'Reporting is enabled only when the configured API resolves to loopback/private/link-local addresses; public or unresolved destinations are treated as offline and buffered locally.'
