param([string]$InstallRoot = "$env:ProgramFiles\SentryGate\Agent", [string]$DataRoot = "$env:ProgramData\SentryGate\Agent", [Parameter(Mandatory=$true)][string]$DeviceId, [string]$ApiBaseUrl = 'http://127.0.0.1:4300', [switch]$EnableFirewallManagement)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator permission is required to install the Windows service.' }
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$node = (Get-Command node.exe -ErrorAction Stop).Source
$nodeVersion = [version]((& $node --version).TrimStart('v'))
if ($nodeVersion -lt [version]'24.0') { throw 'Node.js 24 or later is required.' }
if (Get-Service SentryGateAgent -ErrorAction SilentlyContinue) { throw 'SentryGateAgent service already exists. Uninstall it before reinstalling.' }
New-Item -ItemType Directory -Path $InstallRoot,$DataRoot -Force | Out-Null
Copy-Item (Join-Path $repoRoot 'apps\agent\*') $InstallRoot -Recurse -Force
& (Join-Path $InstallRoot 'scripts\configure-agent.ps1') -DeviceId $DeviceId -ApiBaseUrl $ApiBaseUrl -AgentRoot $DataRoot -DpapiScope LocalMachine -InstallContext
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $compiler)) { $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
if (-not (Test-Path $compiler)) { throw 'The .NET Framework C# compiler is required to build the service host.' }
$hostSource = Join-Path $InstallRoot 'scripts\service-host.cs'
$serviceExe = Join-Path $InstallRoot 'SentryGateAgentService.exe'
& $compiler /nologo /target:exe /out:$serviceExe $hostSource
if ($LASTEXITCODE -ne 0) { throw 'Could not build the Windows service host.' }
$entry = Join-Path $InstallRoot 'src\agent.js'
$config = Join-Path $DataRoot 'config.json'
$service = New-Service -Name SentryGateAgent -DisplayName 'SentryGate Windows Agent' -Description 'Observe-only endpoint metadata and security event reporting.' -BinaryPathName "`"$serviceExe`" `"$node`" `"$entry`" `"$config`"" -StartupType Automatic
if (-not $EnableFirewallManagement) {
  $serviceConfig = & sc.exe config SentryGateAgent obj= 'NT AUTHORITY\LocalService' password= ''
  if ($LASTEXITCODE -ne 0) { sc.exe delete SentryGateAgent | Out-Null; throw 'Could not configure the least-privilege LocalService account.' }
} else {
  Write-Warning 'Firewall management opts into LocalSystem for the entire agent service because NetSecurity rule changes require elevated rights. This increases the agent process privilege; use only on a device you administer.'
  if ((Read-Host 'Type ENABLE to confirm LocalSystem service installation') -cne 'ENABLE') { sc.exe delete SentryGateAgent | Out-Null; throw 'Firewall management installation was not confirmed.' }
}
Start-Service $service.Name
Write-Output 'SentryGate Windows Agent installed and started. It collects process metadata and TCP connection metadata only.'
