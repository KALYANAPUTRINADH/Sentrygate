param(
  [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$DeviceId,
  [Parameter(Mandatory=$true)][ValidatePattern('^https?://')][string]$ApiBaseUrl,
  [Parameter(Mandatory=$true)][string]$AgentRoot,
  [string]$CaCertificatePath = '',
  [long]$SpoolMaxBytes = 268435456,
  [ValidateSet('CurrentUser','LocalMachine')][string]$DpapiScope = 'CurrentUser',
  [switch]$InstallContext
)
$ErrorActionPreference = 'Stop'
if ($SpoolMaxBytes -lt 1048576 -or $SpoolMaxBytes -gt 10737418240) { throw 'SpoolMaxBytes must be between 1 MiB and 10 GiB.' }
try { $apiUri=[uri]$ApiBaseUrl } catch { throw 'ApiBaseUrl must be a valid HTTP(S) URL.' }
$apiHost=$apiUri.Host.TrimStart([char]'[').TrimEnd([char]']')
if ($apiUri.Scheme -ne 'https' -and $apiHost -notin @('127.0.0.1','::1','localhost')) { throw 'HTTPS is required for remote agent connections; HTTP is allowed only for loopback development.' }
if ($CaCertificatePath) { $CaCertificatePath=(Resolve-Path -LiteralPath $CaCertificatePath).Path }
if ($InstallContext -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this command from an elevated PowerShell session.' }
New-Item -ItemType Directory -Path $AgentRoot -Force | Out-Null
$credential = Read-Host 'Paste the one-time device credential' -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential)
$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
try {
  $dpapiPath = Join-Path $PSScriptRoot 'dpapi.ps1'
  $protected = $plain | & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $dpapiPath -Action Protect -Scope $DpapiScope
  if ($LASTEXITCODE -ne 0 -or -not $protected) { throw 'Could not protect the agent credential with DPAPI.' }
  [IO.File]::WriteAllText((Join-Path $AgentRoot 'credential.dpapi'), ($protected -join '').Trim(), [Text.Encoding]::UTF8)
} finally { $plain = $null; [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr); $credential.Dispose() }
$config = [ordered]@{ deviceId = $DeviceId; apiBaseUrl = $ApiBaseUrl.TrimEnd('/'); credentialFile = 'credential.dpapi'; dpapiScope = $DpapiScope; dataRoot = $AgentRoot; caCertificatePath = $CaCertificatePath; firewallHelperKeyFile = 'firewall-helper.key.dpapi'; spoolMaxBytes = $SpoolMaxBytes; intervalSeconds = 30; collectProcesses = $true; collectConnections = $true; outboundConnectionThreshold = 40 }
[IO.File]::WriteAllText((Join-Path $AgentRoot 'config.json'), ($config | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
if ($InstallContext) {
  $acl = Get-Acl $AgentRoot
  $acl.SetAccessRuleProtection($true, $false)
  $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
  foreach ($principal in @('SYSTEM','BUILTIN\Administrators','NT AUTHORITY\LOCAL SERVICE')) { $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit,ObjectInherit','None','Allow')) }
  Set-Acl -Path $AgentRoot -AclObject $acl
}
Write-Output "Agent configuration written to $AgentRoot. Credential is DPAPI-protected and not displayed."
