param([Parameter(Mandatory=$true)][string]$PreviousInstallDirectory,[string]$InstallDirectory = "$env:LOCALAPPDATA\Programs\SentryGate",[string]$DataDirectory = "$env:LOCALAPPDATA\SentryGate\Data",[string]$RuntimeDirectory = "$env:LOCALAPPDATA\SentryGate\Runtime")
$ErrorActionPreference='Stop'
$old=(Resolve-Path -LiteralPath $PreviousInstallDirectory).Path
$current=[IO.Path]::GetFullPath($InstallDirectory).TrimEnd('\')
if (-not (Test-Path -LiteralPath (Join-Path $current '.sentrygate-install')) -or -not (Test-Path -LiteralPath (Join-Path $old '.sentrygate-install'))) { throw 'Install marker missing; rollback is limited to SentryGate program directories.' }
if ($old -eq $current -or $old.StartsWith($current + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Previous application directory must be a separate rollback copy.' }
& (Join-Path $current 'scripts\stop-sentrygate.ps1')
if (Test-Path -LiteralPath $current) { Remove-Item -LiteralPath $current -Recurse -Force }
Copy-Item -LiteralPath $old -Destination $current -Recurse -Force
& (Join-Path $current 'scripts\start-sentrygate.ps1') -DataDirectory $DataDirectory -RuntimeDirectory $RuntimeDirectory
& (Join-Path $current 'scripts\health-sentrygate.ps1') -BaseUrl 'http://127.0.0.1:4300' -SkipAgent
