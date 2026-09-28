param([string]$InstallDirectory = "$env:LOCALAPPDATA\Programs\SentryGate",[string]$DataDirectory = "$env:LOCALAPPDATA\SentryGate\Data",[string]$RuntimeDirectory = "$env:LOCALAPPDATA\SentryGate\Runtime")
$ErrorActionPreference='Stop'
$root=(Resolve-Path -LiteralPath $InstallDirectory).Path
$node=Join-Path $root 'runtime\node.exe'
& (Join-Path $root 'scripts\stop-sentrygate.ps1')
& $node (Join-Path $root 'apps\api\scripts\verify-static-assets.js')
if ($LASTEXITCODE -ne 0) { throw 'Static application verification failed.' }
& (Join-Path $root 'scripts\start-sentrygate.ps1') -DataDirectory $DataDirectory -RuntimeDirectory $RuntimeDirectory -LocalOnly
& (Join-Path $root 'scripts\health-sentrygate.ps1') -BaseUrl 'http://127.0.0.1:4300' -SkipAgent -RequireStandalone
