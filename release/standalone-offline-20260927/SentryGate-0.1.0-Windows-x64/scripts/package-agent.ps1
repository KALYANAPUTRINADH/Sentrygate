param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw 'OutputDirectory already exists; choose a new empty destination.' }
$node = (Get-Command node.exe -ErrorAction Stop).Source
if ([version]((& $node --version).TrimStart('v')) -lt [version]'24.0') { throw 'Packaging requires Node.js 24 or later.' }
$version = (Get-Content (Join-Path $root 'apps\agent\package.json') -Raw | ConvertFrom-Json).version
$stage = Join-Path $output "SentryGate-Agent-$version-Windows-x64"
New-Item -ItemType Directory -Path (Join-Path $stage 'apps'),(Join-Path $stage 'packages'),(Join-Path $stage 'runtime') -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $root 'apps\agent') -Destination (Join-Path $stage 'apps') -Recurse
Copy-Item -LiteralPath (Join-Path $root 'packages\shared') -Destination (Join-Path $stage 'packages') -Recurse
Copy-Item -LiteralPath $node -Destination (Join-Path $stage 'runtime\node.exe')
Copy-Item -LiteralPath (Join-Path $root 'docs\multi-computer-deployment.md') -Destination (Join-Path $stage 'INSTALL-AGENT.md')
$archive = "$stage.zip"
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$archive.sha256" -Value "$hash  $(Split-Path $archive -Leaf)" -Encoding ascii
Write-Output "Agent bundle: $archive`nSHA-256: $hash`nNo device identity, credential, configuration, local database, or event spool is included."
