param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop';$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path;$out=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $out){throw 'OutputDirectory already exists; choose a new empty destination.'}
$node=(Get-Command node.exe -ErrorAction Stop).Source;if([version]((& $node --version).TrimStart('v')) -lt [version]'24.0'){throw 'Packaging requires Node.js 24 or later.'}
New-Item -ItemType Directory -Path $out -Force|Out-Null
foreach($relative in @('apps\api\src','apps\api\scripts','apps\web','apps\agent\src','apps\agent\scripts','packages\shared','scripts','docs')){New-Item -ItemType Directory -Path (Join-Path $out $relative) -Force|Out-Null;Copy-Item -Path (Join-Path $root $relative) -Destination (Split-Path (Join-Path $out $relative) -Parent) -Recurse -Force}
foreach($file in @('package.json','README.md','INSTALL-WINDOWS.md','RELEASE-NOTES.md','Install-SentryGate.ps1')){Copy-Item (Join-Path $root $file) $out}
New-Item -ItemType Directory -Path (Join-Path $out 'runtime') -Force|Out-Null;Copy-Item -LiteralPath $node -Destination (Join-Path $out 'runtime\node.exe')
$bundledNode=Join-Path $out 'runtime\node.exe';Push-Location $out
try{& $bundledNode 'apps/api/scripts/verify-static-assets.js';if($LASTEXITCODE -ne 0){throw 'Offline package static-asset verification failed.'}}finally{Pop-Location}
Write-Output "Offline-capable SentryGate package staged and verified at $out. No application data or secret configuration was copied."
