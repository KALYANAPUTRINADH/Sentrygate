param([string]$OutputDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) 'release'))
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$output=[IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $output -Force | Out-Null
$version=(Get-Content (Join-Path $root 'package.json') -Raw | ConvertFrom-Json).version
$bundle=Join-Path $output "SentryGate-$version-Windows-x64"
$zip="$bundle.zip"
if (Test-Path $bundle) { throw "Staging path already exists: $bundle" }
if (Test-Path $zip) { throw "Release archive already exists: $zip" }
try {
  $testOutput=& npm.cmd test 2>&1
  if ($LASTEXITCODE -ne 0) { $testOutput | ForEach-Object { Write-Host $_ }; throw 'Automated tests failed; release package was not produced.' }
  $testSummary=($testOutput | Where-Object { $_ -match 'tests\s+\d+' } | Select-Object -Last 1).ToString()
  $typeOutput=& npm.cmd run typecheck 2>&1
  if ($LASTEXITCODE -ne 0) { $typeOutput | ForEach-Object { Write-Host $_ }; throw 'Type/syntax checks failed; release package was not produced.' }
  $buildOutput=& npm.cmd run build 2>&1
  if ($LASTEXITCODE -ne 0) { $buildOutput | ForEach-Object { Write-Host $_ }; throw 'Static asset build check failed; release package was not produced.' }
  & (Join-Path $root 'scripts\package-local.ps1') -OutputDirectory $bundle
  Copy-Item -LiteralPath (Join-Path $root 'scripts\Install-SentryGate.ps1') -Destination (Join-Path $bundle 'Install-SentryGate.ps1')
  Compress-Archive -Path (Join-Path $bundle '*') -DestinationPath $zip -CompressionLevel Optimal
  & (Join-Path $root 'scripts\test-packaged-smoke.ps1') -ArchivePath $zip
  $hash=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
  $checklist=@"
# SentryGate Windows Release Checklist

Release artifact: ``$(Split-Path $zip -Leaf)``
SHA-256: ``$hash``

## Automated checks
- PASS: automated test suite ($testSummary).
- PASS: JavaScript syntax/typecheck and static asset build checks.
- PASS: package-local static asset verification executed during packaging.
- PASS: extracted-package smoke (bundled Node runtime, SQLite, localhost API/dashboard, and first-admin setup).
- PASS: packaged Node.js runtime included; installer contains no default administrator password.
- PASS: detections default to Observe and firewall policy remains preview-only/disabled.
- FAIL: none in automated checks for this release build.
- NOT RUN: clean-VM service install, reboot, crash recovery, upgrade, rollback, firewall ownership cleanup, and uninstall. Requires a disposable Windows VM and elevated interactive session.

## Unresolved risks
- The backend/dashboard starts per-user at install and after that user's next logon; the enrolled agent service starts automatically with Windows and buffers reports while the dashboard host is unavailable.
- This release is a PowerShell/ZIP installer, not a signed MSI. Verify the downloaded archive SHA-256 and code-signing policy before distribution.
- No clean-machine Windows lifecycle verification is claimed by this build.
"@
  Set-Content -LiteralPath (Join-Path $output 'RELEASE-CHECKLIST.md') -Value $checklist -Encoding utf8
  Set-Content -LiteralPath "$zip.sha256" -Value "$hash  $(Split-Path $zip -Leaf)" -Encoding ascii
  Write-Output "Release: $zip`nSHA-256: $hash"
} finally { }
