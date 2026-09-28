param(
  [Parameter(Mandatory=$true)][ValidatePattern('^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$')][string]$Version,
  [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')][string]$Repository = 'KALYANAPUTRINADH/Sentrygate',
  [string]$InstallDirectory = "$env:LOCALAPPDATA\Programs\SentryGate",
  [string]$DataDirectory = "$env:LOCALAPPDATA\SentryGate\Data",
  [string]$RuntimeDirectory = "$env:LOCALAPPDATA\SentryGate\Runtime",
  [switch]$Update
)
$ErrorActionPreference = 'Stop'
$tag = if ($Version.StartsWith('v')) { $Version } else { "v$Version" }
$releaseVersion = $tag.Substring(1)
$archiveName = "SentryGate-$releaseVersion-Windows-x64.zip"
$checksumName = "$archiveName.sha256"
$api = "https://api.github.com/repos/$Repository/releases/tags/$tag"
$headers = @{ Accept='application/vnd.github+json'; 'X-GitHub-Api-Version'='2022-11-28'; 'User-Agent'='SentryGate-Release-Installer' }
try { $release = Invoke-RestMethod -Uri $api -Headers $headers -TimeoutSec 30 } catch { throw "Could not retrieve named GitHub release '$tag' from '$Repository': $($_.Exception.Message)" }
if ($release.tag_name -ne $tag) { throw "GitHub returned release '$($release.tag_name)' instead of requested tag '$tag'." }
$assets = @($release.assets)
$archiveAsset = $assets | Where-Object name -eq $archiveName | Select-Object -First 1
$checksumAsset = $assets | Where-Object name -eq $checksumName | Select-Object -First 1
if (-not $archiveAsset) { throw "Release '$tag' is missing required installer asset '$archiveName'." }
if (-not $checksumAsset) { throw "Release '$tag' is missing required checksum asset '$checksumName'." }

$cache = Join-Path $env:LOCALAPPDATA "SentryGate\ReleaseCache\$tag"
if (Test-Path -LiteralPath $cache) { throw "Release cache already exists at '$cache'. Remove or rename that specific cache directory before retrying." }
New-Item -ItemType Directory -Path $cache -Force | Out-Null
$archivePath = Join-Path $cache $archiveName
$checksumPath = Join-Path $cache $checksumName
try {
  Invoke-WebRequest -Uri $archiveAsset.browser_download_url -Headers $headers -OutFile $archivePath -TimeoutSec 300
  Invoke-WebRequest -Uri $checksumAsset.browser_download_url -Headers $headers -OutFile $checksumPath -TimeoutSec 30
} catch { throw "Release '$tag' download failed; no installation was started. $($_.Exception.Message)" }
if ((Get-Item -LiteralPath $archivePath).Length -le 0) { throw "Release asset '$archiveName' downloaded as an empty file." }
$checksumText = (Get-Content -LiteralPath $checksumPath -Raw).Trim()
if ($checksumText -notmatch '^([a-fA-F0-9]{64})\s+\*?(.+?)\s*$' -or $Matches[2] -ne $archiveName) { throw "Checksum asset '$checksumName' is missing a valid SHA-256 line for '$archiveName'." }
$expectedHash = $Matches[1].ToLowerInvariant()
$actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) { throw "SHA-256 verification failed for '$archiveName'; installation was not started." }

$bundle = Join-Path $cache 'bundle'
Expand-Archive -LiteralPath $archivePath -DestinationPath $bundle
$localInstaller = Join-Path $bundle 'scripts\Install-SentryGate.ps1'
foreach ($required in @($localInstaller,(Join-Path $bundle 'runtime\node.exe'),(Join-Path $bundle 'apps\api\src\server.js'),(Join-Path $bundle 'apps\agent\scripts\install-agent.ps1'))) {
  if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Verified release package is incomplete; required file is missing: $required" }
}
if (Get-ChildItem -LiteralPath $bundle -Recurse -File | Where-Object { $_.Name -like '.env*' }) { throw 'Release archive unexpectedly contains .env files; refusing installation.' }
if (Get-ChildItem -LiteralPath $bundle -Recurse -File -Filter '*.db' -ErrorAction SilentlyContinue) { throw 'Release archive unexpectedly contains database files; refusing installation.' }

if ($Update) {
  $upgrader = Join-Path $InstallDirectory 'scripts\Upgrade-SentryGate.ps1'
  if (-not (Test-Path -LiteralPath $upgrader -PathType Leaf)) { throw "Update requested, but installed SentryGate upgrader is missing: $upgrader" }
  & $upgrader -BundleDirectory $bundle -InstallDirectory $InstallDirectory -DataDirectory $DataDirectory -RuntimeDirectory $RuntimeDirectory
} else {
  if (Test-Path -LiteralPath (Join-Path $InstallDirectory '.sentrygate-install')) { throw "SentryGate is already installed at '$InstallDirectory'. Use -Update to preserve local data and upgrade." }
  & $localInstaller -InstallDirectory $InstallDirectory -DataDirectory $DataDirectory -RuntimeDirectory $RuntimeDirectory
}
$service = Get-Service -Name 'SentryGateAgent' -ErrorAction SilentlyContinue
if (-not $service) { throw "Installation returned without registering required Windows service 'SentryGateAgent'. Review the elevated installer output and repair before use." }
if ($service.Status -ne 'Running') { throw "Required Windows service 'SentryGateAgent' is '$($service.Status)', expected Running." }
$serviceConfig = Get-CimInstance Win32_Service -Filter "Name='SentryGateAgent'"
if (-not $serviceConfig -or $serviceConfig.StartMode -ne 'Auto') { throw "Required Windows service 'SentryGateAgent' is not configured for automatic startup." }
$health = try { Invoke-RestMethod -Uri 'http://127.0.0.1:4300/api/health' -TimeoutSec 5 -Proxy $null } catch { throw "Agent service is registered, but local backend health check failed: $($_.Exception.Message)" }
if (-not $health.ok -or $health.database -ne 'ready' -or -not $health.standalone -or $health.remoteAccessEnabled) { throw 'Agent service is registered, but local backend/database health or loopback-only standalone checks failed.' }
if (-not (Test-Path -LiteralPath (Join-Path $InstallDirectory 'scripts\health-sentrygate.ps1') -PathType Leaf)) { throw 'Installed health checker is missing; release package is incomplete.' }
Write-Host "Verified release $tag ($archiveName; SHA-256 $actualHash). Windows service: $($service.Name) ($($service.Status), startup $($serviceConfig.StartMode))." -ForegroundColor Green
Write-Host "Verified release files retained at $cache for administrator-controlled rollback or reinstall. Firewall enforcement remains disabled by default."
