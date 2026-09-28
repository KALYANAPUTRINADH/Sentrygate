param(
  [Parameter(Mandatory=$true)][string]$DataDirectory,
  [long]$MaxDatabaseBytes = 2147483648,
  [ValidateRange(50,99)][int]$WarningPercent = 80,
  [long]$MinimumFreeDiskBytes = 1073741824
)
$ErrorActionPreference = 'Stop'
if (-not [System.IO.Path]::IsPathRooted($DataDirectory)) { throw 'DataDirectory must be an absolute local path.' }
if ($DataDirectory.StartsWith('\\')) { throw 'UNC/network paths are not supported for SentryGate local data.' }
if ($MaxDatabaseBytes -lt 1048576 -or $MaxDatabaseBytes -gt 1099511627776) { throw 'MaxDatabaseBytes must be between 1 MiB and 1 TiB.' }
if ($MinimumFreeDiskBytes -lt 0 -or $MinimumFreeDiskBytes -gt 1099511627776) { throw 'MinimumFreeDiskBytes must be between 0 and 1 TiB.' }
$fullPath = [System.IO.Path]::GetFullPath($DataDirectory)
$root = [System.IO.Path]::GetPathRoot($fullPath)
if ($root -and [System.IO.DriveInfo]::new($root).DriveType -eq [System.IO.DriveType]::Network) { throw 'Mapped network drives are not supported for local SentryGate storage.' }
New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
$envPath = Join-Path (Split-Path $PSScriptRoot -Parent) '.env'
if (-not (Test-Path -LiteralPath $envPath)) { throw 'Create .env from .env.example first; existing secrets and configuration will not be generated or replaced.' }
$values = [ordered]@{
  SENTRYGATE_DATA_DIR = $fullPath
  SENTRYGATE_DB_PATH = (Join-Path $fullPath 'sentrygate.db')
  SENTRYGATE_MAX_DB_BYTES = [string]$MaxDatabaseBytes
  SENTRYGATE_STORAGE_WARNING_PERCENT = [string]$WarningPercent
  SENTRYGATE_MIN_FREE_DISK_BYTES = [string]$MinimumFreeDiskBytes
}
$lines = [System.Collections.Generic.List[string]]::new()
$lines.AddRange([string[]](Get-Content -LiteralPath $envPath))
foreach ($key in $values.Keys) {
  $pattern = '^\s*' + [regex]::Escape($key) + '\s*=.*$'
  $indexes = @(); for ($i=0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match $pattern) { $indexes += $i } }
  if ($indexes.Count) {
    $lines[$indexes[0]] = "$key=$($values[$key])"
    for ($i=$indexes.Count-1; $i -gt 0; $i--) { $lines.RemoveAt($indexes[$i]) }
  } else { $lines.Add("$key=$($values[$key])") }
}
[System.IO.File]::WriteAllLines($envPath, $lines, [System.Text.UTF8Encoding]::new($false))
Write-Output "SentryGate local storage configured: $fullPath"
Write-Warning 'This changes configuration only. Stop SentryGate and make/verify a local backup before moving an existing database. Restart SentryGate to apply settings.'
